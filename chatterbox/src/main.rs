/// Currently a modified version of `poem`'s default websocket-chat example
use cassandra_cpp::*;
use futures_util::{SinkExt, StreamExt};
use poem::{
	get, handler,
	listener::TcpListener,
	web::{
		websocket::{Message, WebSocket},
		Data, Path,
	},
	EndpointExt, IntoResponse, Route, Server,
};
use rustflake::Snowflake;
use serde_json::Value;
use std::result::Result;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Local};

#[derive(Serialize, Deserialize, Debug)]
pub struct MessageObj {
	pub id: i64,
	pub channel: i64,
	pub author: i64,
	pub content: String,
}

pub fn gen_id() -> i64 {
	static STATE: std::sync::Mutex<Option<Snowflake>> = std::sync::Mutex::new(None);

	STATE
		.lock()
		.unwrap()
		.get_or_insert_with(|| Snowflake::new(1_564_790_400_000, 2, 1))
		.generate()
}

const KEYSPC: &'static str = "bsk";

fn setup_db() -> Session {
	let contact_points = "127.0.0.1";
	let mut cluster = Cluster::default();
	cluster.set_contact_points(contact_points).unwrap();
	cluster.set_load_balance_round_robin();
	cluster.connect().unwrap()
}

#[handler]
fn ws(
	Path(name): Path<String>,
	ws: WebSocket,
	sender: Data<&tokio::sync::broadcast::Sender<String>>,
) -> impl IntoResponse {
	let sender = sender.clone();
	ws.on_upgrade(move |socket| async move {
	let mut receiver = sender.subscribe();
		let (mut sink, mut stream) = socket.split();

		tokio::spawn(async move {
			let sess = setup_db();
			let mut user: Option<Value> = None;
			while let Some(Ok(msg)) = stream.next().await {
				if let Message::Text(auth) = msg {					
					let req: Value = serde_json::from_str(&auth).unwrap();
					let res = sess.execute(&stmt!(&format!(
						"SELECT hash FROM {}.users WHERE id={};",
						KEYSPC, req["id"].as_i64().unwrap(),
					))).wait().unwrap();
					let row = res.first_row().unwrap();
					let db_hash: String = row.get(0).unwrap();
					if hex::decode(db_hash).unwrap() != hex::decode(req["hash"].as_str().unwrap()).unwrap() {
						return;
					}
					user = Some(req);
					break
				}
			}
			while let Some(Ok(mesg)) = stream.next().await {
				if let Message::Text(text) = mesg {
					let id = gen_id();
					let req: Value = serde_json::from_str(&text).unwrap();
					let msg = MessageObj {
						id,
						content: req["content"].as_str().unwrap().to_string(),
						author: user.clone().unwrap()["id"].as_i64().unwrap(),
						channel: req["channel"].as_i64().unwrap(),
					};
					let now = Local::now();
					let res = sess.execute(&stmt!(&format!(
						"INSERT INTO {}.messages (channel, id, author, time, content) VALUES ({},{},{},'{}','{}');",
						KEYSPC, msg.channel, gen_id(), msg.author, now.to_rfc3339(), msg.content
					))).wait().unwrap();
					if sender.send(serde_json::to_string(&msg).unwrap()).is_err() {
						break;
					}
				}
			}
		});

		tokio::spawn(async move {
			let sess = setup_db();
			while let Ok(msg) = receiver.recv().await {
				let req: Value = serde_json::from_str(&msg).unwrap();
				let res = sess.execute(&stmt!(&format!(
					"SELECT members FROM {}.channels WHERE id={};", KEYSPC, req["channel"].as_i64().unwrap(),
				))).wait().unwrap();
				let row = res.first_row().unwrap();
				let members: SetIterator = row.get(0).unwrap();
				if !members.map(|i| i.get_i64().unwrap()).collect::<Vec<i64>>().contains(&req["author"].as_i64().unwrap()) {
					continue
				}
				if sink.send(Message::Text(msg)).await.is_err() {
					break;
				}
			}
		});
	})
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
	if std::env::var_os("RUST_LOG").is_none() {
		std::env::set_var("RUST_LOG", "poem=debug");
	}
	tracing_subscriber::fmt::init();

	let app = Route::new().at(
		"/ws/:name",
		get(ws.data(tokio::sync::broadcast::channel::<String>(32).0)),
	);

	Server::new(TcpListener::bind("127.0.0.1:3001")).run(app).await
}
