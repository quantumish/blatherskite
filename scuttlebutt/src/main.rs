use poem::{listener::TcpListener, Route, Server, Result, Request, web::Data};
use poem_openapi::{param::Query, payload::{PlainText, Json}, *, auth::ApiKey};
use hmac::{Hmac, Mac};
use log::{warn, info};
use jwt::{SignWithKey, VerifyWithKey};
use serde::{Serialize, Deserialize};
use sha2::Sha256;

struct Api;

#[derive(Object, Serialize, Deserialize)]
struct User {
    id: i64,	
    username: String,
	email: String,	
}

#[derive(Object)]
struct Group {
    id: i64,	
    name: String,
	members: Vec<i64>,
	channels: Vec<i64>,
}

#[derive(Object)]
struct Channel {
    id: i64,
    name: String,
	members: Vec<i64>,
}

// type ServerKey = Hmac<Sha256>;

// /// ApiKey authorization
// #[derive(SecurityScheme)]
// #[oai(
//     type = "api_key",
//     key_name = "X-API-Key",
//     in = "header",
//     checker = "api_checker"
// )]
// struct MyApiKeyAuthorization(User);

// async fn api_checker(req: &Request, api_key: ApiKey) -> Option<User> {
//     let server_key = req.data::<ServerKey>().unwrap();
//     VerifyWithKey::<User>::verify_with_key(api_key.key.as_str(), server_key).ok()
// }

#[derive(ApiResponse)]
enum UserResponse {
	/// Returns the user requested.
	#[oai(status = 200)]
	User(Json<User>),
	/// Returns when there is no user associated with the ID
	#[oai(status = 404)]
	NotFound,
	/// Recieved a bad argument when specifying the user. Returns error type, such as:
	/// - found empty string for any of the arguments
	/// - invalid email	
	#[oai(status = 400)]
	BadRequest,
}

#[OpenApi]
impl Api {
    #[oai(path = "/user", method = "get")]
	/// Gets the user with the given ID
    ///
    /// # Example
    /// 
    /// Call `/user?id=1234` to get the user with id 1234
    async fn get_user(&self, id: Query<i64>) -> UserResponse {		
        todo!()
    }

	#[oai(path = "/user", method = "post")]
	/// Creates a new user	
    async fn make_user(&self, name: Query<String>, email: Query<String>, password: Query<String>) -> Result<Json<User>> {
        todo!()
    }

	#[oai(path = "/user", method = "put")]
	/// Updates a user's name and email	
    async fn update_user(&self, id: Query<i64>, name: Query<String>, email: Query<String>) -> UserResponse {
        todo!()
    }

	#[oai(path = "/user/groups", method = "get")]
	/// Gets all groups accessible to a user
    async fn get_groups(&self, id: Query<i64>) -> Json<Vec<Group>> {
        todo!()
    }
	
	#[oai(path = "/group", method = "get")]
	/// Gets the group with the given ID
    async fn get_group(&self, id: Query<i64>) -> Json<Group> {
        todo!()
    }

	#[oai(path = "/group", method = "post")]
	/// Creates a new group
    async fn make_group(&self, name: Query<String>) -> Json<Group> {
        todo!()
    }

	#[oai(path = "/group", method = "put")]
	/// Updates the name of an existing group
    async fn update_group(&self, id: Query<i64>, name: Query<String>) -> Json<Group> {
        todo!()
    }

	#[oai(path = "/group/members", method = "get")]
	/// Gets the members of the specified group
    async fn get_group_members(&self, id: Query<i64>) -> Json<Vec<User>> {
        todo!()
    }

	#[oai(path = "/group/members", method = "put")]
	/// Adds a member to an existing group
    async fn add_group_member(&self, gid: Query<i64>, uid: Query<i64>) -> Json<Vec<User>> {
        todo!()
    }

	#[oai(path = "/group/channels", method = "get")]
	/// Gets all channels in a group that are accessible to a user
    async fn get_channels(&self, gid: Query<i64>, uid: Query<i64>) -> Json<Vec<Channel>> {
        todo!()
    }

	#[oai(path = "/group/channels", method = "post")]
	/// Creates a channel in a group
    async fn make_channel(&self, gid: Query<i64>, name: Query<String>) -> Json<Channel> {
        todo!()
    }
	
	#[oai(path = "/channel", method = "put")]
	/// Updates the name of a channel
    async fn update_channel(&self, id: Query<i64>, name: Query<String>) -> Json<Channel> {
        todo!()
    }

	#[oai(path = "/channel/members", method = "get")]
	/// Gets the members that can access a channel
    async fn get_channel_members(&self, id: Query<i64>) -> Json<Vec<User>> {
        todo!()
    }
	
	#[oai(path = "/channel/members", method = "put")]
	/// Adds a member to a channel
    async fn add_channel_member(&self, cid: Query<i64>, uid: Query<i64>) -> Json<Channel> {
        todo!()
    }
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "poem=debug");
    }
    tracing_subscriber::fmt::init();

    let api_service =
		OpenApiService::new(Api, "Scuttlebutt", "1.0")
		.description("Scuttlebutt is the REST API for managing everything but sending/receiving messages \
					  - which means creating/updating/deleting all of your users/groups/channels.")
		.server("http://localhost:3000/api");

    let ui = api_service.swagger_ui();

	// let wat = b"whee";
	// let server_key = Hmac::<Sha256>::new_from_slice(wat).expect("valid server key");
	// let server_key2 = Hmac::<Sha256>::new_from_hex
	// println!("{:?}", server_key.);
    Server::new(TcpListener::bind("127.0.0.1:3000"))
        .run(Route::new().nest("/api", api_service).nest("/", ui))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
	use poem::test::TestClient;
	
	fn setup() -> TestClient<Route> {
		let app = OpenApiService::new(Api, "Scuttlebutt", "1.0").server("http://localhost:3000/api");
		TestClient::new(Route::new().nest("/api", app))
	}

	// #[tokio::test]
	// async fn sanity() {
	// 	let cli = setup();
	// 	let resp = cli.get("/api/hello").send().await;
	// 	resp.assert_status_is_ok();
	// 	resp.assert_text("whee").await;		
	// }
}
