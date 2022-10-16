use chrono::{DateTime, Duration, Local, Utc};
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use poem::{
	listener::TcpListener, web::Data, EndpointExt, Request, Result,
	Route, Server,
};
use poem_openapi::{
	auth::ApiKey,
	param::Query,
	payload::{Json, PlainText},
	*,
};
use rand::{distributions::Alphanumeric, Rng};
use rustflake::Snowflake;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub mod responses;
pub use responses::*;

pub mod db;
pub use db::*;

type ServerKey = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
struct Claims {
	id: i64,
	exp: DateTime<Local>,
}

/// ApiKey authorization
#[derive(SecurityScheme)]
#[oai(
	type = "api_key",
	key_name = "Authorization",
	in = "header",
	checker = "api_checker"
)]
struct Authorization(Claims);

async fn api_checker(req: &Request, api_key: ApiKey) -> Option<Claims> {
	let claims: Claims = serde_json::from_str(
		&String::from_utf8(base64::decode(api_key.key.split(".").nth(1).unwrap()).unwrap())
			.unwrap(),
	)
	.unwrap();
	if claims.exp < Local::now() {
		return None;
	}
	let server_key = req.data::<ServerKey>().unwrap();
	VerifyWithKey::<Claims>::verify_with_key(api_key.key.as_str(), server_key).ok()
}

struct Api {
	db: Box<dyn Database>,	
}

pub fn gen_id() -> i64 {
	// Very cursed thread-unique number generation
	// NOTE: substitute for std::thread::current().id() when it's stabilized
	thread_local! { static V: u8 = 0; }
	let id: u64 = V.with(|v| v as *const u8 as u64);

	let now = Utc::now().timestamp_nanos();
	// TODO generalize this hardcoded 1
	Snowflake::new(now, 1, id as i64).generate()
}

#[OpenApi]
#[allow(unused_variables)]
impl Api {
	fn new(db: Box<dyn Database>) -> Api {
		Api { db }
	}

	fn __remove_group_member(&self, gid: i64, uid: i64) {
		self.db.remove_group_member(gid, uid).unwrap();
		let channels = self.db.get_group_channels(gid).unwrap();		
		for channel in channels {
			self.db.remove_channel_member(channel, uid).unwrap();
		}
		self.db.remove_user_group(uid, gid).unwrap();
	}

	#[oai(path = "/login", method = "post")]
	async fn login(&self, key: Data<&ServerKey>, id: Query<i64>, hash: PlainText<String>) -> LoginResponse {
		use LoginResponse::*;
		if hash.0.len() != 64 {
			return BadRequest;
		} else if !self.db.valid_id(IdType::User, id.0).unwrap() {
			return NotFound;
		}
		let db_hash = self.db.get_user_hash(id.0).unwrap();
		if hex::decode(db_hash).unwrap() != hex::decode(hash.0).unwrap() {
			Unauthorized
		} else {
			let token = Claims {
				id: id.0,
				exp: Local::now() + Duration::days(1),
			}
			.sign_with_key(key.0);
			Success(PlainText(token.unwrap()))
		}
	}

	#[oai(path = "/user", method = "get")]
	/// Gets the user with the given ID
	///
	/// # Example
	///
	/// Call `/user?id=1234` to get the user with id 1234
	async fn get_user(&self, id: Query<i64>) -> UserResponse {
		use UserResponse::*;
		if !self.db.valid_id(IdType::User, id.0).unwrap() { return NotFound; }
		match self.db.get_user(id.0) {
			Ok(user) => Success(Json(user)),
			Err(e) => InternalError(PlainText(e.to_string()))
		}
	}

	#[oai(path = "/user", method = "post")]
	/// Creates a new user
	async fn make_user(&self, name: Query<String>, email: Query<String>, hash: Query<String>) -> CreateUserResponse {
		use CreateUserResponse::*;
		if hash.0.len() != 64 {
			return BadRequest(PlainText("Invalid hash provided.".to_string()));
		}
		let id = gen_id();
		self.db.create_user(id, name.0.clone(), email.0.clone(), hash.0).unwrap();
		Success(Json(User {
			id,
			username: name.0,
			email: email.0,
		}))
	}

	#[oai(path = "/user", method = "put")]
	/// Updates your current name and email
	async fn update_user(&self, auth: Authorization, name: Query<String>, email: Query<String>) -> GenericResponse {
		use GenericResponse::*;
		self.db.update_user(auth.0.id, name.0, email.0).unwrap();
		Success
	}

	#[oai(path = "/user", method = "delete")]
	/// Deletes your user
	async fn delete_user(&self, auth: Authorization) -> DeleteResponse {
		use DeleteResponse::*;
		self.db.delete_user(auth.0.id).unwrap();		
		for group in self.db.get_user_groups(auth.0.id).unwrap() {
			self.__remove_group_member(group, auth.0.id);
		}
		self.db.delete_user_groups(auth.0.id).unwrap();		
		Success
	}

	#[oai(path = "/user/groups", method = "get")]
	/// Gets all groups accessible to you
	async fn get_groups(&self, auth: Authorization) -> GroupsResponse {
		use GroupsResponse::*;
		let groups = self.db.get_user_groups(auth.0.id).unwrap();
		let group_vec = groups.iter().map(|i| {
			self.db.get_group(*i).unwrap()
		}).collect();
		Success(Json(group_vec))
	}

	#[oai(path = "/user/groups", method = "delete")]
	/// Leaves a group accessible to you
	async fn leave_group(&self, auth: Authorization, gid: Query<i64>) -> GenericResponse {
		use GenericResponse::*;
		if !self.db.valid_id(IdType::Group, gid.0).unwrap() {
			return NotFound(PlainText("Group not found".to_string()));
		}
		self.__remove_group_member(gid.0, auth.0.id);
		Success
	}

	#[oai(path = "/group", method = "get")]
	/// Gets the group with the given ID
	async fn get_group(&self, auth: Authorization, id: Query<i64>) -> GroupResponse {
		use GroupResponse::*;
		if !self.db.valid_id(IdType::Group, id.0).unwrap() { return NotFound; }
		Success(Json(self.db.get_group(id.0).unwrap()))
	}

	#[oai(path = "/group", method = "post")]
	/// Creates a new group
	async fn make_group(&self, auth: Authorization, name: Query<String>) -> CreateGroupResponse {
		use CreateGroupResponse::*;
		let gid = gen_id();
		let cid = gen_id();
		if name.0 == "" {
			return BadRequest(PlainText("Empty string not allowed for name".to_string()))
		}
		self.db.create_group(gid, auth.0.id, name.0.clone()).unwrap();
		self.db.create_channel(cid, gid, auth.0.id, String::from("main")).unwrap();
		self.db.add_group_channel(gid, cid).unwrap();
		self.db.add_user_group(auth.0.id, gid).unwrap();
		Success(Json(Group {
			id: gid,
			name: name.0,
			members: vec![auth.0.id],
			channels: vec![cid],
		}))
	}

	#[oai(path = "/group", method = "put")]
	/// Updates the name of an existing group
	async fn update_group(&self, auth: Authorization, id: Query<i64>, name: Query<String>) -> GenericResponse {
		use GenericResponse::*;
		if name.0 == "" {
			return BadRequest(PlainText("Empty string not allowed for name".to_string()))
		} else if !self.db.valid_id(IdType::Group, id.0).unwrap() {
			return NotFound(PlainText("Didn't find group or experienced database error.".to_string()));
		}
		self.db.update_group(id.0, name.0).unwrap();
		Success
	}

	#[oai(path = "/group", method = "delete")]
	/// Deletes a group
	async fn delete_group(&self, auth: Authorization, id: Query<i64>) -> DeleteResponse {
		use DeleteResponse::*;
		if !self.db.valid_id(IdType::Group, id.0).unwrap() {
			return NotFound(PlainText("Group not found".to_string()));
		}
		let group = self.db.get_group(id.0).unwrap();
		for member in group.members {
			self.db.remove_user_group(member, id.0).unwrap();
		}
		for channel in group.channels {
			self.db.delete_channel(channel).unwrap();
		}
		self.db.delete_group(id.0).unwrap();
		Success
	}

	#[oai(path = "/group/members", method = "get")]
	/// Gets the members of the specified group
	async fn get_group_members(&self, auth: Authorization, id: Query<i64>) -> MembersResponse {
		use MembersResponse::*;
		if !self.db.valid_id(IdType::Group, id.0).unwrap() {
			return NotFound;
		}		
		let members = self.db.get_group_members(id.0).unwrap();
		Success(Json(members.iter().map(|m| {
			self.db.get_user(*m).unwrap()
		}).collect::<Vec<User>>()))		
	}

	#[oai(path = "/group/members", method = "put")]
	/// Adds a member to an existing group
	async fn add_group_member(&self, auth: Authorization, gid: Query<i64>, uid: Query<i64>) -> GenericResponse {
		use GenericResponse::*;
		if !self.db.valid_id(IdType::Group, gid.0).unwrap() {
			return NotFound(PlainText("Group not found".to_string()));
		}
		self.db.add_group_member(gid.0, uid.0).unwrap();		
		let channels = self.db.get_group_channels(gid.0).unwrap();		
		self.db.add_channel_member(channels[0], uid.0).unwrap();
		self.db.add_user_group(uid.0, gid.0).unwrap();
		Success
	}

	#[oai(path = "/group/members", method = "delete")]
	/// Removes a member from an existing group
	async fn remove_group_member(&self, auth: Authorization, gid: Query<i64>, uid: Query<i64>) -> DeleteResponse {
		use DeleteResponse::*;
		if !self.db.valid_id(IdType::Group, gid.0).unwrap() {
			return NotFound(PlainText("Group not found".to_string()))
		} else if !self.db.valid_id(IdType::User, uid.0).unwrap() {
			return NotFound(PlainText("User not found".to_string()))
		}
		self.__remove_group_member(gid.0, uid.0);
		Success
	}

	#[oai(path = "/group/channels", method = "get")]
	/// Gets all channels in a group that are accessible to you
	async fn get_channels(&self, auth: Authorization, gid: Query<i64>) -> ChannelsResponse {
		use ChannelsResponse::*;
		if !self.db.valid_id(IdType::Group, gid.0).unwrap() {
			return NotFound;
		}
		let channels = self.db.get_group_channels(gid.0).unwrap();
		Success(Json(channels.iter().map(|c| {
			self.db.get_channel(*c).unwrap()
		}).collect::<Vec<Channel>>()))
	}

	#[oai(path = "/group/channels", method = "post")]
	/// CREATES a channel in a group
	async fn make_channel(&self, auth: Authorization, gid: Query<i64>, name: Query<String>) -> CreateChannelResponse {
		use CreateChannelResponse::*;
		if name.0 == "" {
			return BadRequest(PlainText("Empty string not allowed for name".to_string()))
		} else if !self.db.valid_id(IdType::Group, gid.0).unwrap() {
			return NotFound(PlainText("Group not found".to_string()));
		}
		let cid = gen_id();
		self.db.create_channel(cid, gid.0, auth.0.id, name.0.clone()).unwrap();
		self.db.add_group_channel(cid, gid.0).unwrap();
		Success(Json(Channel {
			id: cid,
			name: name.0,
			group: gid.0,
			members: vec![auth.0.id]
		}))
	}

	#[oai(path = "/channel", method = "put")]
	/// Updates the name of a channel
	async fn update_channel(&self, auth: Authorization, id: Query<i64>, name: Query<String>) -> GenericResponse {
		use GenericResponse::*;
		if !self.db.valid_id(IdType::Channel, id.0).unwrap() {
			return NotFound(PlainText("Channel not found".to_string()));
		}
		self.db.update_channel(id.0, name.0).unwrap();
		Success
	}

	#[oai(path = "/channel", method = "get")]
	/// Gets a channel
	async fn get_channel(&self, auth: Authorization, id: Query<i64>) -> ChannelResponse {
		use ChannelResponse::*;
		if !self.db.valid_id(IdType::Channel, id.0).unwrap() {
			return NotFound;
		}
		Success(Json(self.db.get_channel(id.0).unwrap()))
	}

	#[oai(path = "/channel", method = "delete")]
	/// Deletes a channel
	async fn delete_channel(&self, auth: Authorization, id: Query<i64>) -> DeleteResponse {
		use DeleteResponse::*;
		if !self.db.valid_id(IdType::Channel, id.0).unwrap() {
			return NotFound(PlainText("Channel not found".to_string()));
		}
		let channel = self.db.get_channel(id.0).unwrap();
		self.db.remove_group_channel(channel.group, id.0).unwrap();
		self.db.delete_channel(id.0).unwrap();
		Success
	}

	#[oai(path = "/channel/members", method = "get")]
	/// Gets the members that can access a channel
	async fn get_channel_members(&self, auth: Authorization, id: Query<i64>) -> MembersResponse {
		use MembersResponse::*;
		let members = self.db.get_channel_members(id.0).unwrap();
		Success(Json(members.iter().map(|m| {
			self.db.get_user(*m).unwrap()
		}).collect::<Vec<User>>()))
	}

	#[oai(path = "/channel/members", method = "put")]
	/// Adds a member to a channel
	async fn add_channel_member(&self, auth: Authorization, id: Query<i64>, uid: Query<i64>) -> GenericResponse {
		use GenericResponse::*;
		if !self.db.valid_id(IdType::Channel, id.0).unwrap() {
			return NotFound(PlainText("Channel not found".to_string()))
		} else if !self.db.valid_id(IdType::User, uid.0).unwrap() {
			return NotFound(PlainText("User not found".to_string()))
		}
		self.db.add_channel_member(id.0, uid.0).unwrap();
		Success
	}

	#[oai(path = "/channel/members", method = "delete")]
	/// Removes a member from a channel
	async fn remove_channel_member(&self, auth: Authorization, cid: Query<i64>, uid: Query<i64>) -> DeleteResponse {
		use DeleteResponse::*;
		if !self.db.valid_id(IdType::Channel, cid.0).unwrap() {
			return NotFound(PlainText("Channel not found".to_string()))
		} else if !self.db.valid_id(IdType::User, uid.0).unwrap() {
			return NotFound(PlainText("User not found".to_string()))
		}
		self.db.remove_channel_member(cid.0, uid.0).unwrap();
		Success
	}

	#[oai(path = "/channel/term", method = "get")]
	/// Returns batch of messages in channel containing "term" in the last 100 messages
	async fn search_channel(&self, auth: Authorization, cid: Query<i64>, term: Query<String>, off: Query<u64>) -> MessagesResponse {
		use MessagesResponse::*;
		if !self.db.valid_id(IdType::Channel, cid.0).unwrap() {
			return NotFound(PlainText("Channel not found".to_string()))
		}
		let mut messages = self.db.get_messages(cid.0, 100).unwrap();
		messages.retain(|msg| msg.content.contains(&term.0));
		Success(Json(messages))	
	}

	#[oai(path = "/channel/messages", method = "get")]
	/// Returns batch of messages in channel. Do not use for small batches.
	///
	/// For small batches, use `chatterbox`, the websocket service for messaging, instead.
	async fn get_channel_messages(&self, auth: Authorization, cid: Query<i64>, num_msgs: Query<u64>) -> MessagesResponse {
		use MessagesResponse::*;
		if !self.db.valid_id(IdType::Channel, cid.0).unwrap() {
			return NotFound(PlainText("Channel not found".to_string()))
		}
		Success(Json(self.db.get_messages(cid.0, num_msgs.0).unwrap()))
	}
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
	use hmac::Mac;
	if std::env::var_os("RUST_LOG").is_none() {
		std::env::set_var("RUST_LOG", "poem=debug");
	}
	tracing_subscriber::fmt::init();

	let db = Box::new(Cassandra::new("bsk"));
	let api_service = OpenApiService::new(Api::new(db), "Scuttlebutt", "1.0")
		.description(
			"Scuttlebutt is the REST API for managing everything but sending/receiving messages \
					  - which means creating/updating/deleting all of your users/groups/channels.",
		)
		.server("http://localhost:3000/api");

	let ui = api_service.swagger_ui();

	let key: String = rand::thread_rng()
		.sample_iter(&Alphanumeric)
		.take(7)
		.map(char::from)
		.collect();

	let app = Route::new()
		.nest("/api", api_service)
		.nest("/", ui)
		.data(ServerKey::new_from_slice(&key.as_bytes()).unwrap());

	Server::new(TcpListener::bind("127.0.0.1:3000")).run(app).await
}

#[cfg(test)]
mod tests;
