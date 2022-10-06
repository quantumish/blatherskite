use cassandra_cpp::*;
use chrono::{DateTime, Duration, Local};
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use poem::{
	http::StatusCode, listener::TcpListener, web::Data, Endpoint, EndpointExt, Request, Result,
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
use std::sync::Mutex;

pub mod responses;
pub use responses::*;

type ServerKey = Hmac<Sha256>;

const UNUSUAL_ROW_ERROR: &'static str = "Found duplicate ID (or negative rows??)! Giving up!";

#[derive(Serialize, Deserialize)]
struct Claims {
	id: i64,
	exp: DateTime<Local>,
}

/// ApiKey authorization
#[derive(SecurityScheme)]
#[oai(
	type = "api_key",
	key_name = "ScuttleKey",
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
	sess: Session,
	kspc: String,
}

pub fn gen_id() -> i64 {
	static STATE: Mutex<Option<Snowflake>> = Mutex::new(None);

	STATE
		.lock()
		.unwrap()
		.get_or_insert_with(|| Snowflake::default())
		.generate()
}

#[OpenApi]
#[allow(unused_variables)]
impl Api {
	fn new(keyspc: &str) -> Api {
		let contact_points = "127.0.0.1";
		let mut cluster = Cluster::default();
		cluster.set_contact_points(contact_points).unwrap();
		cluster.set_load_balance_round_robin();
		let session = cluster.connect().unwrap();

		session.execute(&stmt!(&format!("CREATE KEYSPACE IF NOT EXISTS {keyspc} WITH replication = {{'class':'SimpleStrategy', 'replication_factor': 1}}"))).wait().unwrap();
		session.execute(&stmt!(&format!("CREATE TABLE IF NOT EXISTS {keyspc}.users (id bigint PRIMARY KEY, name text, email text, hash text);"))).wait().unwrap();
		session.execute(&stmt!(&format!("CREATE TABLE IF NOT EXISTS {keyspc}.groups (id bigint PRIMARY KEY, name text, members set<bigint>, channels set<bigint>);"))).wait().unwrap();
		session.execute(&stmt!(&format!("CREATE TABLE IF NOT EXISTS {keyspc}.channels (id bigint PRIMARY KEY, name text, group bigint, members set<bigint>);"))).wait().unwrap();
		session.execute(&stmt!(&format!("CREATE TABLE IF NOT EXISTS {keyspc}.user_groups (id bigint PRIMARY KEY, groups set<bigint>);"))).wait().unwrap();
		session.execute(&stmt!(&format!("CREATE TABLE IF NOT EXISTS {keyspc}.messages (channel bigint, id bigint, author bigint, time timestamp, content text, PRIMARY KEY (channel, id)) WITH CLUSTERING ORDER BY (id DESC);"))).wait().unwrap();

		Api {
			sess: session,
			kspc: String::from(keyspc),
		}
	}

	fn validate_id(&self, table: &str, gid: i64) -> anyhow::Result<()> {
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT id FROM {}.groups WHERE id = {};", self.kspc, gid
		))).wait().unwrap();
		match res.row_count() {			
			1 => Ok(()),
			_ => Err(anyhow::anyhow!("not found")),
		}
		
	}

	fn __remove_channel_member(&self, cid: i64, uid: i64) {
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.channels SET members = members - {{{}}} WHERE id={};", self.kspc, uid, cid
		))).wait().unwrap();
	}

	fn __remove_group_member(&self, gid: i64, uid: i64) {
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.groups SET members = members - {{{}}} WHERE id={};", self.kspc, uid, gid
		))).wait().unwrap();
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT channels FROM {}.groups WHERE id={};", self.kspc, gid
		))).wait().unwrap();
		let row = res.first_row().unwrap();
		let channels: SetIterator = row.get(0).unwrap();
		for channel in channels {
			self.__remove_channel_member(channel.get_i64().unwrap(), uid);
		}
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.user_groups SET groups = groups - {{{}}} WHERE id={};", self.kspc, gid, uid
		))).wait().unwrap();		
	}

	#[oai(path = "/login", method = "post")]
	async fn login(
		&self,
		key: Data<&ServerKey>,
		id: Query<i64>,
		hash: PlainText<String>,
	) -> LoginResponse {
		use LoginResponse::*;
		if hash.0.len() != 64 {
			return BadRequest;
		}
		let hash_stmt = &stmt!(&format!(
			"SELECT id, name, email, hash FROM {}.users WHERE id={};",
			self.kspc, id.0
		));
		let res = self.sess.execute(hash_stmt).wait().unwrap();
		if res.row_count() == 1 {
			let row = res.first_row().unwrap();
			let db_hash: String = row.get(3).unwrap();
			if hex::decode(db_hash).unwrap() != hex::decode(hash.0).unwrap() {
				Unauthorized
			} else {
				let row = res.first_row().unwrap();
				let token = Claims {
					id: id.0,
					exp: Local::now() + Duration::days(1),
				}
				.sign_with_key(key.0);
				Success(PlainText(token.unwrap()))
			}
		} else if res.row_count() == 0 {
			NotFound
		} else {
			InternalError(PlainText(
				"Found multiple (or negative?) number of rows.".to_string(),
			))
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
		let insert_stmt = &stmt!(&format!(
			"SELECT id, name, email FROM {}.users WHERE id={};",
			self.kspc, id.0
		));
		match self.sess.execute(insert_stmt).wait() {
			Ok(res) => {
				if res.row_count() == 1 {
					let row = res.first_row().unwrap();
					Success(Json(User {
						id: id.0,
						username: row.get(1).unwrap(),
						email: row.get(2).unwrap(),
					}))
				} else if res.row_count() == 0 {
					NotFound
				} else {
					InternalError(PlainText(UNUSUAL_ROW_ERROR.to_string()))
				}
			}
			Err(e) => InternalError(PlainText(e.to_string())),
		}
	}

	#[oai(path = "/user", method = "post")]
	/// Creates a new user
	async fn make_user(
		&self,
		name: Query<String>,
		email: Query<String>,
		hash: Query<String>,
	) -> CreateUserResponse {
		use CreateUserResponse::*;
		if hash.0.len() != 64 {
			return BadRequest(PlainText("Invalid hash provided.".to_string()));
		}
		let id = gen_id();
		let insert_stmt = &stmt!(&format!(
			"INSERT INTO {}.users (id, name, email, hash) VALUES ({},'{}','{}','{}');",
			self.kspc, id, name.0, email.0, hash.0
		));
		if let Err(e) = self.sess.execute(insert_stmt).wait() {
			InternalError(PlainText(e.to_string()))
		} else {
			Success(Json(User {
				id,
				username: name.0,
				email: email.0,
			}))
		}
	}

	#[oai(path = "/user", method = "put")]
	/// Updates your current name and email
	async fn update_user(
		&self,
		auth: Authorization,
		name: Query<String>,
		email: Query<String>,
	) -> CreateUserResponse {
		use CreateUserResponse::*;
		let id = auth.0.id;
		let update_stmt = &stmt!(&format!(
			"UPDATE {}.users SET name = '{}', email = '{}' WHERE id = {};",
			self.kspc, name.0, email.0, id
		));
		if let Err(e) = self.sess.execute(update_stmt).wait() {
			InternalError(PlainText(e.to_string()))
		} else {
			Success(Json(User {
				id,
				username: name.0,
				email: email.0,
			}))
		}
	}

	#[oai(path = "/user", method = "delete")]
	/// Deletes your user
	async fn delete_user(&self, auth: Authorization) -> DeleteResponse {
		use DeleteResponse::*;
		let id = auth.0.id;
		self.sess.execute(&stmt!(&format!(
			"DELETE FROM {}.users WHERE id={};", self.kspc, id
		))).wait().unwrap();
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT groups FROM {}.user_groups WHERE id={};",
			self.kspc, auth.0.id
		))).wait().unwrap();
		let groups: SetIterator = match res.row_count() {
			0 => return Success,
			_ => res.first_row().unwrap().get(0).unwrap(),
		};
		for group in groups {
			self.__remove_group_member(group.get_i64().unwrap(), id);
		}
		self.sess.execute(&stmt!(&format!(
			"DELETE FROM {}.user_groups WHERE id={};", self.kspc, id
		))).wait().unwrap();
		Success
	}

	#[oai(path = "/user/groups", method = "get")]
	/// Gets all groups accessible to you
	async fn get_groups(&self, auth: Authorization) -> GroupsResponse {
		use GroupsResponse::*;
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT groups FROM {}.user_groups WHERE id={};",
			self.kspc, auth.0.id
		))).wait().unwrap();
		
		let groups: SetIterator = match res.row_count() {
			0 => return Success(Json(Vec::new())),
			_ => res.first_row().unwrap().get(0).unwrap(),
		};
		
		let group_vec = groups.map(|i| {
			let res = self.sess.execute(&stmt!(&format!(
				"SELECT id, name, members, channels FROM {}.groups WHERE id={};", self.kspc, i
			))).wait().unwrap();
			let row = res.first_row().unwrap();
			let (members, channels): (SetIterator, SetIterator) = (row.get(2).unwrap(), row.get(3).unwrap());
			Group {
				id: row.get(0).unwrap(),
				name: row.get(1).unwrap(),
				members: members.map(|i| i.get_i64().unwrap()).collect(),
				channels: channels.map(|i| i.get_i64().unwrap()).collect(),
			}
		}).collect();
		Success(Json(group_vec))		
	}

	#[oai(path = "/user/groups", method = "delete")]
	/// Leaves a group accessible to you
	async fn leave_group(&self, auth: Authorization, gid: Query<i64>) -> GenericResponse {
		use GenericResponse::*;
		if let Err(e) = self.validate_id("groups", gid.0) {
			return NotFound(PlainText("Didn't find group or experienced database error.".to_string()));
		}
		self.__remove_group_member(gid.0, auth.0.id);
		Success
	}

	#[oai(path = "/group", method = "get")]
	/// Gets the group with the given ID
	async fn get_group(&self, auth: Authorization, id: Query<i64>) -> GroupResponse {
		use GroupResponse::*;
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT name, members, channels FROM {}.groups WHERE id={};", self.kspc, id.0
		))).wait().unwrap();		
		let (name, members, channels): (String, SetIterator, SetIterator) = match res.row_count() {
			1 => {
				let row = res.first_row().unwrap();
				(row.get(0).unwrap(), row.get(1).unwrap(), row.get(2).unwrap())
			},
			0 => return NotFound,
			_ => return InternalError(PlainText(UNUSUAL_ROW_ERROR.to_string()))
		};

		Success(Json(Group{
			id: id.0,
			name,
			members: members.map(|i| i.get_i64().unwrap()).collect(),
			channels: channels.map(|i| i.get_i64().unwrap()).collect(),
		}))		
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
		self.sess.execute(&stmt!(&format!(
			"INSERT INTO {}.channels (id, group, name, members) VALUES ({}, {}, '{}', {{{}}});",
			self.kspc, cid, gid, "main", auth.0.id
		))).wait().unwrap();
		self.sess.execute(&stmt!(&format!(
			"INSERT INTO {}.groups (id, name, channels, members) VALUES ({}, '{}', {{{}}}, {{{}}});",
			self.kspc, gid, name.0, cid, auth.0.id
		))).wait().unwrap();
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.user_groups SET groups = groups + {{{}}} WHERE id = {};",
			self.kspc, gid, auth.0.id
		))).wait().unwrap();		
		Success(Json(Group {
			id: gid,
			name: name.0,
			members: vec![auth.0.id],
			channels: vec![cid],
		}))
	}

	#[oai(path = "/group", method = "put")]
	/// Updates the name of an existing group
	async fn update_group(
		&self,
		auth: Authorization,
		id: Query<i64>,
		name: Query<String>,
	) -> GenericResponse {
		use GenericResponse::*;
		if name.0 == "" {
			return BadRequest(PlainText("Empty string not allowed for name".to_string()))
		} else if let Err(e) = self.validate_id("groups", id.0) {
			return NotFound(PlainText("Didn't find group or experienced database error.".to_string()));
		}
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.groups SET name = '{}' WHERE id = {};",
			self.kspc, name.0, id.0
		))).wait().unwrap();
		Success		
	}

	#[oai(path = "/group", method = "delete")]
	/// Deletes a group
	async fn delete_group(&self, auth: Authorization, id: Query<i64>) -> DeleteResponse {
		use DeleteResponse::*;
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT id, members, channels FROM {}.groups WHERE id={};", self.kspc, id.0
		))).wait().unwrap();
		
		let (members, channels): (SetIterator, SetIterator) = match res.row_count() {
			1 => {
				let row = res.first_row().unwrap();
				(row.get(1).unwrap(), row.get(2).unwrap())
			},
			0 => return NotFound(PlainText("Group not found".to_string())),
			_ => return InternalError(PlainText(UNUSUAL_ROW_ERROR.to_string()))
		};

		for member in members {
			self.sess.execute(&stmt!(&format!(
				"UPDATE {}.user_groups SET groups = groups - {{{}}} WHERE id = {};",
				self.kspc, id.0, member
			))).wait().unwrap();
		}

		for channel in channels {
			self.sess.execute(&stmt!(&format!(
				"DELETE FROM {}.channels WHERE id={};", self.kspc, channel
			))).wait().unwrap();
		}
	
		self.sess.execute(&stmt!(&format!(
			"DELETE FROM {}.groups WHERE id={};", self.kspc, id.0
		))).wait().unwrap();
		Success
	}

	#[oai(path = "/group/members", method = "get")]
	/// Gets the members of the specified group
	async fn get_group_members(&self, auth: Authorization, id: Query<i64>) -> MembersResponse {
		use MembersResponse::*;
		if let Err(_) = self.validate_id("groups", id.0) {
			return NotFound;
		}
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT members FROM {}.groups WHERE id={};", self.kspc, id.0
		))).wait().unwrap();
		let row = res.first_row().unwrap();
		let members: SetIterator = row.get(0).unwrap();
		let members_objs = members.map(|_| {
			let res = self.sess.execute(&stmt!(&format!(
				"SELECT id, name, email FROM {}.users WHERE id={};",
				self.kspc, id.0
			))).wait().unwrap();
			let row = res.first_row().unwrap();
			User {
				id: id.0,
				username: row.get(1).unwrap(),
				email: row.get(2).unwrap(),
			}
		}).collect::<Vec<User>>();
		Success(Json(members_objs))
	}

	#[oai(path = "/group/members", method = "put")]
	/// Adds a member to an existing group
	async fn add_group_member(
		&self,
		auth: Authorization,
		gid: Query<i64>,
		uid: Query<i64>,
	) -> GenericResponse {
		use GenericResponse::*;		
		if let Err(e) = self.validate_id("groups", gid.0) {
			return NotFound(PlainText("Didn't find group or experienced database error.".to_string()));
		}
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.groups SET members = members + {{{}}} WHERE id = {};",
			self.kspc, uid.0, gid.0
		))).wait().unwrap();
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT channels FROM {}.groups WHERE id = {};",
			self.kspc, gid.0
		))).wait().unwrap();
		let row = res.first_row().unwrap();
		let mut channels: SetIterator = row.get(0).unwrap();
		let cid: i64  = channels.next().unwrap().get_i64().unwrap();		
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.channels SET members = members + {{{}}} WHERE id = {};",
			self.kspc, uid.0, cid
		))).wait().unwrap();
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.user_groups SET groups = groups + {{{}}} WHERE id = {};",
			self.kspc, gid.0, uid.0
		))).wait().unwrap();
		Success
	}

	#[oai(path = "/group/members", method = "delete")]
	/// Removes a member from an existing group
	async fn remove_group_member(
		&self,
		auth: Authorization,
		gid: Query<i64>,
		uid: Query<i64>,
	) -> DeleteResponse {
		use DeleteResponse::*;
		if let Err(_) = self.validate_id("groups", gid.0) {
			return NotFound(PlainText("Group not found".to_string()))
		} else if let Err(_) = self.validate_id("users", uid.0) {
			return NotFound(PlainText("User not found".to_string()))
		}
		self.__remove_group_member(gid.0, uid.0);
		Success
	}

	#[oai(path = "/group/channels", method = "get")]
	/// Gets all channels in a group that are accessible to you
	async fn get_channels(&self, auth: Authorization, gid: Query<i64>) -> ChannelsResponse {
		use ChannelsResponse::*;
		if let Err(_) = self.validate_id("groups", gid.0) {
			return NotFound;
		}
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT channels FROM {}.groups WHERE id={};", self.kspc, gid.0
		))).wait().unwrap();
		let row = res.first_row().unwrap();
		let channels: SetIterator = row.get(0).unwrap();
		let mut channel_objs = Vec::new();
		for chan in channels {
			let res = self.sess.execute(&stmt!(&format!(
				"SELECT id, name, members FROM {}.channels WHERE id={};", self.kspc, chan
			))).wait().unwrap();
			let row = res.first_row().unwrap();
			let members: SetIterator = row.get(2).unwrap();
			let members = members.map(|m| m.get_i64().unwrap()).collect::<Vec<i64>>();
			if !members.contains(&auth.0.id) {
				continue;
			}
			channel_objs.push(Channel {
				id: row.get(0).unwrap(),
				name: row.get(1).unwrap(),
				group: gid.0,
				members
			});
		}
		Success(Json(channel_objs))
	}
	
	#[oai(path = "/group/channels", method = "post")]
	/// CREATES a channel in a group
	async fn make_channel(
		&self,
		auth: Authorization,
		gid: Query<i64>,
		name: Query<String>,
	) -> CreateChannelResponse {
		use CreateChannelResponse::*;
		if name.0 == "" {
			return BadRequest(PlainText("Empty string not allowed for name".to_string()))
		} else if let Err(e) = self.validate_id("groups", gid.0) {
			return NotFound(PlainText("Group not found.".to_string()));
		}		
		let cid = gen_id();
		self.sess.execute(&stmt!(&format!(
			"INSERT INTO {}.channels (id, group, name, members) VALUES ({}, {}, '{}', {{{}}});",
			self.kspc, cid, gid.0, name.0, auth.0.id
		))).wait().unwrap();
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.groups SET channels = channels + {{{}}} WHERE id = {};",
			self.kspc, cid, gid.0
		))).wait().unwrap();
		Success(Json(Channel {
			id: cid,
			name: name.0,
			group: gid.0,
			members: vec![auth.0.id]
		}))
	}

	#[oai(path = "/channel", method = "put")]
	/// Updates the name of a channel
	async fn update_channel(
		&self,
		auth: Authorization,
		id: Query<i64>,
		name: Query<String>,
	) -> GenericResponse {
		use GenericResponse::*;
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT id FROM {}.channels WHERE id = {};", self.kspc, id.0
		))).wait().unwrap();
		match res.row_count() {
			0 => return NotFound(PlainText("Channel not found".to_string())),
			1 => (),
			_ => return InternalError(PlainText(UNUSUAL_ROW_ERROR.to_string()))
		}
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.channels SET name = '{}', WHERE id = {};",
			self.kspc, name.0, id.0
		))).wait().unwrap();
		Success
	}

	#[oai(path = "/channel", method = "get")]
	/// Gets a channel
	async fn get_channel(&self, auth: Authorization, id: Query<i64>) -> ChannelResponse {
		use ChannelResponse::*;
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT name, group, members FROM {}.channels WHERE id={};", self.kspc, id.0
		))).wait().unwrap();
		let (name, group, members): (String, i64, SetIterator) = match res.row_count() {
			1 => {
				let row = res.first_row().unwrap();
				(row.get(0).unwrap(), row.get(1).unwrap(), row.get(2).unwrap())
			},
			0 => return NotFound,
			_ => return InternalError(PlainText(UNUSUAL_ROW_ERROR.to_string()))
		};
		Success(Json(Channel {
			id: id.0,
			name,
			group,
			members: members.map(|i| i.get_i64().unwrap()).collect(),
		}))
	}
	
	#[oai(path = "/channel", method = "delete")]
	/// Deletes a channel
	async fn delete_channel(&self, auth: Authorization, id: Query<i64>) -> DeleteResponse {
		use DeleteResponse::*;
		if let Err(_) = self.validate_id("channels", id.0) {
			NotFound(PlainText("Channel not found.".to_string()))
		} else {
			let res = self.sess.execute(&stmt!(&format!(
				"SELECT group FROM {}.channels WHERE id={};", self.kspc, id.0
			))).wait().unwrap();
			let row = res.first_row().unwrap();
			let group: i64 = row.get(0).unwrap();
			self.sess.execute(&stmt!(&format!(
				"UPDATE {}.groups SET channels = channels - {{{}}} WHERE id = {};",
				self.kspc, id.0, group
			))).wait().unwrap();
			self.sess.execute(&stmt!(&format!(
				"DELETE FROM {}.channels WHERE id = {};",
				self.kspc, id.0
			))).wait().unwrap();
			Success
		}
	}

	#[oai(path = "/channel/members", method = "get")]
	/// Gets the members that can access a channel
	async fn get_channel_members(&self, auth: Authorization, id: Query<i64>) -> MembersResponse {
		use MembersResponse::*;
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT members FROM {}.channels WHERE id={};", self.kspc, id.0
		))).wait().unwrap();
		let row = res.first_row().unwrap();
		let members: SetIterator = row.get(0).unwrap();
		let members_objs = members.map(|_| {
			let res = self.sess.execute(&stmt!(&format!(
				"SELECT id, name, email FROM {}.users WHERE id={};",
				self.kspc, id.0
			))).wait().unwrap();
			let row = res.first_row().unwrap();
			User {
				id: id.0,
				username: row.get(1).unwrap(),
				email: row.get(2).unwrap(),
			}
		}).collect::<Vec<User>>();
		Success(Json(members_objs))
	}

	#[oai(path = "/channel/members", method = "put")]
	/// Adds a member to a channel
	async fn add_channel_member(
		&self,
		auth: Authorization,
		id: Query<i64>,
		uid: Query<i64>,
	) -> GenericResponse {
		use GenericResponse::*;
		if let Err(_) = self.validate_id("channels", id.0) {
			return NotFound(PlainText("Channel not found".to_string()))
		} else if let Err(_) = self.validate_id("users", uid.0) {
			return NotFound(PlainText("User not found".to_string()))
		}
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.channels SET members = members + {{{}}} WHERE id={};", self.kspc, uid.0, id.0
		))).wait().unwrap();
		Success
	}

	#[oai(path = "/channel/members", method = "delete")]
	/// Removes a member from a channel
	async fn remove_channel_member(
		&self,
		auth: Authorization,
		cid: Query<i64>,
		uid: Query<i64>,
	) -> DeleteResponse {
		use DeleteResponse::*;
		if let Err(_) = self.validate_id("channels", cid.0) {
			return NotFound(PlainText("Channel not found".to_string()))
		} else if let Err(_) = self.validate_id("users", uid.0) {
			return NotFound(PlainText("User not found".to_string()))
		}
		self.__remove_channel_member(cid.0, uid.0);
		Success
	}

	#[oai(path = "/channel/message", method = "get")]
	/// Returns batch of messages in channel containing "term" in the last 100 messages
	async fn search_channel(
		&self,
		auth: Authorization,
		cid: Query<i64>,
		term: Query<String>,
		off: Query<u64>,
	) -> MessagesResponse {
		use MessagesResponse::*;
		if let Err(_) = self.validate_id("channels", cid.0) {
			return NotFound(PlainText("Channel not found".to_string()))
		}
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT * FROM {}.messages WHERE channel={} LIMIT 100;",
			self.kspc, cid.0
		))).wait().unwrap();
		let messages = res.iter().filter(|row| {
			let content: String = row.get(4).unwrap();
			content.contains(&term.0)
		}).map(|row| {
			Message {
				id: row.get(0).unwrap(),
				author: row.get(2).unwrap(),
				channel: row.get(1).unwrap(),
				content: row.get(4).unwrap()
			}
		}).collect::<Vec<Message>>();
		Success(Json(messages))
	}

	#[oai(path = "/channel/messages", method = "get")]
	/// Returns batch of messages in channel. Do not use for small batches.
	///
	/// For small batches, use `chatterbox`, the websocket service for messaging, instead.
	async fn get_channel_messages(
		&self,
		auth: Authorization,
		cid: Query<i64>,
		num_msgs: Query<u64>,
	) -> MessagesResponse {
		use MessagesResponse::*;
		if let Err(_) = self.validate_id("channels", cid.0) {
			return NotFound(PlainText("Channel not found".to_string()))
		}
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT * FROM {}.messages WHERE channel={} LIMIT {};",
			self.kspc, cid.0, num_msgs.0, 
		))).wait().unwrap();
		let messages = res.iter().map(|row| {
			Message {
				id: row.get(0).unwrap(),
				author: row.get(2).unwrap(),
				channel: row.get(1).unwrap(),
				content: row.get(4).unwrap()
			}
		}).collect::<Vec<Message>>();
		Success(Json(messages))	
	}
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
	use hmac::Mac;
	if std::env::var_os("RUST_LOG").is_none() {
		std::env::set_var("RUST_LOG", "poem=debug");
	}
	tracing_subscriber::fmt::init();

	let api_service = OpenApiService::new(Api::new("bsk"), "Scuttlebutt", "1.0")
		.description(
			"Scuttlebutt is the REST API for managing everything but sending/receiving messages \
					  - which means creating/updating/deleting all of your users/groups/channels.",
		)
		.server("http://localhost:3000/api");

	let ui = api_service.swagger_ui();
	let spec = api_service.spec();

	let key: String = rand::thread_rng()
		.sample_iter(&Alphanumeric)
		.take(7)
		.map(char::from)
		.collect();

	let app = Route::new()
		.nest("/api", api_service)
		.nest("/", ui)
		.data(ServerKey::new_from_slice(&key.as_bytes()).unwrap());
	// let cli = poem::test::TestClient::new(app);
	// let resp = cli.post("/api/login?id=234").body("abc").send();
	// resp.assert_status_is_ok();
	// Ok(())
	Server::new(TcpListener::bind("127.0.0.1:3000"))
		.run(
			app, // .at("/spec", poem::endpoint::make_sync(move |_| spec.clone()))
		)
		.await
}

#[cfg(test)]
mod tests;
