#![allow(warnings, unused)]

use chrono::{DateTime, Duration, Local, Utc};
use hmac::Hmac;
use jwt::{SignWithKey, VerifyWithKey};
use poem::{
	listener::TcpListener, web::Data, EndpointExt, Request, Result,
	Route, Server, http::StatusCode,
};
use poem_openapi::{
	auth::ApiKey,
	param::Query,
	payload::{Json, PlainText},
	*,
};
use std::sync::Mutex;
use rand::{distributions::Alphanumeric, Rng};
use rustflake::Snowflake;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use diesel::pg::PgConnection;
use diesel::prelude::*;
use dotenvy::dotenv;
use std::env;

pub mod models;
use models::*;
pub mod schema;
use schema::*;
pub mod error;
use error::*;

type ServerKey = Hmac<Sha256>;

/// Struct representing the ID of the authorized users and the expiration date of the token
/// The serialized form of this struct forms the content portion of the JWT returned by /login
#[derive(Serialize, Deserialize)]
struct Claims {
	id: i64,
	exp: DateTime<Local>,
}

/// API key authorization scheme
#[derive(SecurityScheme)]
#[oai(
	type = "api_key",
	key_name = "Authorization", // header to look for API key in
	in = "header",
	checker = "api_checker" // hook to run when checking authorization
)]
struct Authorization(Claims);

fn append_array(conn: &mut PgConnection, table: &str, field: &str, id: i64, val: i64) -> Result<usize, WithBacktrace<diesel::result::Error>> {
	diesel::sql_query(format!(
		"UPDATE {table} SET {field} = array_append({field},$1) WHERE id = $2;"
	))
		.bind::<diesel::sql_types::BigInt, _>(val)
		.bind::<diesel::sql_types::BigInt, _>(id)
		.execute(conn).with_backtrace()
}


fn remove_array(conn: &mut PgConnection, table: &str, field: &str, id: i64, val: i64) -> Result<usize, WithBacktrace<diesel::result::Error>> {
	diesel::sql_query(format!(
		"UPDATE {table} SET {field} = array_remove({field},$1) WHERE id = $2;"
	))
		.bind::<diesel::sql_types::BigInt, _>(val)
		.bind::<diesel::sql_types::BigInt, _>(id)
		.execute(conn).with_backtrace()
}


/// Check if a user has supplied a valid authorization token.
///
/// Returns None if the token was invalid or if it fails to parse the given token
/// (which will then be handled by Poem to throw a 401), otherwise returns the
/// Claims struct.
async fn api_checker(req: &Request, api_key: ApiKey) -> Option<Claims> {
	let encoded_claims_str = match api_key.key.split(".").nth(1) {
		None => return None,
		Some(s) => s,
	};
	let claims_str = match base64::decode(encoded_claims_str) {
		Err(_) => return None,
		Ok(s) => s,
	};
	let claims: Claims = match serde_json::from_str(&String::from_utf8(claims_str).unwrap()) {
		Err(_) => return None,
		Ok(c) => c
	};
	if claims.exp < Local::now() {
		return None;
	}
	let server_key = req.data::<ServerKey>().unwrap(); // get server secret
	VerifyWithKey::<Claims>::verify_with_key(api_key.key.as_str(), server_key).ok()
}

/// Wrapper struct for the API functions
struct Api {}

/// Generates a unique i64 for ID generation
// FIXME: Very bad performance - acts as a chokehold for parallelism since
// every request that sends a message / makes a channel / etc. has to contest
// a global mutex.
pub fn gen_id() -> i64 {
	static STATE: Mutex<Option<Snowflake>> = Mutex::new(None);

	STATE
		.lock()
		.unwrap()
		.get_or_insert_with(|| Snowflake::default())
		.generate()
}

pub fn check_name(name: String) -> String{
	let name_chars = name.chars();
	let fixed_name_chars = name_chars.filter(|i| !i.is_whitespace());
	let mut fixed_name: String = "".to_string();
	for i in fixed_name_chars{
		fixed_name.push(i);
	};
	// assert!(fixed_name != "".to_string(), "name is empty or contains only illegal characters");
	return fixed_name;
}

pub fn open_db_conn() -> PgConnection {
	let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
	PgConnection::establish(&database_url)
		.unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

#[OpenApi]
#[allow(unused_variables)]
impl Api {
	fn __remove_group_member(&self, conn: &mut PgConnection, gid: i64, uid: i64) -> Result<usize, WithBacktrace<diesel::result::Error>> {
		remove_array(conn, "groups", "members", gid, uid)?;

		let channels = groups::table.select(groups::dsl::channels)
			.filter(groups::dsl::id.eq(gid)).first::<Vec<i64>>(conn)
			.with_backtrace()?;

		for channel in channels {
			remove_array(conn, "channels", "members", channel, uid)?;
		}
		remove_array(conn, "user_groups", "groups", uid, gid)
	}

	#[oai(path = "/login", method = "post")]
	/// Log in as a user. Returns an authentication token given id and hash.
	///
	/// Expects hash of user's password to be given in the request body.
	/// Checks validity of hash, then signs JWT with a server secret key.
	// good
	async fn login(&self, key: Data<&ServerKey>, id: Query<i64>, hash: PlainText<String>) -> Result<PlainText<String>> {
		if hash.0.len() != 64 {
			return Err(UserFacingError::new(StatusCode::BAD_REQUEST, "Hash is not of length 24!").into())
		}
		let conn = &mut open_db_conn();
		let user: User = users::table.find(id.0).first(conn)
			.poemify("retrieving specified user")?;
		if hex::decode(&user.hash).unwrap() != hex::decode(&hash.0).unwrap() {
			return Err(UserFacingError::new(StatusCode::UNAUTHORIZED, "Incorrect hash provided.").into())
		} else {
			let token = Claims {
				id: id.0,
				exp: Local::now() + Duration::days(1),
			}
			.sign_with_key(key.0);
			Ok(PlainText(token.unwrap()))
		}
	}

	#[oai(path = "/user", method = "get")]
	/// Get the user with the given ID
	///
	/// Does not require any authorization.
	// good
	async fn get_user(&self, id: Query<i64>) -> Result<Json<User>> {
		let conn = &mut open_db_conn();
		let user: User = users::table.find(id.0).first(conn)
			.poemify("retrieving specified user")?;
		Ok(Json(user))
	}

	#[oai(path = "/user", method = "post")]
	/// Create a new user.
	///
	/// Expects hash of user's password to be given in the request body.
	/// Does not require any authorization.
	// good
	async fn make_user(&self, name: Query<String>, email: Query<String>, hash: PlainText<String>) -> Result<Json<User>> {
		let conn = &mut open_db_conn();

		if hash.0.len() != 64 {
			return Err(UserFacingError::new(StatusCode::BAD_REQUEST, "Hash is not of length 24!").into())
		}

		let user = User {
			id: gen_id(),
			name: check_name(name.0),
			email: email.0,
			hash: hash.0,
		};

		diesel::insert_into(users::table).values(&user)
			.execute(conn).poemify("adding user to database")?;
		// diesel::update(users::table).set(users::dsl::hash.eq(hash.0))
		//	.execute(conn).poemify("setting user hash");
		diesel::insert_into(user_groups::table)
			.values((user_groups::dsl::id.eq(user.id), user_groups::dsl::groups.eq(Vec::<i64>::new())))
			.execute(conn).poemify("initializing associated database entries")?;
		diesel::insert_into(user_dms::table)
			.values((user_dms::dsl::id.eq(user.id), user_dms::dsl::dms.eq(Vec::<i64>::new())))
			.execute(conn).poemify("initializing associated database entries")?;

		Ok(Json(user))
	}

	#[oai(path = "/user", method = "put")]
	/// Update your name and email.
	// good
	async fn update_user(&self, auth: Authorization, name: Query<String>, email: Query<String>) -> Result<()> {
		let conn = &mut open_db_conn();
		let checked_name = check_name(name.0.clone());
		diesel::update(users::table.find(auth.0.id))
			.set((users::dsl::name.eq(checked_name), users::dsl::email.eq(email.0)))
			.execute(conn).poemify("updating database")?;
		Ok(())
	}

	#[oai(path = "/user", method = "delete")]
	/// Delete your user.
	///
	/// Has the side effects of removing your user from every group, channel, or DM
	/// it is a member of.
	// good
	async fn delete_user(&self, auth: Authorization) -> Result<()> {
		let conn = &mut open_db_conn();
		diesel::delete(users::table.find(auth.0.id)).execute(conn).poemify("deleting your user")?;
		let your_groups: Vec<i64> = user_groups::table
			.select(user_groups::dsl::groups).find(auth.0.id)
			.first(conn).poemify("getting your groups")?;
		let your_dms: Vec<i64> = user_dms::table
			.select(user_dms::dsl::dms).find(auth.0.id)
			.first(conn).poemify("getting your DMs")?;
		for group in your_groups {
			self.__remove_group_member(conn, group, auth.0.id);
		}
		for dm in your_dms {
			self.__remove_group_member(conn, dm, auth.0.id);
		}
		diesel::delete(user_dms::table.find(auth.0.id)).execute(conn).poemify("deleting your groups list")?;
		diesel::delete(user_groups::table.find(auth.0.id)).execute(conn).poemify("deleting your DM list")?;
		Ok(())
	}

	#[oai(path = "/user/groups", method = "get")]
	/// Get all groups accessible to you.
	// good
	async fn get_groups(&self, auth: Authorization) -> Result<Json<Vec<Group>>> {
		let conn = &mut open_db_conn();
		let res: UserGroup = user_groups::table.find(auth.0.id)
			.first(conn).poemify("retrieving your groups")?;
		Ok(Json(res.groups.iter().map(|i| {
			groups::table.find(*i).first(conn).unwrap()
		}).collect()))
	}

	#[oai(path = "/user/dms", method = "get")]
	/// Get all DMs accessible to you.
	// good
	async fn get_dms(&self, auth: Authorization) -> Result<Json<Vec<Group>>> {
		let conn = &mut open_db_conn();
		let res: UserDm = user_dms::table.find(auth.0.id)
			.first(conn).poemify("retrieving your dms")?;
		Ok(Json(res.dms.iter().map(|i| {
			groups::table.find(*i).first(conn).unwrap()
		}).collect()))
	}

	#[oai(path = "/user/groups", method = "delete")]
	/// Leave a group accessible to you
	// good
	async fn leave_group(&self, auth: Authorization, gid: Query<i64>) -> Result<()> {
		let conn = &mut open_db_conn();
		self.__remove_group_member(conn, gid.0, auth.0.id).poemify("removing you from group")?;
		Ok(())
	}


	#[oai(path = "/group", method = "get")]
	/// Gets the group with the given ID
	// good
	async fn get_group(&self, auth: Authorization, id: Query<i64>) -> Result<Json<Group>> {
		let conn = &mut open_db_conn();
		let group: Group = groups::table.find(id.0).first(conn)
			.poemify("retrieving specified group")?;
		if !group.members.contains(&auth.0.id) {
			return Err(UserFacingError::terse(StatusCode::FORBIDDEN).into())
		}
		Ok(Json(group))
	}


	#[oai(path = "/group", method = "post")]
	/// Create a new group.
	///
	/// The group created...
	/// - will have a default public "main" channel
	/// - will have your user as the owner
	/// - will have your user as an admin
	// good
	async fn make_group(&self, auth: Authorization, name: Query<String>) -> Result<Json<Group>> {
		let conn = &mut open_db_conn();
		let gid = gen_id();
		let channel = Channel {
			id: gen_id(),
			src_group: gid,
			name: String::from("main"),
			members: vec![auth.0.id],
			private: false
		};
		diesel::insert_into(channels::table).values(&channel)
			.execute(conn).poemify("adding 'main' channel to database")?;
		let group = Group {
			id: gid,
			name: check_name(name.0),
			members: vec![auth.0.id],
			admin: vec![auth.0.id],
			owner: auth.0.id,
			is_dm: false,
			channels: vec![channel.id]
		};
		diesel::insert_into(groups::table).values(&group)
			.execute(conn).poemify("adding group to database")?;
		append_array(conn, "user_groups", "groups", auth.0.id, gid)
			.poemify("adding group to your groups")?;
		Ok(Json(group))
	}

	#[oai(path = "/dm", method = "post")]
	/// Create a new DM with a user `uid`.
	///
	/// The group created...
	/// - will have the `is_dm` attribute set to true.
	/// - will have only one channel "main" with you and `uid`
	/// - will have no owner or admins
	// good
	async fn make_dm(&self, auth: Authorization, uid: Query<i64>) -> Result<Json<Group>> {
		let conn = &mut open_db_conn();
		let user: User = users::table.find(uid.0).first(conn)
			.poemify("retreiving specified user")?;
		let gid = gen_id();
		let channel = Channel {
			id: gen_id(),
			src_group: gid,
			name: String::from("main"),
			members: vec![auth.0.id, uid.0],
			private: false
		};
		diesel::insert_into(channels::table).values(&channel)
			.execute(conn).poemify("adding 'main' channel to database")?;
		let group = Group {
			id: gid,
			name: String::from(""),
			members: vec![auth.0.id, uid.0],
			admin: vec![],
			owner: auth.0.id,
			is_dm: false,
			channels: vec![channel.id]
		};
		diesel::insert_into(groups::table).values(&group)
			.execute(conn).poemify("adding group to database")?;
		append_array(conn, "user_dms", "groups", auth.0.id, gid)
			.poemify("adding DM to your DMs")?;
		append_array(conn, "user_dms", "groups", uid.0, gid)
			.poemify("adding DM to their DMs")?;
		Ok(Json(group))
	}

	#[oai(path = "/group", method = "put")]
	/// Update the name of an existing group.
	///
	/// Only authorized for the owner of a group.
	// good
	async fn update_group(&self, auth: Authorization, id: Query<i64>, name: Query<String>) -> Result<()> {
		let conn = &mut open_db_conn();
		let mut group: Group = groups::table.find(id.0).first(conn)
			.poemify("retreiving specified group")?;
		if group.owner != auth.0.id {
			return Err(UserFacingError::terse(StatusCode::FORBIDDEN).into());
		}
		group.name = check_name(name.0);
		diesel::update(groups::table.find(id.0)).set(&group)
			.execute(conn).poemify("updating group in database");
		Ok(())
	}

	#[oai(path = "/group", method = "delete")]
	/// Delete a group.
	///
	/// Only authorized for the owner of a group.
	// good
	async fn delete_group(&self, auth: Authorization, id: Query<i64>) -> Result<()> {
		let conn = &mut open_db_conn();
		let group: Group = groups::table.find(id.0).first(conn)
			.poemify("retreiving specified group")?;
		if group.owner != auth.0.id {
			return Err(UserFacingError::terse(StatusCode::FORBIDDEN).into());
		}
		for member in group.members {
			remove_array(conn, "user_groups", "groups", member, id.0)
				.poemify("removing member from group")?;
		}
		for channel in group.channels {
			diesel::delete(channels::table.find(channel)).execute(conn)
				.poemify("deleting channel from database")?;
		}
		diesel::delete(groups::table.find(id.0)).execute(conn)
			.poemify("deleting group from database")?;
		Ok(())
	}

	#[oai(path = "/group/members", method = "get")]
	/// Get the members of the specified group.
	///
	/// No specific order for the list is guaranteed.
	// good
	async fn get_group_members(&self, auth: Authorization, id: Query<i64>) -> Result<Json<Vec<User>>> {
		let conn = &mut open_db_conn();
		let group: Group = groups::table.find(id.0).first(conn)
			.poemify("retreiving specified group")?;
		Ok(Json(group.members.iter().map(|m| {
			users::table.find(*m).first(conn).unwrap()
		}).collect()))
	}

	#[oai(path = "/group/members", method = "put")]
	/// Add a member to an existing group
	///
	/// Only authorized for group admins.
	/// Has the side effect of adding that member to all public channels.
	// good
	async fn add_group_member(&self, auth: Authorization, gid: Query<i64>, uid: Query<i64>) -> Result<()> {
		let conn = &mut open_db_conn();
		let mut group: Group = groups::table.find(gid.0).first(conn)
			.poemify("retreiving specified group")?;
		if !group.admin.contains(&auth.0.id) {
			return Err(UserFacingError::terse(StatusCode::FORBIDDEN).into());
		}
		group.members.push(uid.0);
		for chan_id in group.channels {
			let mut channel: Channel = channels::table.find(chan_id).first(conn)
				.poemify(&format!("retreiving channel (id {}) of group", chan_id))?;
			if channel.private { continue; }
			diesel::update(channels::table.find(chan_id)).set(&channel)
				.execute(conn).poemify("adding member to channel");
		}
		if !group.is_dm {
			append_array(conn, "user_groups", "groups", auth.0.id, gid.0)
				.poemify("adding group to your groups")?;
		} else {
			append_array(conn, "user_dms", "dms", auth.0.id, gid.0)
				.poemify("adding DM to your DMs")?;
		}
		Ok(())
	}

	#[oai(path = "/group/members", method = "delete")]
	/// Remove a member from an existing group
	///
	/// Only authorized for group admin.
	/// Attempting to remove the owner from their group will always be unauthorized.
	///
	/// Has the side effect of removing the member from all channels.
	// good
	async fn remove_group_member(&self, auth: Authorization, gid: Query<i64>, uid: Query<i64>) -> Result<()> {
		let conn = &mut open_db_conn();
		let admin: Vec<i64> = groups::table.select(groups::dsl::admin)
			.find(gid.0).first(conn).poemify("getting group admin")?;
		if !admin.contains(&auth.0.id) {
			return Err(UserFacingError::terse(StatusCode::FORBIDDEN).into());
		}
		self.__remove_group_member(conn, gid.0, uid.0).poemify("removing group member")?;
		Ok(())
	}

	#[oai(path = "/group/admin", method = "get")]
	/// Get the admins of the specified group.
	///
	/// No specific order for the list is guaranteed.
	// good
	async fn get_group_admin(&self, auth: Authorization, id: Query<i64>) -> Result<Json<Vec<User>>> {
		let conn = &mut open_db_conn();
		Ok(Json(
			groups::table
				.select(groups::dsl::admin)
				.filter(groups::dsl::id.eq(id.0))
				.first::<Vec<i64>>(conn)
				.poemify("retreiving admin of group")?
				.iter().map(|a| {
					users::table.find(*a).first(conn).unwrap()
				}).collect()
		))
	}

	#[oai(path = "/group/admin", method = "put")]
	/// Add an admin to an existing group
	///
	/// Only authorized for the owner of a group.
	// good
	async fn add_group_admin(&self, auth: Authorization, gid: Query<i64>, uid: Query<i64>) -> Result<()> {
		let conn = &mut open_db_conn();
		let mut group: Group = groups::table.find(gid.0).first(conn)
			.poemify("retreiving specified group")?;
		let _user: User = users::table.find(uid.0).first(conn)
			.poemify("retreiving specified user")?; // prevent adding invalid UID
		if auth.0.id != group.owner {
			return Err(UserFacingError::terse(StatusCode::FORBIDDEN).into());
		}
		group.admin.push(uid.0);
		diesel::update(groups::table.find(gid.0)).set(&group)
			.execute(conn).poemify("updating group in database");
		Ok(())
	}

	#[oai(path = "/group/admin", method = "delete")]
	/// Remove an admin from an existing group
	///
	/// Only authorized for the owner of a group.
	// good
	async fn remove_group_admin(&self, auth: Authorization, gid: Query<i64>, uid: Query<i64>) -> Result<()> {
		let conn = &mut open_db_conn();
		let mut group: Group = groups::table.find(gid.0).first(conn)
			.poemify("retreiving specified group")?;
		let _user: User = users::table.find(uid.0).first(conn)
			.poemify("retreiving specified user")?; // prevent adding invalid UID
		if auth.0.id != group.owner {
			return Err(UserFacingError::terse(StatusCode::FORBIDDEN).into());
		}
		group.admin.retain(|x| *x != uid.0);
		diesel::update(groups::table.find(gid.0)).set(&group)
			.execute(conn).poemify("updating group in database");
		Ok(())
	}

	#[oai(path = "/group/channels", method = "get")]
	/// Gets all channels in a group that are accessible to you
	// good
	async fn get_channels(&self, auth: Authorization, gid: Query<i64>) -> Result<Json<Vec<Channel>>> {
		let conn = &mut open_db_conn();
		Ok(Json(
			groups::table
				.select(groups::dsl::channels)
				.filter(groups::dsl::id.eq(gid.0))
				.first::<Vec<i64>>(conn)
				.poemify("retreiving group channels")?
				.iter()
				.map(|c| channels::table.find(*c).first(conn).unwrap())
				.filter(|c: &Channel| c.members.contains(&auth.0.id))
				.collect()
		))
	}

	#[oai(path = "/group/channels", method = "post")]
	// good
	async fn make_channel(&self, auth: Authorization, gid: Query<i64>, name: Query<String>) -> Result<Json<Channel>> {
		let conn = &mut open_db_conn();
		let out: Group = groups::table.find(gid.0).first(conn)
			.with_backtrace().poemify("retrieving specified group")?;

		if !out.admin.contains(&auth.0.id) {
			return Err(UserFacingError::new(StatusCode::FORBIDDEN,
				"You do not have permission to perform the requested action."
			).into())
		}

		let chan = Channel {
			id: gen_id(),
			src_group: gid.0,
			name: check_name(name.0.clone()),
			members: vec![auth.0.id],
			private: false
		};

		diesel::insert_into(channels::table).values(&chan)
			.execute(conn).poemify("adding channel to database")?;

		append_array(conn, "groups", "channels", gid.0, chan.id)
			.poemify("adding channel to group")?;

		Ok(Json(chan))
	}

	#[oai(path = "/channel", method = "put")]
	/// Update the name of a channel.
	///
	/// Only authorized for group admins.
	// good
	async fn update_channel(&self, auth: Authorization, id: Query<i64>, name: Query<String>) -> Result<()> {
		let conn = &mut open_db_conn();
		diesel::update(channels::table.find(auth.0.id))
			.set(channels::dsl::name.eq(check_name(name.0)))
			.execute(conn).poemify("updating database");
		Ok(())
	}

	#[oai(path = "/channel/private", method = "put")]
	/// Make a channel private.
	///
	/// Only authorized for group admins.
	// good
	async fn make_channel_private(&self, auth: Authorization, id: Query<i64>, val: Query<bool>) -> Result<()> {
		let conn = &mut open_db_conn();
		let group: i64 = channels::table.select(channels::dsl::src_group).find(id.0)
			.first(conn).poemify("getting channel group")?;
		let admin: Vec<i64> = groups::table.select(groups::dsl::admin)
			.find(group).first(conn).poemify("getting group admin")?;
		if !admin.contains(&auth.0.id) {
			return Err(UserFacingError::terse(StatusCode::FORBIDDEN).into())
		}
		diesel::update(channels::table.find(id.0))
			.set(channels::dsl::private.eq(val.0))
			.execute(conn).poemify("setting channel privacy in database");
		Ok(())
	}

	#[oai(path = "/channel", method = "get")]
	/// Get a channel.
	// good
	async fn get_channel(&self, auth: Authorization, id: Query<i64>) -> Result<Json<Channel>> {
		let conn = &mut open_db_conn();
		Ok(Json(channels::table.find(id.0).first(conn).poemify("retrieving specified channel")?))
	}

	#[oai(path = "/channel", method = "delete")]
	/// Delete a channel.
	///
	/// Only authorized for group admins.
	// good
	async fn delete_channel(&self, auth: Authorization, id: Query<i64>) -> Result<()> {
		let conn = &mut open_db_conn();
		let group: i64 = channels::table.select(channels::dsl::src_group).find(id.0)
			.first(conn).poemify("getting channel group")?;
		let admin: Vec<i64> = groups::table.select(groups::dsl::admin)
			.find(group).first(conn).poemify("getting group admin")?;
		if !admin.contains(&auth.0.id) {
			return Err(UserFacingError::terse(StatusCode::FORBIDDEN).into())
		}
		diesel::delete(channels::table.find(id.0)).execute(conn)
			.poemify("deleting channel from database")?;
		remove_array(conn, "groups", "channels", group, id.0)
			.poemify("removing channel from group")?;
		Ok(())
	}

	#[oai(path = "/channel/members", method = "get")]
	/// Get the members that can access a channel.
	///
	/// No specific order for the list is guaranteed.
	// good
	async fn get_channel_members(&self, auth: Authorization, id: Query<i64>) -> Result<Json<Vec<User>>> {
		let conn = &mut open_db_conn();
		Ok(Json(
			channels::table
				.select(channels::dsl::members)
				.filter(channels::dsl::id.eq(id.0))
				.first::<Vec<i64>>(conn)
				.poemify("retreiving channel members")?
				.iter().map(|u| {
					users::table.find(*u).first(conn).unwrap()
				}).collect()
		))
	}

	#[oai(path = "/channel/members", method = "put")]
	/// Add a member to a channel
	///
	/// Only authorized for group admins.
	// good
	async fn add_channel_member(&self, auth: Authorization, cid: Query<i64>, uid: Query<i64>) -> Result<()> {
		let conn = &mut open_db_conn();
		let mut chan: Channel = channels::table.find(cid.0).first(conn)
			.poemify("retreiving specified channel")?;
		let group: Group = groups::table.find(chan.src_group).first(conn)
			.poemify("retreiving channel's group")?;
		let _user: User = users::table.find(uid.0).first(conn)
			.poemify("retreiving specified user")?; // prevent adding invalid UID
		if !group.admin.contains(&auth.0.id) {
			return Err(UserFacingError::terse(StatusCode::FORBIDDEN).into());
		}
		chan.members.push(uid.0);
		diesel::update(channels::table.find(cid.0)).set(&chan)
			.execute(conn).poemify("updating channel in database");
		Ok(())
	}

	#[oai(path = "/channel/members", method = "delete")]
	/// Remove a member from a channel.
	///
	/// Only authorized for group admins.
	// good
	async fn remove_channel_member(&self, auth: Authorization, cid: Query<i64>, uid: Query<i64>) -> Result<()> {
		let conn = &mut open_db_conn();
		let mut chan: Channel = channels::table.find(cid.0).first(conn)
			.poemify("retreiving specified channel")?;
		let group: Group = groups::table.find(chan.src_group).first(conn)
			.poemify("retreiving channel's group")?;
		let _user: User = users::table.find(uid.0).first(conn)
			.poemify("retreiving specified user")?; // prevent adding invalid UID
		if !group.admin.contains(&auth.0.id) {
			return Err(UserFacingError::terse(StatusCode::FORBIDDEN).into());
		}
		chan.members.retain(|x| *x != uid.0);
		diesel::update(channels::table.find(cid.0)).set(&chan)
			.execute(conn).poemify("updating channel in database");
		Ok(())
	}

	#[oai(path = "/channel/term", method = "get")]
	/// Get a batch of messages in channel containing `term` in the last 100 messages
	///
	/// Will not search for `term` in any messages older than the last 100.
	// good
	async fn search_channel(&self, auth: Authorization, cid: Query<i64>, term: Query<String>) -> Result<Json<Vec<Message>>> {
		let conn = &mut open_db_conn();
		let mut messages = messages::table.limit(100).load::<Message>(conn)
			.poemify("retrieving past 100 messages")?;
		messages.retain(|msg| {
			if let Some(content) = &msg.content {
				return content.contains(&term.0)
			} else { return false }
		});
		Ok(Json(messages))
	}

	#[oai(path = "/channel/messages", method = "get")]
	/// Returns batch of messages in channel. Do not use for small batches.
	///
	/// For small batches, use `chatterbox`, the websocket service for messaging, instead.
	// good
	async fn get_channel_messages(&self, auth: Authorization, cid: Query<i64>, num_msgs: Query<i64>) -> Result<Json<Vec<Message>>> {
		let conn = &mut open_db_conn();
		Ok(Json(
			messages::table.limit(num_msgs.0).load::<Message>(conn)
				.poemify("retrieving past messages")?
		))
	}

	#[oai(path = "/message/thread", method = "put")]
	/// Make a thread for a given message.
	///
	/// Thread will be private with you as its sole member
	async fn make_thread(&self, auth: Authorization, id: Query<i64>, name: Query<String>) -> Result<Json<Channel>> {
		let conn = &mut open_db_conn();
		let mut msg: Message = messages::table.find(id.0).first(conn)
			.poemify("retreiving specified message")?;
		let group: i64 = channels::table.select(channels::dsl::src_group).find(msg.channel)
			.first(conn).poemify("getting channel group")?;
		let thread = Channel {
			id: gen_id(),
			name: check_name(name.0),
			src_group: group,
			members: vec![auth.0.id],
			private: true,
		};
		msg.thread = Some(thread.id);
		diesel::insert_into(channels::table).values(&thread)
			.execute(conn).poemify("adding thread to database")?;
		diesel::update(messages::table.find(id.0)).set(&msg)
			.execute(conn).poemify("updating message in database")?;
		Ok(Json(thread))
	}

	#[oai(path = "/message", method = "delete")]
	/// Delete a message
	///
	/// Only authorized for the message author or a group admin.
	async fn delete_message(&self, auth: Authorization, id: Query<i64>) -> Result<()> {
		let conn = &mut open_db_conn();
		let msg: Message = messages::table.find(id.0).first(conn)
			.poemify("retreiving specified message")?;
		let group: i64 = channels::table.select(channels::dsl::src_group).find(msg.channel)
			.first(conn).poemify("getting channel group")?;
		let admin: Vec<i64> = groups::table.select(groups::dsl::admin)
			.find(group).first(conn).poemify("getting group admin")?;
		if msg.author != auth.0.id && !admin.contains(&auth.0.id) {
			return Err(UserFacingError::terse(StatusCode::FORBIDDEN).into());;
		}
		diesel::delete(messages::table.find(id.0)).execute(conn)
			.poemify("deleting message")?;
		Ok(())
	}


}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
	use hmac::Mac;

	dotenv().ok();

	if std::env::var_os("RUST_LOG").is_none() {
		std::env::set_var("RUST_LOG", "poem=debug");
	}
	tracing_subscriber::fmt::init();
	
	let api_service = OpenApiService::new(Api {}, "Scuttlebutt", "1.0")
		.description(
			"Scuttlebutt is the REST API for managing everything but sending/receiving messages \
					  - which means creating/updating/deleting all of your users/groups/channels.",
		)
		.server("http://localhost:3000/api");

	// API documentation
	// let ui = api_service.swagger_ui();

	// Generate server-side secret key used for signing the JWTs
	let key: String = rand::thread_rng()
		.sample_iter(&Alphanumeric)
		.take(7)
		.map(char::from)
		.collect();

	let app = Route::new()
		.nest("/api", api_service)
		// .nest("/", ui)
		.data(ServerKey::new_from_slice(&key.as_bytes()).unwrap())
		.catch_error(|_: poem::error::NotFoundError| async move {
			poem::Response::builder()
				.status(StatusCode::NOT_FOUND)
				.body("<h1>404 Not Found</h1>Path not found.")
		})
		.catch_error(|err: poem_openapi::error::ParseParamError| async move {
			poem::Response::builder()
				.status(StatusCode::BAD_REQUEST)
				.body(format!("<h1>400 Bad Request</h1><pre>{}.</pre>", err))
		});

	Server::new(TcpListener::bind("127.0.0.1:3000")).run(app).await
}

#[cfg(test)]
mod tests;
