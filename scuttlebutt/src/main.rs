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
        session.execute(&stmt!(&format!("CREATE TABLE IF NOT EXISTS {keyspc}.groups (id bigint PRIMARY KEY, name text, members list<bigint>, channels list<bigint>);"))).wait().unwrap();
        session.execute(&stmt!(&format!("CREATE TABLE IF NOT EXISTS {keyspc}.channels (id bigint PRIMARY KEY, name text, group bigint, members list<bigint>);"))).wait().unwrap();
        session.execute(&stmt!(&format!("CREATE TABLE IF NOT EXISTS {keyspc}.user_groups (id bigint PRIMARY KEY, groups list<bigint>);"))).wait().unwrap();
        session.execute(&stmt!(&format!("CREATE TABLE IF NOT EXISTS {keyspc}.messages (group bigint, channel bigint, author bigint, time timestamp, content text, PRIMARY KEY ((group, channel)));"))).wait().unwrap();

        Api {
            sess: session,
            kspc: String::from(keyspc),
        }
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
                    InternalError(PlainText(
                        "Found duplicate ID (or negative rows??)! Giving up!".to_string(),
                    ))
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
        let delete_stmt = &stmt!(&format!("DELETE FROM {}.users WHERE id={};", self.kspc, id));
        if let Err(e) = self.sess.execute(delete_stmt).wait() {
            InternalError(PlainText(e.to_string()))
        } else {
            Success
        }
    }

    #[oai(path = "/user/groups", method = "get")]
    /// Gets all groups accessible to you
    async fn get_groups(&self, auth: Authorization) -> GroupsResponse {
        todo!()
    }

    #[oai(path = "/user/groups", method = "delete")]
    /// Leaves a group accessible to you
    async fn leave_group(&self, auth: Authorization, gid: Query<i64>) -> GenericResponse {
        todo!()
    }

    #[oai(path = "/group", method = "get")]
    /// Gets the group with the given ID
    async fn get_group(&self, auth: Authorization, id: Query<i64>) -> GroupResponse {
        todo!()
    }

    #[oai(path = "/group", method = "post")]
    /// Creates a new group
    async fn make_group(&self, auth: Authorization, name: Query<String>) -> CreateGroupResponse {
        use CreateGroupResponse::*;
        // InternalError(PlainText("test".to_string()))
        let gid = gen_id();
        let cid = gen_id();
        // if name.0 == "" {
        // 	return BadRequest(PlainText("Empty string not allowed for name".to_string()))
        // }
        // let channel_stmt = &stmt!(&format!(
        // 	"INSERT INTO {}.channels (id, group, name, members) VALUES ({}, {}, '{}', [{}]);",
        // 	self.kspc, cid, gid, "main", auth.0.id
        // ));
        // if let Err(e) = self.sess.execute(channel_stmt).wait() {
        //     return InternalError(PlainText(e.to_string()))
        // }
        let group_stmt = &stmt!(&format!(
            "INSERT INTO {}.groups (id, name, channels, members) VALUES ({}, '{}', [{}], [{}]);",
            self.kspc, gid, name.0, cid, auth.0.id
        ));
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
    ) -> CreateGroupResponse {
        todo!()
    }

    #[oai(path = "/group", method = "delete")]
    /// Deletes a group
    async fn delete_group(&self, auth: Authorization, id: Query<i64>) -> DeleteResponse {
        todo!()
    }

    #[oai(path = "/group/members", method = "get")]
    /// Gets the members of the specified group
    async fn get_group_members(&self, auth: Authorization, id: Query<i64>) -> MembersResponse {
        todo!()
    }

    #[oai(path = "/group/members", method = "put")]
    /// Adds a member to an existing group
    async fn add_group_member(
        &self,
        auth: Authorization,
        gid: Query<i64>,
        uid: Query<i64>,
    ) -> GenericResponse {
        todo!()
    }

    #[oai(path = "/group/members", method = "delete")]
    /// Removes a member from an existing group
    async fn remove_group_member(
        &self,
        auth: Authorization,
        gid: Query<i64>,
        uid: Query<i64>,
    ) -> DeleteResponse {
        todo!()
    }

    #[oai(path = "/group/channels", method = "get")]
    /// Gets all channels in a group that are accessible to you
    async fn get_channels(&self, auth: Authorization, gid: Query<i64>) -> ChannelsResponse {
        todo!()
    }

    #[oai(path = "/group/channels", method = "post")]
    /// Creates a channel in a group
    async fn make_channel(
        &self,
        auth: Authorization,
        gid: Query<i64>,
        name: Query<String>,
    ) -> CreateChannelResponse {
        todo!()
    }

    #[oai(path = "/channel", method = "put")]
    /// Updates the name of a channel
    async fn update_channel(
        &self,
        auth: Authorization,
        id: Query<i64>,
        name: Query<String>,
    ) -> CreateChannelResponse {
        todo!()
    }

    #[oai(path = "/channel", method = "delete")]
    /// Deletes a channel
    async fn delete_channel(&self, auth: Authorization, id: Query<i64>) -> DeleteResponse {
        todo!()
    }

    #[oai(path = "/channel/members", method = "get")]
    /// Gets the members that can access a channel
    async fn get_channel_members(&self, auth: Authorization, id: Query<i64>) -> MembersResponse {
        todo!()
    }

    #[oai(path = "/channel/members", method = "put")]
    /// Adds a member to a channel
    async fn add_channel_member(
        &self,
        auth: Authorization,
        id: Query<i64>,
        uid: Query<i64>,
    ) -> GenericResponse {
        todo!()
    }

    #[oai(path = "/channel/members", method = "delete")]
    /// Removes a member from a channel
    async fn remove_channel_member(
        &self,
        auth: Authorization,
        cid: Query<i64>,
        uid: Query<i64>,
    ) -> DeleteResponse {
        todo!()
    }

    #[oai(path = "/channel/message", method = "get")]
    /// Returns batch of messages in channel containing "term" starting at offset
    async fn search_channel(
        &self,
        auth: Authorization,
        cid: Query<i64>,
        term: Query<String>,
        off: Query<u64>,
    ) -> MessagesResponse {
        todo!()
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
        todo!()
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
    // let resp = cli.post("/api/login?id=234").body("abc").send().await;
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
