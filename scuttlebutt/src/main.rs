use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use poem::{listener::TcpListener, Request, Result, Route, Server};
use poem_openapi::{
    auth::ApiKey,
    param::Query,
    payload::{Base64, Json, PlainText},
    *,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub mod responses;
pub use responses::*;

type ServerKey = Hmac<Sha256>;

/// ApiKey authorization
#[derive(SecurityScheme)]
#[oai(
    type = "api_key",
    key_name = "X-API-Key",
    in = "header",
    checker = "api_checker"
)]
struct Authorization(User);

async fn api_checker(req: &Request, api_key: ApiKey) -> Option<User> {
    let claims: User = serde_json::from_str(
        &String::from_utf8(base64::decode(api_key.key.split(".").nth(1).unwrap()).unwrap())
            .unwrap(),
    )
    .unwrap();
    let key = todo!(); // Query DB here...
    let server_key = req.data::<ServerKey>().unwrap();
    VerifyWithKey::<User>::verify_with_key(api_key.key.as_str(), server_key).ok()
}

struct Api;

#[OpenApi]
impl Api {
    #[oai(path = "/login", method = "post")]
    async fn login(&self, id: Query<String>, hash: Base64<Vec<u8>>) -> Result<PlainText<String>> {
        let key =
            Hmac::<Sha256>::new_from_slice(&hash.0).map_err(poem::error::InternalServerError)?;
        let token = User {
            username: String::from("Blurgh"),
            email: String::from("Blurgh"),
            id: 0,
        }
        .sign_with_key(&key)
        .map_err(poem::error::InternalServerError)?;
        Ok(PlainText(token))
    }

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
    async fn make_user(
        &self,
        name: Query<String>,
        email: Query<String>,
        hash: Query<String>,
    ) -> CreateUserResponse {
        todo!()
    }

    #[oai(path = "/user", method = "put")]
    /// Updates your current name and email
    async fn update_user(
        &self,
        auth: Authorization,
        name: Query<String>,
        email: Query<String>,
    ) -> CreateUserResponse {
        todo!()
    }

    #[oai(path = "/user", method = "delete")]
    /// Deletes your user
    async fn delete_user(&self, auth: Authorization) -> DeleteResponse {
        todo!()
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
        todo!()
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
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "poem=debug");
    }
    tracing_subscriber::fmt::init();

    let api_service = OpenApiService::new(Api, "Scuttlebutt", "1.0")
        .description(
            "Scuttlebutt is the REST API for managing everything but sending/receiving messages \
					  - which means creating/updating/deleting all of your users/groups/channels.",
        )
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

    // fn setup() -> TestClient<Route> {
    // 	let app = OpenApiService::new(Api, "Scuttlebutt", "1.0").server("http://localhost:3000/api");
    // 	TestClient::new(Route::new().nest("/api", app))
    // }

    // #[tokio::test]
    // async fn sanity() {
    // 	let cli = setup();
    // 	let resp = cli.get("/api/hello").send().await;
    // 	resp.assert_status_is_ok();
    // 	resp.assert_text("whee").await;
    // }
}
