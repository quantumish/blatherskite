use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use log::{info, warn};
use poem::{listener::TcpListener, web::Data, Request, Result, Route, Server};
use poem_openapi::{
    auth::ApiKey,
    param::Query,
    payload::{Json, PlainText},
    *,
};
use serde::{Deserialize, Serialize};
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
    // The IDs of the group members
    members: Vec<i64>,
    // The IDs of the group's channels
    channels: Vec<i64>,
}

#[derive(Object)]
struct Channel {
    id: i64,
    name: String,
    members: Vec<i64>,
}

#[derive(Object)]
struct Message {
    id: i64,
    channel: i64,
    author: i64,
    content: String,
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
    /// Invalid ID. Content specifies which of the IDs passed is invalid.
    #[oai(status = 404)]
    NotFound(PlainText<String>),
}

#[derive(ApiResponse)]
enum CreateUserResponse {
    /// Returns the user requested.
    #[oai(status = 200)]
    User(Json<User>),
    /// Recieved a bad argument when specifying the user. Returns error type, such as:
    /// - found empty string for any of the arguments
    /// - invalid email
    #[oai(status = 400)]
    BadRequest,
}

#[derive(ApiResponse)]
enum DeleteResponse {
    /// The delete operation succeeded
    #[oai(status = 200)]
    Success,
    /// You are not authorized to perform the action
    #[oai(status = 401)]
    Unauthorized,
    /// Invalid ID. Content specifies which of the IDs passed is invalid.
    #[oai(status = 404)]
    NotFound(PlainText<String>),
}

#[derive(ApiResponse)]
enum GroupResponse {
    /// Returns the group requested
    #[oai(status = 200)]
    Group(Json<Group>),
    /// Invalid ID.
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum CreateGroupResponse {
    /// Returns the group requested
    #[oai(status = 200)]
    Group(Json<Group>),
    /// Invalid parameter, such as:
    /// - empty string for name
    /// - bad string
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
}

#[derive(ApiResponse)]
enum ChannelResponse {
    /// Returns the channel requested
    #[oai(status = 200)]
    Channel(Json<Channel>),
    /// Invalid ID. Content specifies which of the IDs passed is invalid.
    #[oai(status = 404)]
    NotFound(PlainText<String>),
}

#[derive(ApiResponse)]
enum CreateChannelResponse {
    /// Returns the channel requested
    #[oai(status = 200)]
    Channel(Json<Channel>),
    /// Invalid parameter, such as:
    /// - empty string for name
    /// - bad string
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
}

#[derive(ApiResponse)]
enum GenericResponse {
    /// Action succeeded
    #[oai(status = 200)]
    Success,
    /// Invalid ID. Content specifies which of the IDs passed is invalid.
    #[oai(status = 404)]
    NotFound(PlainText<String>),
}

#[derive(ApiResponse)]
enum MessagesResponse {
    /// Returns the messages requested
    #[oai(status = 200)]
    Messages(Json<Vec<Message>>),
    /// Invalid ID, or no messages found. Content specifies which error occured.
    #[oai(status = 404)]
    NotFound(PlainText<String>),
    /// Offset or number of messages requested is bad. Content specifies which error occured.
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
}

#[derive(ApiResponse)]
enum MembersResponse {
    /// Returns the members of current channel/group
    #[oai(status = 200)]
    Messages(Json<Vec<User>>),
    /// Invalid ID
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GroupsResponse {
    /// Returns the groups the user is a memmber of
    #[oai(status = 200)]
    Messages(Json<Vec<Group>>),
    /// Invalid user ID
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum ChannelsResponse {
    /// Returns the channels in a group
    #[oai(status = 200)]
    Messages(Json<Vec<Channel>>),
    /// Invalid group ID
    #[oai(status = 404)]
    NotFound,
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
    async fn make_user(
        &self,
        name: Query<String>,
        email: Query<String>,
        password: Query<String>,
    ) -> CreateUserResponse {
        todo!()
    }

    #[oai(path = "/user", method = "put")]
    /// Updates a user's name and email
    async fn update_user(
        &self,
        id: Query<i64>,
        name: Query<String>,
        email: Query<String>,
    ) -> CreateUserResponse {
        todo!()
    }

    #[oai(path = "/user", method = "delete")]
    /// Deletes a user
    async fn delete_user(&self, id: Query<i64>) -> DeleteResponse {
        todo!()
    }

    #[oai(path = "/user/groups", method = "get")]
    /// Gets all groups accessible to a user
    async fn get_groups(&self, id: Query<i64>) -> GroupsResponse {
        todo!()
    }

    #[oai(path = "/user/groups", method = "delete")]
    /// Leaves a group accessible to the user
    async fn leave_group(&self, uid: Query<i64>, gid: Query<i64>) -> GenericResponse {
        todo!()
    }

    #[oai(path = "/group", method = "get")]
    /// Gets the group with the given ID
    async fn get_group(&self, id: Query<i64>) -> GroupResponse {
        todo!()
    }

    #[oai(path = "/group", method = "post")]
    /// Creates a new group
    async fn make_group(&self, name: Query<String>) -> CreateGroupResponse {
        todo!()
    }

    #[oai(path = "/group", method = "put")]
    /// Updates the name of an existing group
    async fn update_group(&self, id: Query<i64>, name: Query<String>) -> CreateGroupResponse {
        todo!()
    }

    #[oai(path = "/group", method = "delete")]
    /// Deletes a user
    async fn delete_group(&self, id: Query<i64>) -> DeleteResponse {
        todo!()
    }

    #[oai(path = "/group/members", method = "get")]
    /// Gets the members of the specified group
    async fn get_group_members(&self, id: Query<i64>) -> MembersResponse {
        todo!()
    }

    #[oai(path = "/group/members", method = "put")]
    /// Adds a member to an existing group
    async fn add_group_member(&self, gid: Query<i64>, uid: Query<i64>) -> GenericResponse {
        todo!()
    }

    #[oai(path = "/group/members", method = "delete")]
    /// Removes a member to an existing group
    async fn remove_group_member(&self, gid: Query<i64>, uid: Query<i64>) -> DeleteResponse {
        todo!()
    }

    #[oai(path = "/group/channels", method = "get")]
    /// Gets all channels in a group that are accessible to a user
    async fn get_channels(&self, gid: Query<i64>, uid: Query<i64>) -> ChannelsResponse {
        todo!()
    }

    #[oai(path = "/group/channels", method = "post")]
    /// Creates a channel in a group
    async fn make_channel(&self, gid: Query<i64>, name: Query<String>) -> CreateChannelResponse {
        todo!()
    }

    #[oai(path = "/channel", method = "put")]
    /// Updates the name of a channel
    async fn update_channel(&self, id: Query<i64>, name: Query<String>) -> CreateChannelResponse {
        todo!()
    }

    #[oai(path = "/channel", method = "delete")]
    /// Deletes a channel
    async fn delete_channel(&self, id: Query<i64>) -> DeleteResponse {
        todo!()
    }

    #[oai(path = "/channel/members", method = "get")]
    /// Gets the members that can access a channel
    async fn get_channel_members(&self, id: Query<i64>) -> MembersResponse {
        todo!()
    }

    #[oai(path = "/channel/members", method = "put")]
    /// Adds a member to a channel
    async fn add_channel_member(&self, cid: Query<i64>, uid: Query<i64>) -> GenericResponse {
        todo!()
    }

    #[oai(path = "/channel/members", method = "delete")]
    /// Removes a member from a channel
    async fn remove_channel_member(&self, cid: Query<i64>, uid: Query<i64>) -> DeleteResponse {
        todo!()
    }

    #[oai(path = "/channel/message", method = "get")]
    /// Returns batch of messages in channel containing "term" starting at offset
    async fn search_channel(
        &self,
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
