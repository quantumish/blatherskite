use poem_openapi::{
    payload::{Json, PlainText},
    ApiResponse, Object,
};
use serde::{Deserialize, Serialize};

#[derive(Object, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
}

#[derive(Object, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Group {
    pub id: i64,
    pub name: String,
    // The IDs of the group members
    pub members: Vec<i64>,
    // The IDs of the group's channels
    pub channels: Vec<i64>,
}

#[derive(Object, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Channel {
    pub id: i64,
    pub name: String,
    pub members: Vec<i64>,
}

#[derive(Object, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct Message {
    pub id: i64,
    pub channel: i64,
    pub author: i64,
    pub content: String,
}

#[derive(ApiResponse)]
pub enum UserResponse {
    /// Returns the user requested.
    #[oai(status = 200)]
    Success(Json<User>),
    /// Invalid ID. Content specifies which of the IDs passed is invalid.
    #[oai(status = 404)]
    NotFound,
    /// Internal server error: likely due to a database operation failing
    #[oai(status = 500)]
    InternalError(PlainText<String>),
}

#[derive(ApiResponse)]
pub enum CreateUserResponse {
    /// Returns the user requested.
    #[oai(status = 200)]
    Success(Json<User>),
    /// Recieved a bad argument when specifying the user. Returns error type, such as:
    /// - found empty string for any of the arguments
    /// - invalid email
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
    /// Internal server error: likely due to a database operation failing
    #[oai(status = 500)]
    InternalError(PlainText<String>),
}

#[derive(ApiResponse)]
pub enum DeleteResponse {
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
pub enum GroupResponse {
    /// Returns the group requested
    #[oai(status = 200)]
    Group(Json<Group>),
    /// Invalid ID.
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
pub enum CreateGroupResponse {
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
pub enum ChannelResponse {
    /// Returns the channel requested
    #[oai(status = 200)]
    Channel(Json<Channel>),
    /// Invalid ID. Content specifies which of the IDs passed is invalid.
    #[oai(status = 404)]
    NotFound(PlainText<String>),
}

#[derive(ApiResponse)]
pub enum CreateChannelResponse {
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
pub enum GenericResponse {
    /// Action succeeded
    #[oai(status = 200)]
    Success,
    /// Invalid ID. Content specifies which of the IDs passed is invalid.
    #[oai(status = 404)]
    NotFound(PlainText<String>),
}

#[derive(ApiResponse)]
pub enum MessagesResponse {
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
pub enum MembersResponse {
    /// Returns the members of current channel/group
    #[oai(status = 200)]
    Messages(Json<Vec<User>>),
    /// Invalid ID
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
pub enum GroupsResponse {
    /// Returns the groups the user is a memmber of
    #[oai(status = 200)]
    Messages(Json<Vec<Group>>),
    /// Invalid user ID
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
pub enum ChannelsResponse {
    /// Returns the channels in a group
    #[oai(status = 200)]
    Messages(Json<Vec<Channel>>),
    /// Invalid group ID
    #[oai(status = 404)]
    NotFound,
}
