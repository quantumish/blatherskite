use poem_openapi::{
    payload::{Json, PlainText},
    ApiResponse, Object,
};
use serde::{Deserialize, Serialize};

use crate::models;

#[derive(Object, Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
/// Object representing a user
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
}

#[derive(Object, Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
/// Object representing a group.
/// No guarantees are made for the order of any vector in this struct.
pub struct Group {
    pub id: i64,
    pub name: String,
    // The IDs of the group members
    pub members: Vec<i64>,
    // The IDs of the group's channels
    pub channels: Vec<i64>,
	// The IDs of the group's users with admin permissions
	pub admin: Vec<i64>,
	// The ID of the owner of the group
	pub owner: i64,
	// Whether or not the group is a DM
	pub is_dm: bool,
}

#[derive(Object, Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
/// Object representing a group's channel.
/// No guarantees are made for the order of any vector in this struct.
pub struct ChannelOrig {
    pub id: i64,
    pub name: String,
	// ID of the group the channel is in
	pub group: i64,
	// The IDs of the group members
    pub members: Vec<i64>,
	// Whether or not the channel is private
	pub private: bool,
}

#[derive(Object, Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
/// Object representing a message from a user.
pub struct Message {
    pub id: i64,
    pub channel: i64,
    pub author: i64,
    pub content: String,
	// The (optional) thread associated with the message
	pub thread: Option<i64>
}

#[derive(ApiResponse)]
pub enum LoginResponse {
	/// Returns a JWT encoding the user's ID and the token expiration date
	/// (1 day from now) that can be used to authenticate future requests
    #[oai(status = 200)]
    Success(PlainText<String>),
    /// User ID not found
    #[oai(status = 404)]
    NotFound,
    /// Incorrect hash provided
    #[oai(status = 401)]
    Unauthorized,
    /// Hash provided is of incorrect length
    #[oai(status = 400)]
    BadRequest,
    /// Internal server error when attempting to access database/sign key
    #[oai(status = 500)]
    InternalError(PlainText<String>),
}

#[derive(ApiResponse)]
pub enum UserResponse {
    /// Returns the user requested.
    #[oai(status = 200)]
    Success(Json<User>),
    /// Invalid ID.
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
    /// Internal server error: likely due to a database operation failing
    #[oai(status = 500)]
    InternalError(PlainText<String>),
}

#[derive(ApiResponse)]
pub enum GroupResponse {
    /// Returns the group requested
    #[oai(status = 200)]
    Success(Json<Group>),
    /// Invalid ID or user is not a member of specified group.
    #[oai(status = 404)]
    NotFound,
    /// Internal server error when attempting to access database
    #[oai(status = 500)]
    InternalError(PlainText<String>),
}

#[derive(ApiResponse)]
pub enum CreateGroupResponse {
    /// Returns the group requested
    #[oai(status = 200)]
    Success(Json<Group>),
	/// Invalid User ID (only possible when making a DM).
    #[oai(status = 404)]
    NotFound,
    /// Invalid parameter, such as:
    /// - empty string for name
    /// - bad string
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
    /// Internal server error: likely due to a database operation failing
    #[oai(status = 500)]
    InternalError(PlainText<String>),
}

#[derive(ApiResponse)]
pub enum ChannelResponse {
    /// Returns the channel requested
    #[oai(status = 200)]
    Success(Json<ChannelOrig>),
	/// Invalid ID or user is not a member of specified channel.
    #[oai(status = 404)]
    NotFound,
    /// Internal server error: likely due to a database operation failing
    #[oai(status = 500)]
    InternalError(PlainText<String>),
}


#[derive(ApiResponse)]
pub enum ChannelResponse2 {
    /// Returns the channel requested
    #[oai(status = 200)]
    Success(Json<models::Channel>),
	/// Invalid ID or user is not a member of specified channel.
    #[oai(status = 404)]
    NotFound,
    /// Internal server error: likely due to a database operation failing
    #[oai(status = 500)]
    InternalError(PlainText<String>),
}


#[derive(ApiResponse)]
pub enum CreateChannelResponse {
    /// Returns the channel requested
    #[oai(status = 200)]
    Success(Json<ChannelOrig>),
	/// You are not authorized to perform the action
    #[oai(status = 401)]
    Unauthorized,
    /// Invalid parameter, such as:
    /// - empty string for name
    /// - bad string
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
    /// Invalid ID. Content specifies which of the IDs passed is invalid.
    #[oai(status = 404)]
    NotFound(PlainText<String>),
    /// Internal server error: likely due to a database operation failing
    #[oai(status = 500)]
    InternalError(PlainText<String>),
}

#[derive(ApiResponse)]
pub enum GenericResponse {
    /// Action succeeded.
    #[oai(status = 200)]
    Success,
	/// You are not authorized to perform the action
    #[oai(status = 401)]
    Unauthorized,
    /// Recieved a bad argument.    
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
    /// Invalid ID. Content specifies which of the IDs passed is invalid.
    #[oai(status = 404)]
    NotFound(PlainText<String>),
    /// Internal server error: likely due to a database operation failing
    #[oai(status = 500)]
    InternalError(PlainText<String>),
}

#[derive(ApiResponse)]
pub enum MessagesResponse {
    /// Returns the messages requested
    #[oai(status = 200)]
    Success(Json<Vec<Message>>),
    /// Invalid ID, no messages found, or user is not a member of specified channel.
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
    Success(Json<Vec<User>>),
    /// Invalid ID
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
pub enum GroupsResponse {
    /// Returns the groups the user is a memmber of
    #[oai(status = 200)]
    Success(Json<Vec<Group>>),
    /// Invalid user ID
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
pub enum ChannelsResponse {
    /// Returns the channels in a group
    #[oai(status = 200)]
    Success(Json<Vec<ChannelOrig>>),
    /// Invalid group ID
    #[oai(status = 404)]
    NotFound,
    /// Internal server error: likely due to a database operation failing
    #[oai(status = 500)]
    InternalError(PlainText<String>),
}
