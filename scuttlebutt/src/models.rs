use diesel::prelude::*;
use crate::schema::*;
use poem_openapi::{
    payload::{Json, PlainText},
    ApiResponse, Object,
};
use serde::{Deserialize, Serialize};


#[derive(Object, Serialize, Deserialize, Queryable, Identifiable, Insertable, AsChangeset, Debug)]
pub struct Channel {
    pub id: i64,
    pub src_group: i64,
	pub name: String,
    pub members: Vec<i64>,
    pub private: bool,
}

#[derive(Object, Serialize, Deserialize, Queryable, Identifiable, Insertable, AsChangeset, Debug)]
pub struct Group {
    pub id: i64,
	pub name: String,
    pub members: Vec<i64>,
    pub is_dm: bool,
	pub channels: Vec<i64>,
	pub admin: Vec<i64>,
	pub owner: i64
}

#[derive(Object, Serialize, Deserialize, Queryable, Identifiable, Insertable, AsChangeset, Debug)]
pub struct User {
    pub id: i64,
	pub name: String,
	pub email: String,
	pub hash: String,
}


#[derive(Serialize, Deserialize, Queryable, Identifiable, Insertable, AsChangeset, Debug)]
pub struct UserGroup {
    pub id: i64,
	pub groups: Vec<i64>
}


#[derive(Serialize, Deserialize, Queryable, Identifiable, Insertable, AsChangeset, Debug)]
pub struct UserDm {
    pub id: i64,
	pub dms: Vec<i64>
}


#[derive(Object, Deserialize, Queryable, Identifiable, Insertable, AsChangeset, Debug)]
pub struct Message {
	pub channel: i64,
    pub id: i64,
	pub author: i64,
	pub content: Option<String>,
	pub thread: Option<i64>
}

