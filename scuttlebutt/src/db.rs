use cassandra_cpp::*;
use crate::responses::*;

#[derive(Debug)]
pub enum IdType {
	User,
	Group,
	Channel,
	Message
}

pub trait Database: Sync + Send {	
	fn valid_id(&self, kind: IdType, id: i64) -> Result<bool>;

	fn create_user(&self, id: i64, name: String, email: String, hash: String) -> Result<()>;
	fn update_user(&self, id: i64, name: String, email: String) -> Result<()>;
	fn get_user(&self, id: i64) -> Result<User>;
	fn get_user_hash(&self, id: i64) -> Result<String>;
	fn delete_user(&self, id: i64) -> Result<()>;
	
	fn create_group(&self, gid: i64, uid: i64, name: String) -> Result<()>;
	fn update_group(&self, id: i64, name: String) -> Result<()>;
	fn get_group(&self, id: i64) -> Result<Group>;
	fn delete_group(&self, id: i64) -> Result<()>;	
	fn get_group_members(&self, gid: i64) -> Result<Vec<i64>>;
	fn remove_group_member(&self, gid: i64, uid: i64) -> Result<()>;
	fn add_group_member(&self, gid: i64, uid: i64) -> Result<()>;
	fn get_group_channels(&self, gid: i64) -> Result<Vec<i64>>;
	fn remove_group_channel(&self, gid: i64, uid: i64) -> Result<()>;
	fn add_group_channel(&self, gid: i64, uid: i64) -> Result<()>;
	
	fn create_channel(&self, cid: i64, gid: i64, uid: i64, name: String) -> Result<()>;
	fn get_channel(&self, id: i64) -> Result<Channel>;
	fn update_channel(&self, id: i64, name: String) -> Result<()>;
	fn delete_channel(&self, id: i64) -> Result<()>;
	fn get_channel_members(&self, gid: i64) -> Result<Vec<i64>>;
	fn remove_channel_member(&self, cid: i64, id: i64) -> Result<()>;
	fn add_channel_member(&self,cid: i64, id: i64) -> Result<()>;
		
	fn get_user_groups(&self, id: i64) -> Result<Vec<i64>>;
	fn delete_user_groups(&self, id: i64) -> Result<()>;
	fn add_user_group(&self, uid: i64, gid: i64) -> Result<()>;
	fn remove_user_group(&self, uid: i64, gid: i64) -> Result<()>;

	fn get_message(&self, id: i64) -> Result<Message>;
	fn get_messages(&self, cid: i64, num: u64) -> Result<Vec<Message>>;
}

pub struct Cassandra {
	kspc: String,
	sess: Session
}

impl Cassandra {
	pub fn new(keyspc: &str) -> Self {
		let contact_points = "127.0.0.1";
		let mut cluster = Cluster::default();
		cluster.set_contact_points(contact_points).unwrap();
		cluster.set_load_balance_round_robin();
		let session = cluster.connect().unwrap();

		session.execute(&stmt!(&format!(
			"CREATE KEYSPACE IF NOT EXISTS {keyspc} \
			 WITH replication = {{'class':'SimpleStrategy', 'replication_factor': 1}}"
		))).wait().unwrap();

		session.execute(&stmt!(&format!(
			"CREATE TABLE IF NOT EXISTS {keyspc}.users \
			 (id bigint PRIMARY KEY, name text, email text, hash text);"
		))).wait().unwrap();

		session.execute(&stmt!(&format!(
			"CREATE TABLE IF NOT EXISTS {keyspc}.groups \
			 (id bigint PRIMARY KEY, name text, members set<bigint>, channels set<bigint>);"
		))).wait().unwrap();

		session.execute(&stmt!(&format!(
			"CREATE TABLE IF NOT EXISTS {keyspc}.channels \
			 (id bigint PRIMARY KEY, name text, group bigint, members set<bigint>);"
		))).wait().unwrap();

		session.execute(&stmt!(&format!(
			"CREATE TABLE IF NOT EXISTS {keyspc}.user_groups \
			 (id bigint PRIMARY KEY, groups set<bigint>);"
		))).wait().unwrap();

		session.execute(&stmt!(&format!(
			"CREATE TABLE IF NOT EXISTS {keyspc}.messages \
			 (channel bigint, id bigint, author bigint, \
			 time timestamp, content text, PRIMARY KEY (channel, id)) \
			 WITH CLUSTERING ORDER BY (id DESC);"
		))).wait().unwrap();

		Self {
			kspc: keyspc.to_string(),
			sess: session
		}
	}

	fn delete_row(&self, table: &str, id: i64) -> Result<()> {
		self.sess.execute(&stmt!(&format!(
			"DELETE FROM {}.{table} WHERE id={id};", self.kspc
		))).wait().unwrap();
		Ok(())
	}
	
	fn get_set(&self, table: &str, set: &str, id: i64) -> Result<Vec<i64>> {
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT {set} FROM {}.{table} WHERE id = {id};", self.kspc
		))).wait()?;
		let row = res.first_row().unwrap();
		let items: SetIterator = row.get(0)?;
		Ok(items.map(|i| i.get_i64().unwrap()).collect())
	}

	fn pop_set(&self, table: &str, set: &str, id: i64, elem: i64) -> Result<()> {
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.{table} SET {set} = {set} - {{{elem}}} WHERE ID={id};", self.kspc
		))).wait()?;
		Ok(())
	}

	fn push_set(&self, table: &str, set: &str, id: i64, elem: i64) -> Result<()> {
		self.sess.execute(&stmt!(&format!(
			"UPDATE {}.{table} SET {set} = {set} + {{{elem}}} WHERE ID={id};", self.kspc
		))).wait()?;
		Ok(())
	}
}

impl Database for Cassandra {
	fn valid_id(&self, kind: IdType, id: i64) -> Result<bool> {
		let table = match kind {
			IdType::User => "users",
			IdType::Group => "groups",
			IdType::Channel => "channels",
			IdType::Message => "messages",
		};
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT * FROM {}.{table} WHERE ID={id};", self.kspc
		))).wait()?;
		if let Some(_row) = res.first_row() {
			return Ok(true)
		} else { return Ok(false) };		
	}
	
	fn create_user(&self, id: i64, name: String, email: String, hash: String) -> Result<()> {
		let mut stmt = stmt!(&format!(
			"INSERT INTO {}.users (id, name, email, hash) VALUES ({id}, ?, ?, ?);", self.kspc
		));
		stmt.bind(0, name.as_str())?;
		stmt.bind(1, email.as_str())?;
		stmt.bind(2, hash.as_str())?;
		self.sess.execute(&stmt).wait()?;
		Ok(())
	}

	fn get_user(&self, id: i64) -> Result<User> {
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT name, email FROM {}.users WHERE ID={id};", self.kspc
		))).wait()?;
		let row = res.first_row().unwrap();
		Ok(User {
			id,
			username: row.get(0)?,
			email: row.get(1)?
		})
	}

	fn get_user_hash(&self, id: i64) -> Result<String> {
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT hash FROM {}.users WHERE ID={id};", self.kspc
		))).wait()?;
		let row = res.first_row().unwrap();
		Ok(row.get(0)?)
	}

	fn update_user(&self, id: i64, name: String, email: String) -> Result<()> {
		let mut stmt = stmt!(&format!(
			"UPDATE {}.users SET name=?, email=? WHERE ID={id};", self.kspc
		));
		stmt.bind(0, name.as_str())?;
		stmt.bind(1, email.as_str())?;
		self.sess.execute(&stmt).wait()?;
		Ok(())
	}

	fn delete_user(&self, id: i64) -> Result<()> {
		self.delete_row("users", id)
	}
	
	fn get_group(&self, id: i64) -> Result<Group> {
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT name, members, channels FROM {}.groups WHERE ID={id};", self.kspc
		))).wait()?;
		let row = res.first_row().unwrap();
		let members: SetIterator = row.get(1)?;
		let channels: SetIterator = row.get(2)?;		
		Ok(Group {
			id,
			name: row.get(0)?,
			members: members.map(|i| i.get_i64().unwrap()).collect(),
			channels: channels.map(|i| i.get_i64().unwrap()).collect(),
		})
	}

	fn create_group(&self, gid: i64, uid: i64, name: String) -> Result<()> {
		let mut stmt = stmt!(&format!(
			"INSERT INTO {}.groups (id, name, channels, members) VALUES ({gid}, ?, {{}}, {{{uid}}});", self.kspc
		));
		stmt.bind(0, name.as_str())?;
		self.sess.execute(&stmt).wait()?;
		Ok(())
	}
	
	fn delete_group(&self, id: i64) -> Result<()> {
		self.delete_row("groups", id)
	}

	fn update_group(&self, id: i64, name: String) -> Result<()> {
		let mut stmt = stmt!(&format!(
			"UPDATE {}.groups SET name = ? WHERE id = {id};", self.kspc
		));
		stmt.bind(0, name.as_str())?;
		self.sess.execute(&stmt).wait()?;
		Ok(())
	}

	fn get_group_members(&self, gid: i64) -> Result<Vec<i64>> {
		self.get_set("groups", "members", gid)
	}
	
	fn get_group_channels(&self, gid: i64) -> Result<Vec<i64>> {
		self.get_set("groups", "channels", gid)
	}
	
	fn add_group_member(&self, gid: i64, uid: i64) -> Result<()> {
		self.push_set("groups", "members", gid, uid)
	}

	fn remove_group_member(&self, gid: i64, uid: i64) -> Result<()> {
		self.pop_set("groups", "members", gid, uid)
	}

	fn add_group_channel(&self, gid: i64, uid: i64) -> Result<()> {
		self.push_set("groups", "channels", gid, uid)
	}

	fn remove_group_channel(&self, gid: i64, uid: i64) -> Result<()> {
		self.pop_set("groups", "channels", gid, uid)
	}
	
	fn get_channel(&self, id: i64) -> Result<Channel> {
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT group, name, members FROM {}.channels WHERE ID={id};", self.kspc
		))).wait()?;
		let row = res.first_row().unwrap();
		let members: SetIterator = row.get(2)?;		
		Ok(Channel {
			id,
			group: row.get(0)?,
			name: row.get(1)?,			
			members: members.map(|i| i.get_i64().unwrap()).collect(),			
		})
	}

	fn create_channel(&self, cid: i64, gid: i64, uid: i64, name: String) -> Result<()> {
		let mut stmt = stmt!(&format!(
			"INSERT INTO {}.channels (id, group, name, members) VALUES ({cid}, {gid}, ?, {{{uid}}});", self.kspc
		));
		stmt.bind(0, name.as_str())?;
		self.sess.execute(&stmt).wait()?;
		Ok(())
	}
	
	fn delete_channel(&self, id: i64) -> Result<()> {
		self.delete_row("channels", id)		
	}

	fn update_channel(&self, id: i64, name: String) -> Result<()> {
		let mut stmt = stmt!(&format!(
			"UPDATE {}.channels SET name = ? WHERE id = {id};", self.kspc
		));
		stmt.bind(0, name.as_str())?;
		self.sess.execute(&stmt).wait()?;
		Ok(())
	}
	
	fn get_channel_members(&self, cid: i64) -> Result<Vec<i64>> {
		self.get_set("channel", "members", cid)
	}
	
	fn add_channel_member(&self, gid: i64, uid: i64) -> Result<()> {
		self.push_set("channels", "members", gid, uid)
	}

	fn remove_channel_member(&self, gid: i64, uid: i64) -> Result<()> {
		self.pop_set("channels", "members", gid, uid)
	}
	
	fn get_user_groups(&self, id: i64) -> Result<Vec<i64>> {
		self.get_set("user_groups", "groups", id)
	}

	fn add_user_group(&self, uid: i64, gid: i64) -> Result<()> {
		self.push_set("user_groups", "groups", uid, gid)
	}

	fn remove_user_group(&self, uid: i64, gid: i64) -> Result<()> {
		self.pop_set("user_groups", "groups", uid, gid)
	}

	fn delete_user_groups(&self, id: i64) -> Result<()> {
		self.delete_row("user_groups", id)		
	}

	// TODO the unwraps here are not great
	fn get_messages(&self, cid: i64, num: u64) -> Result<Vec<Message>> {
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT * FROM {}.messages WHERE channel={cid} LIMIT {num};", self.kspc
		))).wait()?;
		Ok(res.iter().map(|row| {
			Message {
				id: row.get(0).unwrap(),
				author: row.get(2).unwrap(),
				channel: row.get(1).unwrap(),
				content: row.get(4).unwrap()
			}
		}).collect::<Vec<Message>>())
	}

	fn get_message(&self, id: i64) -> Result<Message> {
		let res = self.sess.execute(&stmt!(&format!(
			"SELECT channel, author, content, time FROM {}.users WHERE ID={id};", self.kspc
		))).wait()?;		
		let row = res.first_row().unwrap();
		Ok(Message {
			id,
			channel: row.get(0)?,
			author: row.get(1)?,
			content: row.get(2)?,			
		})
	}
}
