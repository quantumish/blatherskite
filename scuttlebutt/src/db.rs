use cassandra_cpp::{Value, SetIterator, Session, AsRustType, BindRustType, Result, Cluster, stmt};
use crate::responses::*;

#[derive(Debug)]
pub enum IdType {
    User,
    Group,
    Channel,
    Message
}

/// Trait for the back-end database that contains all CRUD database operations.
///
/// **Every method (outside of `valid_id`) assumes that the IDs passed are valid.**
///
/// Meant to enable switching backends, but right now the Result type is hardcoded
/// to a `cassandra_cpp::Result` due to other concerns (see [Issue #2](https://github.com/quantumish/blatherskite/issues/2) discussion on repo).
pub trait Database: Sync + Send {
    fn valid_id(&self, kind: IdType, id: i64) -> Result<bool>;

    fn create_user(&self, id: i64, name: String, email: String, hash: String) -> Result<()>;
    fn update_user(&self, id: i64, name: String, email: String) -> Result<()>;
    fn get_user(&self, id: i64) -> Result<User>;
    fn get_user_hash(&self, id: i64) -> Result<String>;
    fn delete_user(&self, id: i64) -> Result<()>;

    fn create_group(&self, gid: i64, uid: i64, name: String, dm: bool) -> Result<()>;
    fn get_group(&self, id: i64) -> Result<Group>;
    fn update_group(&self, id: i64, name: String) -> Result<()>;
    fn delete_group(&self, id: i64) -> Result<()>;
    
    fn get_group_members(&self, gid: i64) -> Result<Vec<i64>>;
    fn add_group_member(&self, gid: i64, uid: i64) -> Result<()>;
    fn remove_group_member(&self, gid: i64, uid: i64) -> Result<()>;
    
    fn get_group_channels(&self, gid: i64) -> Result<Vec<i64>>;    
    fn add_group_channel(&self, gid: i64, uid: i64) -> Result<()>;
    fn remove_group_channel(&self, gid: i64, uid: i64) -> Result<()>;
    
    fn get_group_admin(&self, gid: i64) -> Result<Vec<i64>>;
    fn add_group_admin(&self, gid: i64, uid: i64) -> Result<()>;
    fn remove_group_admin(&self, gid: i64, uid: i64) -> Result<()>;
    
    fn get_group_owner(&self, gid: i64) -> Result<i64>;

    fn is_group_dm(&self, gid: i64) -> Result<bool>;

    fn create_channel(&self, cid: i64, gid: i64, uid: i64, name: String) -> Result<()>;
    fn get_channel(&self, id: i64) -> Result<Channel>;
    fn update_channel(&self, id: i64, name: String) -> Result<()>;
    fn delete_channel(&self, id: i64) -> Result<()>;

    fn get_channel_members(&self, gid: i64) -> Result<Vec<i64>>;
    fn add_channel_member(&self,cid: i64, id: i64) -> Result<()>;
    fn remove_channel_member(&self, cid: i64, id: i64) -> Result<()>;

    fn is_channel_private(&self, id: i64) -> Result<bool>;
    fn set_channel_private(&self, id: i64, value: bool) -> Result<bool>;

    fn create_user_groups(&self, id: i64) -> Result<()>;
    fn get_user_groups(&self, id: i64) -> Result<Vec<i64>>;
    fn delete_user_groups(&self, id: i64) -> Result<()>;
    fn add_user_group(&self, uid: i64, gid: i64) -> Result<()>;
    fn remove_user_group(&self, uid: i64, gid: i64) -> Result<()>;

    fn create_user_dms(&self, id: i64) -> Result<()>;
    fn get_user_dms(&self, id: i64) -> Result<Vec<i64>>;
    fn delete_user_dms(&self, id: i64) -> Result<()>;
    fn add_user_dm(&self, uid: i64, gid: i64) -> Result<()>;    
    
    fn get_message(&self, id: i64) -> Result<Message>;
    fn get_messages(&self, cid: i64, num: u64) -> Result<Vec<Message>>;
    fn delete_message(&self, id: i64) -> Result<()>;
    fn set_thread(&self, id: i64, cid: i64) -> Result<()>;
}

/// Cassandra backend struct
pub struct Cassandra {
    kspc: String, // keyspace
    sess: Session 
}

impl Cassandra {
    /// Initialize the database session and creates tables
    ///
    /// Arguments:
    /// - `keyspc`: the keyspace to use for all database queries.
    pub fn new(keyspc: &str) -> Self {
        let contact_points = "127.0.0.1"; // NOTE: generalize me
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
             (id bigint PRIMARY KEY, name text, members set<bigint>, is_dm boolean, \
             channels set<bigint>, admin set<bigint>, owner bigint);"
        ))).wait().unwrap();

        session.execute(&stmt!(&format!(
            "CREATE TABLE IF NOT EXISTS {keyspc}.channels \
             (id bigint PRIMARY KEY, group bigint, name text, \
             members set<bigint>, private boolean);"
        ))).wait().unwrap();

        session.execute(&stmt!(&format!(
            "CREATE TABLE IF NOT EXISTS {keyspc}.user_groups \
             (id bigint PRIMARY KEY, groups set<bigint>);"
        ))).wait().unwrap();

        session.execute(&stmt!(&format!(
            "CREATE TABLE IF NOT EXISTS {keyspc}.user_dms \
             (id bigint PRIMARY KEY, dms set<bigint>);"
        ))).wait().unwrap();
        
        session.execute(&stmt!(&format!(
            "CREATE TABLE IF NOT EXISTS {keyspc}.messages \
             (channel bigint, id bigint, author bigint, \
             content text, group bigint, thread bigint, \
             PRIMARY KEY (channel, id)) \
             WITH CLUSTERING ORDER BY (id DESC);"
        ))).wait().unwrap();

        Self {
            kspc: keyspc.to_string(),
            sess: session
        }
    }

    /// Delete a row from the database.
    ///
    /// Arguments:
    /// - `table`: the table to delete the row from
    /// - `id`: the id of the row to delete
    fn delete_row(&self, table: &str, id: i64) -> Result<()> {
        self.sess.execute(&stmt!(&format!(
            "DELETE FROM {}.{table} WHERE id={id};", self.kspc
        ))).wait().unwrap();
        Ok(())
    }

    /// Extract a set from a database row
    ///
    /// Arguments:
    /// - `table`: the table with the desired row
    /// - `set`: the name of the column with the set in it
    /// - `id`: the id of the row to get the set from
    fn get_set(&self, table: &str, set: &str, id: i64) -> Result<Vec<i64>> {
        let res = self.sess.execute(&stmt!(&format!(
            "SELECT {set} FROM {}.{table} WHERE id = {id};", self.kspc
        ))).wait()?;
        let row = res.first_row().unwrap();
        let set: Value = row.get_column(0)?;
        Ok(match set.is_null() {
            true => Vec::new(),
            false => set.get_set()?.map(|i| i.get_i64().unwrap()).collect()
        })
    }

    /// Remove an element from a set in a database row
    ///
    /// Arguments:
    /// - `table`: the table with the desired row
    /// - `set`: the name of the column with the set in it
    /// - `id`: the id of the row to get the set from
    /// - `elem`: the element to remove from the set
    fn pop_set(&self, table: &str, set: &str, id: i64, elem: i64) -> Result<()> {
        self.sess.execute(&stmt!(&format!(
            "UPDATE {}.{table} SET {set} = {set} - {{{elem}}} WHERE ID={id};", self.kspc
        ))).wait()?;
        Ok(())
    }

    /// Add an element to a set in a database row
    ///
    /// Arguments:
    /// - `table`: the table with the desired row
    /// - `set`: the name of the column with the set in it
    /// - `id`: the id of the row to get the set from
    /// - `elem`: the element to add to the set
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
            "SELECT name, members, channels, owner, is_dm FROM {}.groups WHERE ID={id};", self.kspc
        ))).wait()?;
        let row = res.first_row().unwrap();
        let members: SetIterator = row.get(1)?;
        let channels: SetIterator = row.get(2)?;        
        Ok(Group {
            id,
            name: row.get(0)?,
            members: members.map(|i| i.get_i64().unwrap()).collect(),
            channels: channels.map(|i| i.get_i64().unwrap()).collect(),
            admin: self.get_set("groups", "admin", id)?, // HACK
            owner: row.get(3)?,
            is_dm: row.get(4)?,
        })
    }

    fn create_group(&self, gid: i64, uid: i64, name: String, dm: bool) -> Result<()> {
        let mut stmt = stmt!(&format!(
            "INSERT INTO {}.groups (id, name, channels, \
             members, is_dm, owner) VALUES ({gid}, ?, {{}}, {{{uid}}}, {dm}, {uid});", self.kspc
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

    fn add_group_member(&self, gid: i64, uid: i64) -> Result<()> {
        self.push_set("groups", "members", gid, uid)
    }

    fn remove_group_member(&self, gid: i64, uid: i64) -> Result<()> {
        self.pop_set("groups", "members", gid, uid)
    }

    fn get_group_channels(&self, gid: i64) -> Result<Vec<i64>> {
        self.get_set("groups", "channels", gid)
    }

    fn add_group_channel(&self, gid: i64, cid: i64) -> Result<()> {
        self.push_set("groups", "channels", gid, cid)
    }

    fn remove_group_channel(&self, gid: i64, cid: i64) -> Result<()> {
        self.pop_set("groups", "channels", gid, cid)
    }

    fn get_group_admin(&self, gid: i64) -> Result<Vec<i64>> {
        self.get_set("groups", "admin", gid)
    }

    fn add_group_admin(&self, gid: i64, uid: i64) -> Result<()> {
        self.push_set("groups", "admin", gid, uid)
    }


    fn remove_group_admin(&self, gid: i64, uid: i64) -> Result<()> {
        self.pop_set("groups", "admin", gid, uid)
    }

    fn get_group_owner(&self, gid: i64) -> Result<i64> {
        let res = self.sess.execute(&stmt!(&format!(
            "SELECT owner FROM {}.groups WHERE id={gid};", self.kspc
        ))).wait()?;
        let row = res.first_row().unwrap();
        Ok(row.get(0)?)
    }

    fn is_group_dm(&self, gid: i64) -> Result<bool> {
        let res = self.sess.execute(&stmt!(&format!(
            "SELECT is_dm FROM {}.groups WHERE id={gid};", self.kspc
        ))).wait()?;
        let row = res.first_row().unwrap();
        Ok(row.get(0)?)
    }
    
    fn get_channel(&self, id: i64) -> Result<Channel> {
        let res = self.sess.execute(&stmt!(&format!(
            "SELECT group, name, members, private FROM {}.channels WHERE ID={id};", self.kspc
        ))).wait()?;
        let row = res.first_row().unwrap();
        let members: SetIterator = row.get(2)?;
        Ok(Channel {
            id,
            group: row.get(0)?,
            name: row.get(1)?,
            members: members.map(|i| i.get_i64().unwrap()).collect(),
            private: row.get(3)?
        })
    }

    fn create_channel(&self, cid: i64, gid: i64, uid: i64, name: String) -> Result<()> {
        let mut stmt = stmt!(&format!(
            "INSERT INTO {}.channels (id, group, name, members, private) VALUES ({cid}, {gid}, ?, {{{uid}}}, false);", self.kspc
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
        self.get_set("channels", "members", cid)
    }

    fn add_channel_member(&self, gid: i64, uid: i64) -> Result<()> {
        self.push_set("channels", "members", gid, uid)
    }

    fn remove_channel_member(&self, gid: i64, uid: i64) -> Result<()> {
        self.pop_set("channels", "members", gid, uid)
    }

    fn is_channel_private(&self, id: i64) -> Result<bool> {
        let res = self.sess.execute(&stmt!(&format!(
            "SELECT private FROM {}.channels WHERE id={id};", self.kspc
        ))).wait()?;
        let row = res.first_row().unwrap();
        Ok(row.get(0)?)
    }

    fn set_channel_private(&self, id: i64, value: bool) -> Result<bool> {
        let res = self.sess.execute(&stmt!(&format!(
            "UPDATE {}.channels SET private = {value} WHERE id={id};", self.kspc
        ))).wait()?;
        let row = res.first_row().unwrap();
        Ok(row.get(0)?)
    }

    fn create_user_dms(&self, id: i64) -> Result<()> {
        self.sess.execute(&stmt!(&format!(
            "INSERT INTO {}.user_dms (id, dms) VALUES ({id}, {{}});", self.kspc
        ))).wait()?;
        Ok(())
    }

    fn get_user_dms(&self, id: i64) -> Result<Vec<i64>> {
        self.get_set("user_dms", "dms", id)
    }

    fn add_user_dm(&self, uid: i64, gid: i64) -> Result<()> {
        self.push_set("user_dms", "dms", uid, gid)
    }

    fn delete_user_dms(&self, id: i64) -> Result<()> {
        self.delete_row("user_dms", id)
    }
    
    fn create_user_groups(&self, id: i64) -> Result<()> {
        self.sess.execute(&stmt!(&format!(
            "INSERT INTO {}.user_groups (id, groups) VALUES ({id}, {{}});", self.kspc
        ))).wait()?;
        Ok(())
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
            let maybe_thread: Value = row.get_column(5).unwrap();
            Message {
                id: row.get(0).unwrap(),
                author: row.get(2).unwrap(),
                channel: row.get(1).unwrap(),
                content: row.get(4).unwrap(),
                thread: match maybe_thread.is_null() {
                    true => None,
                    false => Some(maybe_thread.get_i64().unwrap())
                }
            }
        }).collect::<Vec<Message>>())
    }

    fn get_message(&self, id: i64) -> Result<Message> {
        let res = self.sess.execute(&stmt!(&format!(
            "SELECT channel, author, content, thread FROM {}.messages WHERE ID={id};", self.kspc
        ))).wait()?;
        let row = res.first_row().unwrap();
        let thread: Value = row.get_column(3)?;
        Ok(Message {
            id,
            channel: row.get(0)?,
            author: row.get(1)?,
            content: row.get(2)?,
            thread: match thread.is_null() {
                true => None,
                false => Some(thread.get_i64().unwrap())
            }
        })
    }

    fn delete_message(&self, id: i64) -> Result<()> {
        self.delete_row("messages", id)
    }

    fn set_thread(&self, id: i64, cid: i64) -> Result<()> {
        self.sess.execute(&stmt!(&format!(
            "UPDATE {}.messages SET thread = {cid} WHERE id = {id};", self.kspc
        ))).wait()?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn test_delete_row() {
        let db = Cassandra::new("test");
        db.sess.execute(&stmt!(
            "INSERT INTO test.users (id, name, email, hash) VALUES (11, 'fred', '', '');"
        )).wait().unwrap();
        db.delete_row("users", 11).unwrap();
        let res = db.sess.execute(&stmt!(
            "SELECT * FROM test.users WHERE id=11;"
        )).wait().unwrap();
        assert_eq!(res.row_count(), 0);
    }

    #[test]
    fn test_get_set() {
        let db = Cassandra::new("test");
        db.sess.execute(&stmt!(
            "INSERT INTO test.user_groups (id, groups) VALUES (12, {1,2,3});"
        )).wait().unwrap();
        assert_eq!(db.get_set("user_groups", "groups", 12).unwrap(), vec![1,2,3]);
        db.delete_row("user_groups", 12).unwrap();        
    }

    #[test]
    fn test_push_set() {
        let db = Cassandra::new("test");
        db.sess.execute(&stmt!(
            "INSERT INTO test.user_groups (id, groups) VALUES (13, {1,2,3});"
        )).wait().unwrap();
        db.push_set("user_groups", "groups", 13, 4).unwrap();
        assert_eq!(db.get_set("user_groups", "groups", 13).unwrap(), vec![1,2,3,4]);
        db.delete_row("user_groups", 13).unwrap();
    }

    #[test]
    fn test_pop_set() {
        let db = Cassandra::new("test");
        db.sess.execute(&stmt!(
            "INSERT INTO test.user_groups (id, groups) VALUES (14, {1,2,3});"
        )).wait().unwrap();
        db.pop_set("user_groups", "groups", 14, 3).unwrap();
        assert_eq!(db.get_set("user_groups", "groups", 14).unwrap(), vec![1,2]);
        db.delete_row("user_groups", 14).unwrap();
    }
}
