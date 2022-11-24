use super::*;

use hmac::Mac;
use more_asserts::*;
use poem::{
    http::StatusCode,
    middleware::AddDataEndpoint,
    test::TestClient,
    Route,
};
use pretty_assertions::assert_eq;
use sha2::Digest;

type FakeClient = TestClient<AddDataEndpoint<Route, ServerKey>>;

fn contents_eq<T: PartialEq>(a: Vec<T>, b: Vec<T>) -> bool {
    b.iter().all(|item| a.contains(item))
}

fn setup() -> FakeClient {
    let key: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(char::from)
        .collect();
    let db = Box::new(Cassandra::new("test"));
    let api_service = OpenApiService::new(Api::new(db), "Scuttlebutt", "1.0").server("http://localhost:3000/api");
    let app = Route::new()
        .nest("/api", api_service)
        .data(ServerKey::new_from_slice(&key.as_bytes()).unwrap());
    TestClient::new(app)
}

fn hash_pass(pass: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pass);
    hex::encode(hasher.finalize())
}

async fn make_user(cli: &FakeClient, name: &str, email: &str, pass: &str) -> User {
    let hash = hash_pass(pass);
    let resp = cli.post(format!("/api/user?name={}&email={}", name, email))
        .content_type("text/plain").body(hash).send().await;
    resp.assert_status_is_ok();
    resp.json().await.value().deserialize::<User>()
}

async fn login(cli: &FakeClient, id: i64, pass: &str) -> String {
    let hash = hash_pass(pass);
    let mut resp = cli.post(format!("/api/login?id={}", id)).content_type("text/plain").body(hash).send().await;
    resp.assert_status_is_ok();
    resp.0.take_body().into_string().await.unwrap()
}

async fn user_auth(cli: &FakeClient, name: &str, email: &str, pass: &str) -> (User, String) {
    let user = make_user(&cli, name, email, pass).await;    
    let auth = login(&cli, user.id, pass).await;
    (user, auth)
}

async fn setup_user_auth() -> (FakeClient, User) {
    let cli = setup();
    let (user, auth) = user_auth(&cli, "test", "test@example.com", "12345").await;
    let cli = cli.default_header("Authorization", &auth);
    (cli, user)
}

async fn make_group(cli: &FakeClient, name: &str) -> Group {
    let resp = cli.post(format!("/api/group?name={}", name)).send().await;
    resp.assert_status_is_ok();
    resp.json().await.value().deserialize::<Group>()
}

async fn add_group_member(cli: &FakeClient, gid: i64, uid: i64) {
    let resp = cli.put(format!("/api/group/members?gid={}&uid={}", gid, uid)).send().await;
    resp.assert_status_is_ok();
}

async fn make_dm(cli: &FakeClient, uid: i64) -> Group {
    let resp = cli.post(format!("/api/dm?uid={}", uid)).send().await;
    resp.assert_status_is_ok();
    resp.json().await.value().deserialize::<Group>()
}

async fn find_groups(cli: &FakeClient) -> Vec<Group> {
    let resp = cli.post("/api/user/groups").send().await;
    resp.assert_status_is_ok();
    resp.json().await.value().deserialize::<Vec<Group>>()
}

async fn make_channel(cli: &FakeClient, gid: i64, name: &str, private:bool) -> Channel {
    let resp = cli.post(format!("/api/group/channels?gid={}&name={}", gid, name, private)).send().await;
    resp.assert_status_is_ok();
    resp.json().await.value().deserialize::<Channel>()
}

async fn find_channel(cli: &FakeClient, id: i64) -> Channel {
    let resp = cli.get(format!("/api/channel?id={}", id)).send().await;
    resp.assert_status_is_ok();
    resp.json().await.value().deserialize::<Channel>()
}

async fn find_group(cli: &FakeClient, id: i64) -> Group {
    let resp = cli.get(format!("/api/group?id={}", id)).send().await;
    resp.assert_status_is_ok();
    resp.json().await.value().deserialize::<Group>()
}

#[tokio::test]
async fn post_login() {
    let cli = setup();
    let user = make_user(&cli, "test", "test@example.com", "12345").await;
    let hash = hash_pass("12345");

    let resp = cli.post(format!("/api/login?id={}", user.id))
        .content_type("text/plain").body("abc").send().await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let resp = cli.post(format!("/api/login?id={}", user.id))
        .content_type("text/plain").send().await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    let resp = cli.post("/api/login?id=12")
        .content_type("text/plain").body(hash.clone()).send().await;
    resp.assert_status(StatusCode::NOT_FOUND);

    let resp = cli.post(format!("/api/login?id={}", user.id))
        .header::<&str, &str>("Authorization", "")
        .content_type("text/plain").body(hash_pass("123")).send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    let mut resp = cli.post(format!("/api/login?id={}", user.id))
        .content_type("text/plain").body(hash.clone()).send().await;
    resp.assert_status_is_ok();
    let raw_str = resp.0.take_body().into_string().await.unwrap();
    let claims: Claims = serde_json::from_str(&String::from_utf8(base64::decode(
        raw_str.split(".").nth(1).unwrap()
    ).unwrap()).unwrap()).unwrap();
    assert_eq!(claims.id, user.id);
    assert_ge!(claims.exp, Local::now())
}

#[tokio::test]
async fn get_user() {
    let cli = setup();
    let user = make_user(&cli, "test", "test@example.com", "12345").await;
    let resp = cli.get("/api/user?id=12").send().await;
    resp.assert_status(StatusCode::NOT_FOUND);
    let resp = cli.get(format!("/api/user?id={}", user.id)).send().await;
    resp.assert_status_is_ok();
    let ret_user = resp.json().await.value().deserialize::<User>();
    assert_eq!(user, ret_user);
}

#[tokio::test]
async fn post_user() {
    let cli = setup();
    let user = make_user(&cli, "test", "test@example.com", "12345").await;

    assert_eq!(user.email, "test@example.com");
    assert_eq!(user.username, "test");

    let resp = cli.get(format!("/api/user?id={}", user.id)).send().await;
    resp.assert_status_is_ok();

    let same_user = resp.json().await.value().deserialize::<User>();
    assert_eq!(user, same_user);
}

#[tokio::test]
async fn post_user_whitebox() {
    let cli = setup();
    let user = make_user(&cli, "test", "test@example.com", "12345").await;
    let db = Cassandra::new("test");
    assert_eq!(db.get_user(user.id).unwrap(), user);
    assert_eq!(db.get_user_groups(user.id).unwrap(), Vec::<i64>::new());
}

#[tokio::test]
async fn put_user() {
    let (cli, user) = setup_user_auth().await;

    let resp = cli.put("/api/user?name=fred&email=whoo@whee.com")
        .header::<&str, &str>("Authorization", "").send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    let resp = cli.put("/api/user?name=fred&email=whoo@whee.com").send().await;
    resp.assert_status_is_ok();

    let resp = cli.get(format!("/api/user?id={}", user.id)).send().await;
    resp.assert_status_is_ok();
    let ret_user = resp.json().await.value().deserialize::<User>();
    assert_eq!(ret_user.email, "whoo@whee.com");
    assert_eq!(ret_user.username, "fred");
    // User should retain their underlying ID
    assert_eq!(user.id, ret_user.id);
}

#[tokio::test]
/// FIXME non exhaustive
async fn del_user() {
    let (cli, user) = setup_user_auth().await;

    let resp = cli.delete(format!("/api/user?id={}", user.id))
        .header::<&str, &str>("Authorization", "").send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    let resp = cli.delete(format!("/api/user?id={}", user.id)).send().await;

    resp.assert_status_is_ok();
    let resp = cli.get(format!("/api/user?id={}", user.id)).send().await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn post_group() {
    let (cli, user) = setup_user_auth().await;
    let resp = cli.post("/api/group?name=test")
        .header::<&str, &str>("Authorization", "").send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    let resp = cli.post("/api/group?name=").send().await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let resp = cli.post("/api/group?name=test").send().await;
    resp.assert_status_is_ok();

    let group = resp.json().await.value().deserialize::<Group>();
    assert_eq!(group.name, "test");
    assert_eq!(group.members, vec![user.id]);
    assert_eq!(group.admin, vec![user.id]);
    assert_eq!(group.owner, user.id);
    assert_eq!(group.channels.len(), 1);

    let channel = find_channel(&cli, group.channels[0]).await;
    assert_eq!(channel.members, vec![user.id]);
    assert_eq!(channel.private, false);
    assert_eq!(
        find_channel(&cli, group.channels[0]).await.name,
        String::from("main")
    );
}

#[tokio::test]
async fn post_dm() {
    let (cli, user) = setup_user_auth().await;
    let (user2, auth2) = user_auth(&cli, "user2", "who@cares.com", "12").await;
    let resp = cli.post("/api/dm?uid=12")
        .header::<&str, &str>("Authorization", "").send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
    
    let resp = cli.post(format!("/api/dm?uid={}", user2.id)).send().await;
    resp.assert_status_is_ok();

    let group = resp.json().await.value().deserialize::<Group>();
    assert_eq!(group.name, "");
    assert_eq!(group.members, vec![user.id, user2.id]);
    assert_eq!(group.admin, Vec::<i64>::new());
    assert_eq!(group.owner, user.id);
    assert_eq!(group.channels.len(), 1);   
}

#[tokio::test]
async fn post_dm_whitebox() {
    let (cli, user) = setup_user_auth().await;
    let (user2, auth2) = user_auth(&cli, "user2", "who@cares.com", "12").await;
    let resp = cli.post(format!("/api/dm?uid={}", user2.id)).send().await;
    resp.assert_status_is_ok();
    let dm = resp.json().await.value().deserialize::<Group>();

    let db = Cassandra::new("test");
    assert_eq!(db.get_group(dm.id).unwrap(), dm);
    assert_eq!(db.get_user_dms(user.id).unwrap(), vec![dm.id]);
}

#[tokio::test]
async fn put_group() {
    let (cli, _user) = setup_user_auth().await;
    let (user2, auth2) = user_auth(&cli, "user2", "who@cares.com", "12").await;
    let group = make_group(&cli, "test").await;
    add_group_member(&cli, group.id, user2.id).await;

    let resp = cli.put(format!("/api/group?id={}&name=test2", group.id))
        .header::<&str, &str>("Authorization", "").send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
    let resp = cli.put(format!("/api/group?id={}&name=test2", group.id))
        .header::<&str, &str>("Authorization", &auth2).send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
    
    let resp = cli.put(format!("/api/group?id={}&name=", group.id)).send().await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    let resp = cli.put("/api/group?id=12&name=test2").send().await;
    resp.assert_status(StatusCode::NOT_FOUND);

    let resp = cli.put(format!("/api/group?id={}&name=test2", group.id)).send().await;
    resp.assert_status_is_ok();

    let group = find_group(&cli, group.id).await;
    assert_eq!(group.name, String::from("test2"));
}

#[tokio::test]
/// TODO non exhaustive
async fn del_group() {
    let (cli, _user) = setup_user_auth().await;
    let group = make_group(&cli, "test").await;

    let resp = cli.delete(format!("/api/group?id={}", group.id))
        .header::<&str, &str>("Authorization", "").send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    let resp = cli.delete("/api/group?id=12").send().await;
    resp.assert_status(StatusCode::NOT_FOUND);

    let resp = cli.delete(format!("/api/group?id={}", group.id)).send().await;
    resp.assert_status_is_ok();

    let resp = cli.get(format!("/api/group?id={}", group.id)).send().await;
    resp.assert_status(StatusCode::NOT_FOUND);
    let resp = cli.get(format!("/api/channel?id={}", group.channels[0])).send().await;
    resp.assert_status(StatusCode::NOT_FOUND);

    let resp = cli.get("/api/user/groups").send().await;
    resp.assert_status_is_ok();
    let groups = resp.json().await.value().deserialize::<Vec<Group>>();
    assert!(!groups.contains(&group));
}

// #[tokio::test]
// async fn get_group_members() {
//     let (cli, user) = setup_user_auth().await;
//     let group = make_group(&cli, auth.clone(), "test").await;
//     add_group_member
// }

#[tokio::test]
/// TODO non exhaustive
async fn put_group_members() {
    let (cli, user) = setup_user_auth().await;
    let group = make_group(&cli, "test").await;
    let user2 = make_user(&cli, "testeroo", "test2@example.com", "123456").await;
    
    let resp = cli.put(format!("/api/group/members?gid={}&uid={}", group.id, user2.id))
        .header::<&str, &str>("Authorization", "").send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    let resp = cli.put(format!("/api/group/members?gid={}&uid=", group.id)).send().await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    let resp = cli.put(format!("/api/group/members?gid=12&uid={}", user.id)).send().await;
    resp.assert_status(StatusCode::NOT_FOUND);

    let resp = cli.put(format!("/api/group/members?gid={}&uid={}", group.id, user2.id)).send().await;
    resp.assert_status_is_ok();
    
    assert!(find_group(&cli, group.id).await.members.contains(&user2.id));
}
#[test]
/// Test if gen_id() gives unique IDs on successive calls
/// and if it can be called from multiple threads without error
fn test_id_gen() {
    let a = gen_id();
    std::thread::sleep(std::time::Duration::from_secs(1));
    let b = gen_id();
    assert_ge!(b, a);
    let threads: Vec<_> = (0..100).map(|i| std::thread::spawn(move || gen_id())).collect();
    for handle in threads {
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn get_channel() {
    let (cli, _user) = setup_user_auth().await;
    let group = make_group(&cli, "test").await;
    let chan = make_channel(&cli, group.id, "random", true).await;
    let resp = cli.get(format!("/api/channel?id={}", chan.id)).send().await;
    resp.assert_status_is_ok();
    let recv_chan = resp.json().await.value().deserialize::<Channel>();
    assert_eq!(chan, recv_chan);
}


#[tokio::test]
async fn post_channel_whitebox() {
    let (cli, _user) = setup_user_auth().await;
    let group = make_group(&cli, "test").await;
    let chan = make_channel(&cli, group.id, "random", true).await;
    
    let db = Cassandra::new("test");
    assert_eq!(db.get_channel(chan.id).unwrap(), chan);
    assert!(db.get_group_channels(group.id).unwrap().contains(&chan.id));
}


// FIXME non exhaustive
#[tokio::test]
async fn get_channels() {
    let (cli, _user) = setup_user_auth().await;
    let group = make_group(&cli, "test").await;
    let chan1 = make_channel(&cli, group.id, "random", true).await; // are private here
    let chan2 = make_channel(&cli, group.id, "random", true).await;
    let chan3 = make_channel(&cli, group.id, "random", true).await;
    let resp = cli.get(format!("/api/group/channels?gid={}", group.id)).send().await;
    resp.assert_status_is_ok();
    let channels = resp.json().await.value().deserialize::<Vec<Channel>>();

    assert!(contents_eq(
        channels,
        vec![find_channel(&cli, group.channels[0]).await, chan1, chan2, chan3]
    ));
}

#[tokio::test]
async fn get_group() {
    let (cli, _user) = setup_user_auth().await;
    let (user2, auth2) = user_auth(&cli, "wehee", "who@cares.com", "12").await;
    let group = make_group(&cli, "test1").await;
    let group2 = make_group(&cli, "test2").await;
    add_group_member(&cli, group2.id, user2.id).await;
    
    let resp = cli.get(format!("/api/group?id={}", group.id)).send().await;
    resp.assert_status_is_ok();
    let recv_group = resp.json().await.value().deserialize::<Group>();
    assert_eq!(group, recv_group);

    let resp = cli.get(format!("/api/group?id={}", group.id))
        .header::<&str, &str>("Authorization", &auth2).send().await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_groups() {
    let (cli, _user) = setup_user_auth().await;
    let (user2, auth2) = user_auth(&cli, "wehee", "who@cares.com", "12").await;
    let group = make_group(&cli, "test1").await;
    add_group_member(&cli, group.id, user2.id).await;
    let group = find_group(&cli, group.id).await;
    let group2 = make_group(&cli, "test2").await;
    let group3 = make_group(&cli, "test3").await;
    
    let resp = cli.get("/api/user/groups").send().await;
    resp.assert_status_is_ok();
    let groups = resp.json().await.value().deserialize::<Vec<Group>>();
    assert!(contents_eq(groups, vec![group.clone(), group2, group3]));

    let resp = cli.get("/api/user/groups")
        .header::<&str, &str>("Authorization", &auth2).send().await;
    resp.assert_status_is_ok();
    let groups = resp.json().await.value().deserialize::<Vec<Group>>();
    assert!(contents_eq(groups, vec![group]));
}

#[tokio::test]
async fn get_dms() {
    let (cli, _user) = setup_user_auth().await;
    let (user2, auth2) = user_auth(&cli, "wehee", "who@cares.com", "12").await;
    let (user3, auth3) = user_auth(&cli, "whoo", "why@ask.com", "11").await;
    let dm1 = make_dm(&cli, user2.id).await;
    add_group_member(&cli, dm1.id, user3.id).await;
    let dm2 = make_dm(&cli, user3.id).await;
    let dm1 = find_group(&cli, dm1.id).await;
    let dm2 = find_group(&cli, dm2.id).await;
        
    let resp = cli.get("/api/user/dms").send().await;
    resp.assert_status_is_ok();
    let dms = resp.json().await.value().deserialize::<Vec<Group>>();
    assert!(contents_eq(dms, vec![dm1.clone(), dm2.clone()]));
    
    let resp = cli.get("/api/user/dms")
        .header::<&str, &str>("Authorization", &auth2).send().await;
    resp.assert_status_is_ok();
    let dms = resp.json().await.value().deserialize::<Vec<Group>>();
    assert!(contents_eq(dms, vec![dm1.clone()]));

    let resp = cli.get("/api/user/dms")
        .header::<&str, &str>("Authorization", &auth3).send().await;
    resp.assert_status_is_ok();
    let dms = resp.json().await.value().deserialize::<Vec<Group>>();
    assert!(contents_eq(dms, vec![dm1.clone(), dm2.clone()]));
}

#[tokio::test]
async fn leave_group() {
    let (cli, user) = setup_user_auth().await;
    let (user2, auth2) = user_auth(&cli, "wehee", "who@cares.com", "12").await;
    let group = make_group(&cli, "test1").await;
    add_group_member(&cli, group.id, user2.id).await;

    let resp = cli.delete(format!("/api/user/groups?gid={}", group.id))
        .header::<&str, &str>("Authorization", &auth2).send().await;    
    resp.assert_status_is_ok();

    let members = find_group(&cli, group.id).await.members;
    assert!(contents_eq(members, vec![user.id]));
}
