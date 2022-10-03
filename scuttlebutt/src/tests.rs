use super::*;

use hmac::Mac;
use more_asserts::*;
use poem::{
    http::StatusCode,
    middleware::AddDataEndpoint,
    test::{TestClient, TestRequestBuilder, TestResponse},
    Route,
};
use pretty_assertions::assert_eq;
use sha2::Digest;

type FakeClient = TestClient<AddDataEndpoint<Route, ServerKey>>;

fn setup() -> FakeClient {
    let key: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(char::from)
        .collect();
    let api_service = OpenApiService::new(Api::new("test"), "Scuttlebutt", "1.0").server("http://localhost:3000/api");
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

enum HttpMethod {
    Post(String),
    Get(String),
    Delete(String),
    Put(String),
}
use crate::tests::HttpMethod::*;

async fn make_user(cli: &FakeClient, name: &str, email: &str, pass: &str) -> User {
    let hash = hash_pass(pass);
    let resp = cli
        .post(format!("/api/user?name={}&email={}&hash={}", name, email, hash))
        .send()
        .await;
    resp.assert_status_is_ok();
    resp.json().await.value().deserialize::<User>()
}

async fn login(cli: &FakeClient, id: i64, pass: &str) -> String {
    let hash = hash_pass(pass);
    let mut resp = cli.post(format!("/api/login?id={}", id))
		.content_type("text/plain")
		.body(hash).send().await;
    resp.assert_status_is_ok();
    resp.0.take_body().into_string().await.unwrap()
}

async fn setup_user_auth() -> (FakeClient, User, String) {
    let cli = setup();
    let user = make_user(&cli, "test", "test@example.com", "12345").await;
    let auth = login(&cli, user.id, "12345").await;
    (cli, user, auth)
}

#[tokio::test]
/// FIXME non exhaustive
async fn post_user() {
    let cli = setup();
    let resp = make_user(&cli, "test", "test@example.com", "12345").await;

    // TODO questionable
    let mut id_gen = Snowflake::default();
    assert_ge!(id_gen.generate(), resp.id);

    assert_eq!(resp.email, "test@example.com");
    assert_eq!(resp.username, "test");
}

#[tokio::test]
async fn post_login() {
    let cli = setup();
    let user = make_user(&cli, "test", "test@example.com", "12345").await;
    let hash = hash_pass("12345");

    let resp = cli.post(format!("/api/login?id={}", user.id))
		.content_type("text/plain").body("abc").send().await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    let resp = cli.post("/api/login?id=12")
		.content_type("text/plain").body(hash.clone()).send().await;
    resp.assert_status(StatusCode::NOT_FOUND);

    let resp = cli.post(format!("/api/login?id={}", user.id))
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
    let resp = cli.get(format!("/api/user?id={}", user.id)).send().await;
    resp.assert_status_is_ok();
    let ret_user = resp.json().await.value().deserialize::<User>();
    assert_eq!(user, ret_user);
}

#[tokio::test]
async fn put_user() {
    let (cli, user, auth) = setup_user_auth().await;

    let resp = cli.put("/api/user?name=fred&email=whoo@whee.com").send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
    let resp = cli
        .put("/api/user?name=fred&email=whoo@whee.com")
        .header::<&str, String>("ScuttleKey", auth)
        .send()
        .await;
    resp.assert_status_is_ok();
    let ret_user = resp.json().await.value().deserialize::<User>();
    assert_eq!(ret_user.email, "whoo@whee.com");
    assert_eq!(ret_user.username, "fred");
    // User should retain their underlying ID
    assert_eq!(user.id, ret_user.id);
}

#[tokio::test]
async fn del_user() {
    let (cli, user, auth) = setup_user_auth().await;

    let resp = cli.delete(format!("/api/user?id={}", user.id)).send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    let resp = cli
        .delete(format!("/api/user?id={}", user.id))
        .header::<&str, String>("ScuttleKey", auth)
        .send()
        .await;
    resp.assert_status_is_ok();
    let resp = cli.get(format!("/api/user?id={}", user.id)).send().await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

async fn make_group(cli: &FakeClient, auth: String, name: &str) -> Group {
    let resp = cli
        .post(format!("/api/group?name={}", name))
        .header::<&str, String>("ScuttleKey", auth)
        .send()
        .await;
    resp.assert_status_is_ok();
    resp.json().await.value().deserialize::<Group>()
}

async fn make_channel(cli: &FakeClient, auth: String, gid: i64, name: &str) -> Channel {
    let resp = cli
        .post(format!("/api/group/channels?gid={}&name={}", gid, name))
        .header::<&str, String>("ScuttleKey", auth)
        .send()
        .await;
    resp.assert_status_is_ok();
    resp.json().await.value().deserialize::<Channel>()
}

async fn find_channel(cli: &FakeClient, auth: String, id: i64) -> Channel {
    let resp = cli
        .get(format!("/api/channel?id={}", id))
        .header::<&str, String>("ScuttleKey", auth)
        .send()
        .await;
    resp.assert_status_is_ok();
    resp.json().await.value().deserialize::<Channel>()
}

async fn find_group(cli: &FakeClient, auth: String, id: i64) -> Group {
    let resp = cli
        .get(format!("/api/group?id={}", id))
        .header::<&str, String>("ScuttleKey", auth)
        .send()
        .await;
    resp.assert_status_is_ok();
    resp.json().await.value().deserialize::<Group>()
}

#[tokio::test]
async fn post_group() {
    let (cli, user, auth) = setup_user_auth().await;	
    let resp = cli.post("/api/group?name=")
        .header::<&str, String>("ScuttleKey", auth.clone()).send().await;
    resp.assert_status(StatusCode::BAD_REQUEST);	
	
    let resp = cli
        .post("/api/group?name=test")
        .header::<&str, String>("ScuttleKey", auth.clone())
        .send()
        .await;
    resp.assert_status_is_ok();
    let group = resp.json().await.value().deserialize::<Group>();
    assert_eq!(group.name, "test");
    assert_eq!(group.members, vec![user.id]);
    assert_eq!(group.channels.len(), 1);
    assert_eq!(
        find_channel(&cli, auth, group.channels[0]).await.name,
        String::from("main")
    );
}

#[tokio::test]
async fn put_group() {
    let (cli, user, auth) = setup_user_auth().await;
    let group = make_group(&cli, auth.clone(), "test").await;

    let resp = cli.put(format!("/api/group?id={}&name=test2", group.id)).send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    let resp = cli
        .put(format!("/api/group?id={}&name=", group.id))
        .header::<&str, String>("ScuttleKey", auth.clone())
        .send()
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    let resp = cli
        .put("/api/group?id=12&name=test2")
        .header::<&str, String>("ScuttleKey", auth.clone())
        .send()
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);

    let resp = cli
        .put(format!("/api/group?id={}&name=test2", group.id))
        .header::<&str, String>("ScuttleKey", auth)
        .send()
        .await;
    resp.assert_status_is_ok();
}

#[tokio::test]
async fn del_group() {
    let (cli, user, auth) = setup_user_auth().await;
    let group = make_group(&cli, auth.clone(), "test").await;

    let resp = cli.delete(format!("/api/group?id={}", group.id)).send().await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    let resp = cli
        .delete("/api/group?id=12")
        .header::<&str, String>("ScuttleKey", auth.clone())
        .send()
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);

    let resp = cli
        .delete(format!("/api/group?id={}", group.id))
        .header::<&str, String>("ScuttleKey", auth.clone())
        .send()
        .await;
    resp.assert_status_is_ok();

    let resp = cli
        .get(format!("/api/group?id={}", group.id))
        .header::<&str, String>("ScuttleKey", auth)
        .send()
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_group_members() {
    let (cli, user, auth) = setup_user_auth().await;
    let group = make_group(&cli, auth.clone(), "test").await;
    let user2 = make_user(&cli, "testeroo", "test2@example.com", "123456").await;
    let user3 = make_user(&cli, "testeroo", "test2@example.com", "123456").await;

    let resp = cli
        .put(format!("/api/group/members?gid={}&uid={}", group.id, user2.id))
        .send()
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    let resp = cli
        .put("/api/group/members?gid=12&uid=32")
        .header::<&str, String>("ScuttleKey", auth.clone())
        .send()
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);

    let resp = cli
        .put(format!("/api/group/members?gid={}&uid={}", group.id, user2.id))
        .header::<&str, String>("ScuttleKey", auth.clone())
        .send()
        .await;
    resp.assert_status_is_ok();
    let resp = cli
        .put(format!("/api/group/members?gid={}&uid={}", group.id, user3.id))
        .header::<&str, String>("ScuttleKey", auth.clone())
        .send()
        .await;
    resp.assert_status_is_ok();

    let new_group = find_group(&cli, auth, group.id).await;
    assert_eq!(new_group.members, vec![user.id, user2.id, user3.id]);
}

#[tokio::test]
async fn post_group_channels() {
    let (cli, user, auth) = setup_user_auth().await;
    let group = make_group(&cli, auth.clone(), "test").await;

    let resp = cli
        .post(format!("/api/group/channels?gid={}&name=test", group.id))
        .send()
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    let resp = cli
        .post(format!("/api/group/channels?gid={}&name=", group.id))
        .header::<&str, String>("ScuttleKey", auth.clone())
        .send()
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    let resp = cli
        .post("/api/group/channels?gid=12&name=test")
        .header::<&str, String>("ScuttleKey", auth.clone())
        .send()
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);

    let resp = cli
        .post(format!("/api/group/channels?gid={}&name=test", group.id))
        .header::<&str, String>("ScuttleKey", auth.clone())
        .send()
        .await;
    resp.assert_status_is_ok();
    let channel = resp.json().await.value().deserialize::<Channel>();
    assert_eq!(channel.name, "test");
    assert_eq!(channel.members, vec![user.id]);
    assert!(find_group(&cli, auth, group.id).await.channels.contains(&channel.id));
}
#[test]
/// Test if gen_id() gives unique IDs on successive calls
/// and if it can be called from multiple threads without error
fn test_id_gen() {
    let a = gen_id();
    let b = gen_id();
    assert_ge!(b, a);
    let threads: Vec<_> = (0..100).map(|i| std::thread::spawn(move || gen_id())).collect();
    for handle in threads {
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn get_channel() {
    let (cli, user, auth) = setup_user_auth().await;
    let group = make_group(&cli, auth.clone(), "test").await;
    let chan = make_channel(&cli, auth.clone(), group.id, "random").await;
    let resp = cli
        .get(format!("/api/channel?id={}", chan.id))
        .header::<&str, String>("ScuttleKey", auth)
        .send()
        .await;
    resp.assert_status_is_ok();
    let recv_chan = resp.json().await.value().deserialize::<Channel>();
    assert_eq!(chan, recv_chan);
}

// FIXME non exhaustive
#[tokio::test]
async fn get_channels() {
    let (cli, user, auth) = setup_user_auth().await;
    let group = make_group(&cli, auth.clone(), "test").await;
    let chan1 = make_channel(&cli, auth.clone(), group.id, "random").await;
    let chan2 = make_channel(&cli, auth.clone(), group.id, "random").await;
    let chan3 = make_channel(&cli, auth.clone(), group.id, "random").await;
    let resp = cli
        .get(format!("/api/group/channels?gid={}", group.id))
        .header::<&str, String>("ScuttleKey", auth.clone())
        .send()
        .await;
    resp.assert_status_is_ok();
    let channels = resp.json().await.value().deserialize::<Vec<Channel>>();
    assert_eq!(
        channels,
        vec![find_channel(&cli, auth, group.channels[0]).await, chan1, chan2, chan3]
    );
}

// #[tokio::test]
// async fn get_group_members() {
// 	let (cli, user, auth) = setup_user_auth().await;
// 	let group = make_group(&cli, auth.clone(), "test").await;
// }
