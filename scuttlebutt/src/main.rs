use poem::{listener::TcpListener, Route, Server, Result };
use poem_openapi::{param::Query, payload::{PlainText, Json}, OpenApi, OpenApiService, Object, ApiResponse};

struct Api;

#[derive(Object)]
struct User {
    id: u64,
    username: String,
}

#[derive(ApiResponse)]
enum UserResponse {
	/// Returns the user requested
	#[oai(status = 200)]
	User(Json<User>),
	/// Returns when there is no user associated with the ID
	#[oai(status = 404)]
	NotFound(PlainText<String>)
}

#[OpenApi]
impl Api {
	#[oai(path = "/hello", method = "get")]	
    async fn hi(&self) -> PlainText<String> {
        PlainText(String::from("whee"))
    }
	
    #[oai(path = "/user", method = "get")]
	/// Gets the user with the given ID
    ///
    /// # Example
    /// 
    /// Call `/user/1234` to get the user with id 1234
    async fn get_user(&self, id: Query<u64>) -> UserResponse {
        todo!()
    }

	#[oai(path = "/user", method = "post")]
	/// Makes a user
    async fn make_user(&self, name: Query<String>, email: Query<String>, password: Query<String>) -> Result<Json<User>> {
        todo!()
    }
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "poem=debug");
    }
    tracing_subscriber::fmt::init();

    let api_service =
        OpenApiService::new(Api, "Hello World", "1.0").server("http://localhost:3000/api");
    let ui = api_service.swagger_ui();

    Server::new(TcpListener::bind("127.0.0.1:3000"))
        .run(Route::new().nest("/api", api_service).nest("/", ui))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
	use poem::test::TestClient;
	
	fn setup() -> TestClient<Route> {
		let app = OpenApiService::new(Api, "Hello World", "1.0").server("http://localhost:3000/api");
		TestClient::new(Route::new().nest("/api", app))
	}

	#[tokio::test]
	async fn sanity() {
		let cli = setup();
		let resp = cli.get("/api/hello").send().await;
		resp.assert_status_is_ok();
		resp.assert_text("whee").await;		
	}
}
