use std::{collections::HashMap, error::Error, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::anyhow;
use async_trait::async_trait;
use auth_for_warp::{
    build_api_route_filter, handle_auth_errors, with_auth, Auth, AuthConfig, HashedPassword,
    UserDatabase, UserID, Username,
};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;
use warp::{path, Filter};

struct TestDB {
    storage: HashMap<String, (UserID, HashedPassword)>,
}

#[async_trait]
impl UserDatabase for TestDB {
    async fn create_user_if_not_exists(
        &mut self,
        user_id: &UserID,
        username: &Username,
        hashed_password: &HashedPassword,
    ) -> Result<UserID, Box<dyn Error + Send + Sync>> {
        if self.storage.contains_key(&username.0) {
            Ok(self.storage[&username.0.clone()].0.clone())
        } else {
            self.storage.insert(
                username.0.clone(),
                (user_id.clone(), hashed_password.clone()),
            );
            Ok(user_id.clone())
        }
    }

    async fn retreive_user(
        &self,
        username: &Username,
    ) -> Result<(UserID, HashedPassword), Box<dyn Error + Send + Sync>> {
        let result = self
            .storage
            .get(&username.0)
            .ok_or_else(|| anyhow!("user not found"))
            .cloned()?;

        Ok(result)
    }
}

async fn start_server() {
    let database_connection = Arc::new(Mutex::new(TestDB {
        storage: HashMap::new(),
    }));

    let config = AuthConfig {
        password_salt: "this is a terrible salt".into(),
        auth_token_issuer: "insert app or organisation name here".into(),
        auth_token_secret: "this is a really bad secret".into(),
        auth_token_lifetime: Duration::from_secs(60 * 60),
        database_connection,
    };

    let auth = Auth::new(config);

    let auth_routes = build_api_route_filter(&auth);

    let unsecured_page =
        path!("insecure").then(|| async move { warp::reply::html("hello, world!") });

    let secure_page = path!("secure")
        .and(with_auth(&auth))
        .then(|user_id| async move { warp::reply::json(&json!({ "user id": user_id })) });

    let all_routes = unsecured_page
        .or(secure_page)
        .or(auth_routes)
        .recover(handle_auth_errors);

    warp::serve(all_routes)
        .run("127.0.0.1:4123".parse::<SocketAddr>().unwrap())
        .await;
}

#[derive(Deserialize)]
struct LoginResponse {
    token: String,
}

#[tokio::test]
async fn integration() {
    let _server = tokio::spawn(start_server());

    let client = reqwest::Client::new();

    assert_eq!(
        client
            .post("http://127.0.0.1:4123/users/register")
            .body(json!({"username": "Sam I Am", "password": "foobar"}).to_string())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
        "failed to register user"
    );

    assert_eq!(
        client
            .post("http://127.0.0.1:4123/users/register")
            .body(json!({"username": "Sam I Am", "password": "fizzbuzz"}).to_string())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT,
        "attempt to register user with the same name should have been denied"
    );

    assert_eq!(
        client
            .post("http://127.0.0.1:4123/users/login")
            .body(json!({"username": "Sam I Am", "password": "hunter1"}).to_string())
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN,
        "attempt to login with an invalid password should have been denied"
    );

    let login_response = client
        .post("http://127.0.0.1:4123/users/login")
        .body(json!({"username": "Sam I Am", "password": "foobar"}).to_string())
        .send()
        .await
        .unwrap();

    assert_eq!(
        login_response.status(),
        StatusCode::OK,
        "failed to login as user"
    );

    let auth_token = login_response.json::<LoginResponse>().await.unwrap().token;

    assert_eq!(
        client
            .post("http://127.0.0.1:4123/insecure")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
        "failed to fetch insecure page"
    );

    assert_eq!(
        client
            .post("http://127.0.0.1:4123/secure")
            .bearer_auth("fake token")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN,
        "access to secure page with a bad auth token should have been denied"
    );

    assert_eq!(
        client
            .post("http://127.0.0.1:4123/secure")
            .bearer_auth(auth_token)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK,
        "failed to access secure page with a valid auth token"
    );
}
