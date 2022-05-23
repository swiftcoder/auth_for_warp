use std::{collections::HashMap, error::Error, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::anyhow;
use async_trait::async_trait;
use auth_for_warp::{
    build_api_route_filter, handle_auth_errors, with_auth, Auth, AuthConfig, HashedPassword,
    UserDatabase, UserID, Username,
};
use serde_json::json;
use tokio::sync::Mutex;
use warp::{path, Filter};

#[tokio::main]
async fn main() {
    let database_connection = Arc::new(Mutex::new(SimpleInMemoryDb::new()));

    let config = AuthConfig {
        password_salt: "this is a terrible salt".into(),
        auth_token_issuer: "insert app or organisation name here".into(),
        auth_token_secret: "this is a really bad secret".into(),
        auth_token_lifetime: Duration::from_secs(60 * 60),
        database_connection,
    };

    let auth = Auth::new(config);

    let auth_routes = build_api_route_filter(&auth);

    let unsecured_homepage =
        warp::path::end().then(|| async move { warp::reply::html("hello, world!") });

    let secure_page = path!("check_user_id")
        .and(with_auth(&auth))
        .then(|user_id| async move { warp::reply::json(&json!({ "user id": user_id })) });

    let all_routes = unsecured_homepage
        .or(secure_page)
        .or(auth_routes)
        .recover(handle_auth_errors);

    warp::serve(all_routes)
        .run("127.0.0.1:4000".parse::<SocketAddr>().unwrap())
        .await;
}

struct SimpleInMemoryDb {
    storage: HashMap<String, (UserID, HashedPassword)>,
}

impl SimpleInMemoryDb {
    pub fn new() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }
}

#[async_trait]
impl UserDatabase for SimpleInMemoryDb {
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
            .ok_or(anyhow!("user not found"))
            .cloned()?;

        Ok(result)
    }
}
