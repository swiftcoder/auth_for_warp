use std::{convert::Infallible, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;
use uuid::Uuid;
use warp::{
    hyper::{Response, StatusCode},
    path, Filter, Rejection, Reply,
};

use crate::{
    auth::{Auth, AuthInternal},
    case_insensitive_string_ext::CaseInsensitiveStringExt,
    error::AuthError,
    types::{HashedPassword, UserID, Username},
};

pub fn build_api_route_filter(
    auth: &Auth,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let register = path!("users" / "register")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_auth_state(auth.internal.clone()))
        .and_then(user_register);

    let login = path!("users" / "login")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_auth_state(auth.internal.clone()))
        .and_then(user_login);

    register.or(login)
}

pub fn with_auth(auth: &Auth) -> impl Filter<Extract = (UserID,), Error = Rejection> + Clone {
    warp::header("authorization")
        .and(with_auth_state(auth.internal.clone()))
        .and_then(user_auth_check)
}

pub async fn handle_auth_errors(err: Rejection) -> Result<impl Reply, Rejection> {
    if let Some(auth_error) = err.find::<AuthError>() {
        let (status, message) = match &auth_error {
            AuthError::UsernameAlreadyTaken => {
                (StatusCode::CONFLICT, "a user with that name already exists")
            }
            AuthError::LoginFailed | AuthError::TokenError { .. } => {
                (StatusCode::FORBIDDEN, "access denied")
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "an unknown error has occurred",
            ),
        };
        return Ok(warp::reply::with_status(message, status));
    }

    Err(err)
}

#[derive(Debug, Deserialize)]
pub struct RegisterQuery {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {}

async fn user_register(
    input: RegisterQuery,
    auth: Arc<Mutex<AuthInternal>>,
) -> Result<impl Reply, Rejection> {
    let auth = auth.lock().await;

    let new_user_id = UserID(Uuid::new_v4().to_string());
    let username = Username(input.username);
    let hashed_password = HashedPassword(auth.hash(&input.password));

    let user_id = auth
        .create_user_if_not_exists(&new_user_id, &username, &hashed_password)
        .await?;

    if !user_id.0.eq(&new_user_id.0) {
        Err(AuthError::UsernameAlreadyTaken)?;
    }

    Ok(Response::builder().body(json!(RegisterResponse {}).to_string()))
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
}

async fn user_login(
    input: LoginQuery,
    auth: Arc<Mutex<AuthInternal>>,
) -> Result<impl Reply, Rejection> {
    let auth = auth.lock().await;

    let username = Username(input.username);

    let (user_id, hashed_password) = auth.retreive_user(&username).await?;

    if !auth.verify_hash(&input.password, &hashed_password) {
        Err(AuthError::LoginFailed)?;
    }

    let token = auth.generate_token(&user_id)?;

    Ok(Response::builder().body(json!(LoginResponse { token }).to_string()))
}

// Unwrap the bearer token and validate it
async fn user_auth_check(
    token: String,
    auth: Arc<Mutex<AuthInternal>>,
) -> Result<UserID, Rejection> {
    let token = token
        .strip_prefix_ignore_ascii_case("bearer ")
        .ok_or(AuthError::TokenError { source: None })?;

    let auth = auth.lock().await;

    let claims = auth.verify_token(token)?;

    Ok(UserID(claims.sub))
}

// functor that adds a reference to the internal auth state into the filter chain
fn with_auth_state(
    auth: Arc<Mutex<AuthInternal>>,
) -> impl Filter<Extract = (Arc<Mutex<AuthInternal>>,), Error = Infallible> + Clone {
    warp::any().map(move || auth.clone())
}
