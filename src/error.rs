use warp::reject::Reject;

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("an account with that username already exists")]
    UsernameAlreadyTaken,
    #[error("username or password incorrect")]
    LoginFailed,
    #[error("error during database operation")]
    DatabaseError {
        #[from]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("error with token")]
    TokenError {
        #[from]
        source: Option<jsonwebtoken::errors::Error>,
    },
}

impl Reject for AuthError {}
