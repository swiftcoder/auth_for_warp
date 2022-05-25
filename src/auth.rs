use std::{
    error::Error,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use tokio::sync::Mutex;

use crate::{
    error::AuthError,
    types::{Claims, HashedPassword, UserID, Username},
};

#[async_trait]
pub trait UserDatabase: Send + Sync + 'static {
    /// Create the specified user, and return the user id. If a user with the given username already exists,
    /// return the userid of that user instead.
    async fn create_user_if_not_exists(
        &mut self,
        userid: &UserID,
        username: &Username,
        hashed_password: &HashedPassword,
    ) -> Result<UserID, Box<dyn Error + Send + Sync>>;

    /// Retreive the user id and hashed password of the user with the specified username.
    async fn retreive_user(
        &self,
        username: &Username,
    ) -> Result<(UserID, HashedPassword), Box<dyn Error + Send + Sync>>;
}

#[derive(Clone)]
pub struct AuthConfig {
    /// The secret used to salt passwords stored in the database.
    /// If the salt changes, all previously-stored passwords can no longer be authenticated.
    pub password_salt: String,
    /// The issuer for auth tokens. We will validate that all auth tokens match the given issuer.
    pub auth_token_issuer: String,
    /// The secret used to encrypt JWT authorization tokens.
    /// If the secret changes, all currently authenticated sessions will be terminated.
    pub auth_token_secret: String,
    /// How long auth tokens should remain valid for. After this interval, the client will have to re-login.
    pub auth_token_lifetime: Duration,
    pub database_connection: Arc<Mutex<dyn UserDatabase>>,
}

#[derive(Clone)]
pub(crate) struct AuthInternal {
    config: AuthConfig,
}

impl AuthInternal {
    pub fn hash(&self, password: &str) -> String {
        argon2::hash_encoded(
            password.as_bytes(),
            self.config.password_salt.as_bytes(),
            &Default::default(),
        )
        .unwrap()
    }

    pub fn verify_hash(&self, password: &str, hash: &HashedPassword) -> bool {
        argon2::verify_encoded(&hash.0, password.as_bytes()).unwrap()
    }

    pub fn generate_token(&self, userid: &UserID) -> Result<String, AuthError> {
        let exp = SystemTime::now() + self.config.auth_token_lifetime;

        let claims = Claims {
            exp: exp.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            iss: self.config.auth_token_issuer.clone(),
            sub: userid.0.clone(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.auth_token_secret.as_ref()),
        )?;

        Ok(token)
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, AuthError> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.config.auth_token_issuer]);

        let token = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.auth_token_secret.as_ref()),
            &validation,
        )?;

        Ok(token.claims)
    }

    pub async fn create_user_if_not_exists(
        &self,
        user_id: &UserID,
        username: &Username,
        hashed_password: &HashedPassword,
    ) -> Result<UserID, AuthError> {
        let user_id = self
            .config
            .database_connection
            .lock()
            .await
            .create_user_if_not_exists(user_id, username, hashed_password)
            .await?;

        Ok(user_id)
    }

    pub async fn retreive_user(
        &self,
        username: &Username,
    ) -> Result<(UserID, HashedPassword), AuthError> {
        let (user_id, hashed_password) = self
            .config
            .database_connection
            .lock()
            .await
            .retreive_user(username)
            .await?;

        Ok((user_id, hashed_password))
    }
}

#[derive(Clone)]
pub struct Auth {
    pub(crate) internal: Arc<Mutex<AuthInternal>>,
}

impl Auth {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            internal: Arc::new(Mutex::new(AuthInternal { config })),
        }
    }
}
