use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[repr(transparent)]
pub struct UserID(pub String);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[repr(transparent)]
pub struct Username(pub String);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[repr(transparent)]
pub struct HashedPassword(pub String);

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Claims {
    pub(crate) exp: u64,
    pub(crate) iss: String,
    pub(crate) sub: String,
}
