use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: Option<Thing>, 
    pub email: String,
    #[serde(rename = "password")]
    pub password_hash: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
    #[serde(rename = "verified")]
    pub is_email_verified: bool,
    pub verification_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    #[serde(rename = "verified")]
    pub is_email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub has_password: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitializePasswordRequest {
    pub password: String,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id.unwrap().id.to_string(),
            email: user.email,
            is_email_verified: user.is_email_verified,
            created_at: user.created_at,
            has_password: user.password_hash.is_some(),
        }
    }
}
