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
}
