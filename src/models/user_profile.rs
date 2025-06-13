use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserProfile {
    pub id: Option<Thing>,
    pub user_id: Thing,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub phone: Option<String>,
    pub date_of_birth: Option<DateTime<Utc>>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserProfileRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub date_of_birth: Option<DateTime<Utc>>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateUserProfileRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub phone: Option<String>,
    pub date_of_birth: Option<DateTime<Utc>>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfileResponse {
    pub id: String,
    pub user_id: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub phone: Option<String>,
    pub date_of_birth: Option<DateTime<Utc>>,
    pub timezone: Option<String>,
    pub locale: Option<String>,
    pub bio: Option<String>,
    pub website: Option<String>,
    pub location: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<UserProfile> for UserProfileResponse {
    fn from(profile: UserProfile) -> Self {
        Self {
            id: profile.id
                .map(|id| id.id.to_string())
                .unwrap_or_default(),
            user_id: profile.user_id.id.to_string(),
            first_name: profile.first_name,
            last_name: profile.last_name,
            display_name: profile.display_name,
            avatar_url: profile.avatar_url,
            phone: profile.phone,
            date_of_birth: profile.date_of_birth,
            timezone: profile.timezone,
            locale: profile.locale,
            bio: profile.bio,
            website: profile.website,
            location: profile.location,
            created_at: profile.created_at,
            updated_at: profile.updated_at,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AvatarUploadResponse {
    pub avatar_url: String,
    pub message: String,
}