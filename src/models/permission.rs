use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Permission {
    pub id: Option<Thing>,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub resource: String, // 资源类型，如 "user", "role", "auth"
    pub action: String,   // 操作类型，如 "read", "write", "delete"
    pub is_system: bool,  // 系统权限不可删除
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePermissionRequest {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdatePermissionRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PermissionResponse {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Permission> for PermissionResponse {
    fn from(permission: Permission) -> Self {
        Self {
            id: permission.id.unwrap().id.to_string(),
            name: permission.name,
            display_name: permission.display_name,
            description: permission.description,
            resource: permission.resource,
            action: permission.action,
            is_system: permission.is_system,
            created_at: permission.created_at,
            updated_at: permission.updated_at,
        }
    }
}