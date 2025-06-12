use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Role {
    pub id: Option<Thing>,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub is_system: bool, // 系统角色不可删除
    #[serde(with = "chrono::serde::ts_seconds")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateRoleRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub permissions: Vec<String>, // 权限名称列表
}

impl From<Role> for RoleResponse {
    fn from(role: Role) -> Self {
        Self {
            id: role.id.unwrap().id.to_string(),
            name: role.name,
            display_name: role.display_name,
            description: role.description,
            is_system: role.is_system,
            created_at: role.created_at,
            updated_at: role.updated_at,
            permissions: vec![], // 需要单独查询填充
        }
    }
}