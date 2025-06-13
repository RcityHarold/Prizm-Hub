use axum::{
    extract::{Path, Query},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Extension, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};

use crate::{
    error::AuthError,
    models::{
        user::User,
        role::{CreateRoleRequest, UpdateRoleRequest, RoleResponse},
        permission::{CreatePermissionRequest, PermissionResponse},
        user_role::{
            AssignRoleRequest, RemoveRoleRequest, 
            AssignPermissionToRoleRequest, RemovePermissionFromRoleRequest,
            UserRoleResponse,
        },
    },
    services::{database::Database, rbac::RBACService},
    require_permission_status,
};

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub message: String,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T, message: &str) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: message.to_string(),
        }
    }

    pub fn success_message(message: &str) -> ApiResponse<()> {
        ApiResponse {
            success: true,
            data: None,
            message: message.to_string(),
        }
    }

    pub fn error(message: &str) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            message: message.to_string(),
        }
    }
}

pub fn router() -> Router {
    Router::new()
        // 角色管理路由
        .route("/roles", get(list_roles).post(create_role))
        .route("/roles/:role_name", get(get_role).post(update_role))
        .route("/roles/:role_name/permissions", get(get_role_permissions))
        .route("/roles/:role_name/permissions/assign", post(assign_permission_to_role))
        .route("/roles/:role_name/permissions/remove", post(remove_permission_from_role))

        // 权限管理路由
        .route("/permissions", get(list_permissions).post(create_permission))
        .route("/permissions/:permission_name", get(get_permission))

        // 用户角色分配路由
        .route("/users/:user_id/roles", get(get_user_roles))
        .route("/users/:user_id/roles/assign", post(assign_role_to_user))
        .route("/users/:user_id/roles/remove", post(remove_role_from_user))
        .route("/users/:user_id/permissions", get(get_user_permissions))

        // 权限检查路由
        .route("/check/permission/:permission_name", get(check_permission))
        .route("/check/role/:role_name", get(check_role))
}

// ===== 角色管理 =====

async fn create_role(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Json(request): Json<CreateRoleRequest>,
) -> Result<Json<ApiResponse<RoleResponse>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "roles.write");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.create_role(request, &current_user).await {
        Ok(role) => {
            info!("Role created successfully by user '{}'", current_user.email);
            Ok(Json(ApiResponse::success(role, "Role created successfully")))
        }
        Err(AuthError::ValidationError(msg)) => {
            error!("Role creation validation error: {}", msg);
            Err(StatusCode::BAD_REQUEST)
        }
        Err(e) => {
            error!("Failed to create role: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn list_roles(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<ApiResponse<Vec<RoleResponse>>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "roles.read");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.list_roles(pagination.page, pagination.limit).await {
        Ok(roles) => Ok(Json(ApiResponse::success(roles, "Roles retrieved successfully"))),
        Err(e) => {
            error!("Failed to list roles: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_role(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Path(role_name): Path<String>,
) -> Result<Json<ApiResponse<RoleResponse>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "roles.read");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.get_role_by_name(&role_name).await {
        Ok(Some(role)) => {
            let mut role_response: RoleResponse = role.into();
            // 获取角色权限
            if let Ok(permissions) = rbac_service.get_role_permissions(&role_name).await {
                role_response.permissions = permissions;
            }
            Ok(Json(ApiResponse::success(role_response, "Role retrieved successfully")))
        }
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get role: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn update_role(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Path(role_name): Path<String>,
    Json(request): Json<UpdateRoleRequest>,
) -> Result<Json<ApiResponse<RoleResponse>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "roles.write");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.update_role(&role_name, request, &current_user).await {
        Ok(role) => {
            info!("Role '{}' updated successfully by user '{}'", role_name, current_user.email);
            Ok(Json(ApiResponse::success(role, "Role updated successfully")))
        }
        Err(AuthError::NotFound(_)) => Err(StatusCode::NOT_FOUND),
        Err(AuthError::ValidationError(msg)) => {
            error!("Role update validation error: {}", msg);
            Err(StatusCode::BAD_REQUEST)
        }
        Err(e) => {
            error!("Failed to update role: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}


// ===== 权限管理 =====

async fn create_permission(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Json(request): Json<CreatePermissionRequest>,
) -> Result<Json<ApiResponse<PermissionResponse>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "permissions.write");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.create_permission(request, &current_user).await {
        Ok(permission) => {
            info!("Permission created successfully by user '{}'", current_user.email);
            Ok(Json(ApiResponse::success(permission, "Permission created successfully")))
        }
        Err(AuthError::ValidationError(msg)) => {
            error!("Permission creation validation error: {}", msg);
            Err(StatusCode::BAD_REQUEST)
        }
        Err(e) => {
            error!("Failed to create permission: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn list_permissions(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Json<ApiResponse<Vec<PermissionResponse>>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "permissions.read");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.list_permissions(pagination.page, pagination.limit).await {
        Ok(permissions) => Ok(Json(ApiResponse::success(permissions, "Permissions retrieved successfully"))),
        Err(e) => {
            error!("Failed to list permissions: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_permission(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Path(permission_name): Path<String>,
) -> Result<Json<ApiResponse<PermissionResponse>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "permissions.read");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.get_permission_by_name(&permission_name).await {
        Ok(Some(permission)) => Ok(Json(ApiResponse::success(permission.into(), "Permission retrieved successfully"))),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get permission: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ===== 角色权限分配 =====

async fn get_role_permissions(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Path(role_name): Path<String>,
) -> Result<Json<ApiResponse<Vec<String>>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "roles.read");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.get_role_permissions(&role_name).await {
        Ok(permissions) => Ok(Json(ApiResponse::success(permissions, "Role permissions retrieved successfully"))),
        Err(AuthError::NotFound(_)) => Err(StatusCode::NOT_FOUND),
        Err(e) => {
            error!("Failed to get role permissions: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn assign_permission_to_role(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Path(role_name): Path<String>,
    Json(request): Json<AssignPermissionToRoleRequest>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "permissions.write");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.assign_permission_to_role(&role_name, &request.permission_name, &current_user).await {
        Ok(_) => {
            info!("Permission '{}' assigned to role '{}' by user '{}'", 
                  request.permission_name, role_name, current_user.email);
            Ok(Json(ApiResponse::<()>::success_message("Permission assigned to role successfully")))
        }
        Err(AuthError::NotFound(msg)) => {
            error!("Assignment failed - not found: {}", msg);
            Err(StatusCode::NOT_FOUND)
        }
        Err(AuthError::ValidationError(msg)) => {
            error!("Assignment validation error: {}", msg);
            Err(StatusCode::BAD_REQUEST)
        }
        Err(e) => {
            error!("Failed to assign permission to role: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn remove_permission_from_role(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Path(role_name): Path<String>,
    Json(request): Json<RemovePermissionFromRoleRequest>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "permissions.write");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.remove_permission_from_role(&role_name, &request.permission_name, &current_user).await {
        Ok(_) => {
            info!("Permission '{}' removed from role '{}' by user '{}'", 
                  request.permission_name, role_name, current_user.email);
            Ok(Json(ApiResponse::<()>::success_message("Permission removed from role successfully")))
        }
        Err(AuthError::NotFound(msg)) => {
            error!("Removal failed - not found: {}", msg);
            Err(StatusCode::NOT_FOUND)
        }
        Err(e) => {
            error!("Failed to remove permission from role: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ===== 用户角色分配 =====

async fn get_user_roles(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Path(user_id): Path<String>,
) -> Result<Json<ApiResponse<UserRoleResponse>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "users.read");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.get_user_roles(&user_id).await {
        Ok(user_roles) => Ok(Json(ApiResponse::success(user_roles, "User roles retrieved successfully"))),
        Err(e) => {
            error!("Failed to get user roles: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn assign_role_to_user(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Path(user_id): Path<String>,
    Json(request): Json<AssignRoleRequest>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "roles.write");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.assign_role_to_user(&user_id, &request.role_name, &current_user).await {
        Ok(_) => {
            info!("Role '{}' assigned to user '{}' by user '{}'", 
                  request.role_name, user_id, current_user.email);
            Ok(Json(ApiResponse::<()>::success_message("Role assigned to user successfully")))
        }
        Err(AuthError::NotFound(msg)) => {
            error!("Assignment failed - not found: {}", msg);
            Err(StatusCode::NOT_FOUND)
        }
        Err(AuthError::ValidationError(msg)) => {
            error!("Assignment validation error: {}", msg);
            Err(StatusCode::BAD_REQUEST)
        }
        Err(e) => {
            error!("Failed to assign role to user: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn remove_role_from_user(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Path(user_id): Path<String>,
    Json(request): Json<RemoveRoleRequest>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "roles.write");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.remove_role_from_user(&user_id, &request.role_name, &current_user).await {
        Ok(_) => {
            info!("Role '{}' removed from user '{}' by user '{}'", 
                  request.role_name, user_id, current_user.email);
            Ok(Json(ApiResponse::<()>::success_message("Role removed from user successfully")))
        }
        Err(AuthError::NotFound(msg)) => {
            error!("Removal failed - not found: {}", msg);
            Err(StatusCode::NOT_FOUND)
        }
        Err(e) => {
            error!("Failed to remove role from user: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_user_permissions(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Path(user_id): Path<String>,
) -> Result<Json<ApiResponse<Vec<String>>>, StatusCode> {
    let user_id = current_user.id.as_ref()
        .ok_or_else(|| StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    require_permission_status!(db, &user_id, "users.read");

    let rbac_service = RBACService::new(db);
    
    match rbac_service.get_user_permissions(&user_id).await {
        Ok(permissions) => Ok(Json(ApiResponse::success(permissions, "User permissions retrieved successfully"))),
        Err(e) => {
            error!("Failed to get user permissions: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ===== 权限检查 =====

#[derive(Debug, Serialize)]
struct PermissionCheckResponse {
    has_permission: bool,
    user_id: String,
    permission: String,
}

#[derive(Debug, Serialize)]
struct RoleCheckResponse {
    has_role: bool,
    user_id: String,
    role: String,
}

async fn check_permission(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Path(permission_name): Path<String>,
) -> Result<Json<ApiResponse<PermissionCheckResponse>>, StatusCode> {
    let rbac_service = RBACService::new(db);
    let user_id = current_user.id.as_ref()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    
    match rbac_service.check_user_permission(&user_id, &permission_name).await {
        Ok(has_permission) => {
            let response = PermissionCheckResponse {
                has_permission,
                user_id: user_id.clone(),
                permission: permission_name,
            };
            Ok(Json(ApiResponse::success(response, "Permission checked successfully")))
        }
        Err(e) => {
            error!("Failed to check permission: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn check_role(
    Extension(db): Extension<Arc<Database>>,
    Extension(current_user): Extension<User>,
    Path(role_name): Path<String>,
) -> Result<Json<ApiResponse<RoleCheckResponse>>, StatusCode> {
    let rbac_service = RBACService::new(db);
    let user_id = current_user.id.as_ref()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
        .id.to_string();
    
    match rbac_service.check_user_role(&user_id, &role_name).await {
        Ok(has_role) => {
            let response = RoleCheckResponse {
                has_role,
                user_id: user_id.clone(),
                role: role_name,
            };
            Ok(Json(ApiResponse::success(response, "Role checked successfully")))
        }
        Err(e) => {
            error!("Failed to check role: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}