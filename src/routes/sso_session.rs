use std::sync::Arc;
use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    response::Json,
    routing::{get, post, delete},
    Router,
};
use serde::{Deserialize, Serialize};

use crate::{
    models::sso_session::{CreateSsoSessionRequest, SsoSessionResponse},
    services::sso_session_management::{SsoSessionService, SessionStats, UserSessionStats},
    error::AuthError,
};

pub fn sso_session_routes() -> Router {
    Router::new()
        .route("/sessions", post(create_session))
        .route("/sessions/:session_id", get(get_session))
        .route("/sessions/:session_id", delete(logout_session))
        .route("/sessions/:session_id/clients/:client_id", post(add_client_session))
        .route("/sessions/:session_id/clients/:client_id", delete(remove_client_session))
        .route("/sessions/:session_id/extend", post(extend_session))
        .route("/users/:user_id/sessions", get(get_user_sessions))
        .route("/users/:user_id/sessions", delete(logout_user_all_sessions))
        .route("/users/:user_id/sessions/stats", get(get_user_session_stats))
        .route("/sessions/stats", get(get_session_stats))
        .route("/sessions/cleanup", post(cleanup_expired_sessions))
}

#[derive(Deserialize)]
struct ExtendSessionRequest {
    extend_seconds: i64,
}

#[derive(Serialize)]
struct LogoutResponse {
    message: String,
    sessions_terminated: i32,
}

#[derive(Serialize)]
struct CleanupResponse {
    message: String,
    sessions_cleaned: i32,
}

// 创建 SSO 会话
async fn create_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Json(request): Json<CreateSsoSessionRequest>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    match session_service.create_session(request).await {
        Ok(session) => Ok(Json(session)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 获取 SSO 会话
async fn get_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Path(session_id): Path<String>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    match session_service.get_session(&session_id).await {
        Ok(session) => {
            let response = SsoSessionResponse {
                session_id: session.session_id,
                user_id: session.user_id,
                client_sessions: session.client_sessions,
                created_at: session.created_at,
                last_accessed_at: session.last_accessed_at,
                expires_at: session.expires_at,
                is_active: !session.is_expired(),
            };
            Ok(Json(response))
        }
        Err(_) => Err(AuthError::NotFound("Session not found".to_string())),
    }
}

// 添加客户端会话
async fn add_client_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Path((session_id, client_id)): Path<(String, String)>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    match session_service.add_client_session(&session_id, &client_id).await {
        Ok(session) => Ok(Json(session)),
        Err(e) => Err(AuthError::BadRequest(e.to_string())),
    }
}

// 移除客户端会话（单点登出）
async fn remove_client_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Path((session_id, client_id)): Path<(String, String)>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    match session_service.remove_client_session(&session_id, &client_id).await {
        Ok(session) => Ok(Json(session)),
        Err(e) => Err(AuthError::BadRequest(e.to_string())),
    }
}

// 延长会话
async fn extend_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Path(session_id): Path<String>,
    Json(request): Json<ExtendSessionRequest>,
) -> Result<Json<SsoSessionResponse>, AuthError> {
    if request.extend_seconds <= 0 || request.extend_seconds > 86400 * 7 { // 最多延长7天
        return Err(AuthError::BadRequest("Invalid extend duration".to_string()));
    }

    match session_service.extend_session(&session_id, request.extend_seconds).await {
        Ok(session) => Ok(Json(session)),
        Err(e) => Err(AuthError::BadRequest(e.to_string())),
    }
}

// 获取用户的所有会话
async fn get_user_sessions(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<SsoSessionResponse>>, AuthError> {
    match session_service.get_user_sessions(&user_id).await {
        Ok(sessions) => Ok(Json(sessions)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 终止用户的所有会话
async fn logout_user_all_sessions(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Path(user_id): Path<String>,
) -> Result<Json<LogoutResponse>, AuthError> {
    match session_service.logout_user_all_sessions(&user_id).await {
        Ok(count) => {
            let response = LogoutResponse {
                message: "All user sessions have been terminated".to_string(),
                sessions_terminated: count,
            };
            Ok(Json(response))
        }
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 终止特定会话
async fn logout_session(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Path(session_id): Path<String>,
) -> Result<StatusCode, AuthError> {
    match session_service.logout_session(&session_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(_) => Err(AuthError::NotFound("Session not found".to_string())),
    }
}

// 获取用户会话统计
async fn get_user_session_stats(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
    Path(user_id): Path<String>,
) -> Result<Json<UserSessionStats>, AuthError> {
    match session_service.get_user_session_stats(&user_id).await {
        Ok(stats) => Ok(Json(stats)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 获取全局会话统计
async fn get_session_stats(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
) -> Result<Json<SessionStats>, AuthError> {
    match session_service.get_session_stats().await {
        Ok(stats) => Ok(Json(stats)),
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}

// 清理过期会话
async fn cleanup_expired_sessions(
    Extension(session_service): Extension<Arc<SsoSessionService>>,
) -> Result<Json<CleanupResponse>, AuthError> {
    match session_service.cleanup_expired_sessions().await {
        Ok(count) => {
            let response = CleanupResponse {
                message: "Expired sessions have been cleaned up".to_string(),
                sessions_cleaned: count,
            };
            Ok(Json(response))
        }
        Err(e) => Err(AuthError::InternalServerError(e.to_string())),
    }
}