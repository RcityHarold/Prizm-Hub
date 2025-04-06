use crate::{
    config::Config,
    error::{AuthError, Result},
    models::user::{CreateUserRequest, LoginRequest, AuthResponse, UserResponse},
    services::auth::AuthService,
    utils::jwt::Claims,
};
use axum::{
    extract::{Query, State},
    routing::{get, post},
    Json, Router,
    Extension,
};
use serde::Deserialize;
use std::sync::Arc;
use crate::services::database::Database;
use tracing::error;

#[derive(Debug, Deserialize)]
pub struct OAuthCallback {
    code: String,
    state: Option<String>,
}

pub fn router(db: Arc<Database>) -> Router {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/verify-email/:token", get(verify_email))
        .route("/me", get(get_current_user))
        // OAuth 路由
        .route("/login/google", get(google_login))
        .route("/callback/google", get(google_callback))
        .route("/login/github", get(github_login))
        .route("/callback/github", get(github_callback))
        .with_state(db)
}

// 注册处理函数
async fn register(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<AuthResponse>> {
    error!("Starting registration with email: {}", req.email);
    let auth_service = AuthService::new(db, config)?;
    let result = auth_service.register(req).await;
    if let Err(ref e) = result {
        error!("Registration failed: {:?}", e);
    }
    result.map(Json)
}

// 登录处理函数
async fn login(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>> {
    let auth_service = AuthService::new(db, config)?;
    let response = auth_service.login(req.email, req.password).await?;
    Ok(Json(response))
}

// 邮箱验证处理函数
async fn verify_email(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.verify_email(token).await?;
    Ok("Email verified successfully")
}

// 获取当前用户信息
async fn get_current_user(
    claims: Claims,
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<Json<UserResponse>> {
    let auth_service = AuthService::new(db, config)?;
    let user = auth_service
        .get_user_by_id(&claims.sub)
        .await?
        .ok_or(AuthError::UserNotFound)?;

    Ok(Json(UserResponse {
        id: claims.sub,
        email: user.email,
        email_verified: user.email_verified,
        created_at: user.created_at,
    }))
}

// Google 登录
async fn google_login(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<axum::response::Redirect> {
    let auth_service = AuthService::new(db, config)?;
    let auth_url = auth_service.get_google_auth_url()?;
    Ok(axum::response::Redirect::to(&auth_url))
}

// Google 回调处理
async fn google_callback(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Query(params): Query<OAuthCallback>,
) -> Result<axum::response::Redirect> {
    let auth_service = AuthService::new(db, config)?;
    let auth_response = auth_service.handle_google_callback(params.code).await?;
    
    // 在实际应用中，你可能想要将用户重定向到前端应用，并将令牌作为URL参数传递
    let redirect_url = format!("/login/success?token={}", auth_response.token);
    Ok(axum::response::Redirect::to(&redirect_url))
}

// GitHub 登录
async fn github_login(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
) -> Result<axum::response::Redirect> {
    let auth_service = AuthService::new(db, config)?;
    let auth_url = auth_service.get_github_auth_url()?;
    Ok(axum::response::Redirect::to(&auth_url))
}

// GitHub 回调处理
async fn github_callback(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Query(params): Query<OAuthCallback>,
) -> Result<axum::response::Redirect> {
    let auth_service = AuthService::new(db, config)?;
    let auth_response = auth_service.handle_github_callback(params.code).await?;
    
    // 在实际应用中，你可能想要将用户重定向到前端应用，并将令牌作为URL参数传递
    let redirect_url = format!("/login/success?token={}", auth_response.token);
    Ok(axum::response::Redirect::to(&redirect_url))
}

// 错误处理中间件
impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            AuthError::DatabaseError(_) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
            ),
            AuthError::InvalidCredentials => (
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid credentials",
            ),
            AuthError::EmailNotVerified => (
                axum::http::StatusCode::FORBIDDEN,
                "Email not verified",
            ),
            AuthError::TokenError(_) => (
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid token",
            ),
            AuthError::UserNotFound => (
                axum::http::StatusCode::NOT_FOUND,
                "User not found",
            ),
            AuthError::EmailExists => (
                axum::http::StatusCode::CONFLICT,
                "Email already exists",
            ),
            AuthError::InvalidToken => (
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid token",
            ),
            AuthError::ServerError(_) => (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
            ),
            AuthError::OAuthError(_) => (
                axum::http::StatusCode::BAD_REQUEST,
                "OAuth error",
            ),
        };

        let body = Json(serde_json::json!({
            "error": message
        }));

        (status, body).into_response()
    }
}
