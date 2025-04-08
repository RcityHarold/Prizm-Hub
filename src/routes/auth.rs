use crate::{
    config::Config,
    error::{AuthError, Result},
    models::user::{CreateUserRequest, LoginRequest, AuthResponse, UserResponse, InitializePasswordRequest},
    services::auth::AuthService,
    utils::jwt::Claims,
};
use axum::{
    extract::{Query, State},
    routing::{get, post},
    Json, Router,
    Extension,
    response::IntoResponse,
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
        .route("/initialize-password", post(initialize_password))
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
    error!("Starting email verification with token: {}", token);
    let auth_service = AuthService::new(db, config)?;
    let result = auth_service.verify_email(token).await;
    if let Err(ref e) = result {
        error!("Email verification failed: {:?}", e);
    }
    result?;
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

    Ok(Json(UserResponse::from(user)))
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
) -> Result<axum::response::Response> {
    error!("Starting Google callback with code: {}", params.code);
    let auth_service = AuthService::new(db, config)?;
    let auth_response = match auth_service.handle_google_callback(params.code).await {
        Ok(response) => response,
        Err(e) => {
            error!("Google callback failed: {:?}", e);
            return Err(e);
        }
    };
    
    // 检查用户是否有密码
    let redirect_url = if !auth_response.user.has_password {
        // 重定向到设置密码页面，并传递 token
        format!("http://localhost:3000/initialize-password?token={}", auth_response.token)
    } else {
        // 正常重定向到前端，并传递 token
        format!("http://localhost:3000?token={}", auth_response.token)
    };

    error!("Redirecting to: {}", redirect_url);
    Ok(axum::response::Redirect::to(&redirect_url).into_response())
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
) -> Result<axum::response::Response> {
    let auth_service = AuthService::new(db, config)?;
    let auth_response = auth_service.handle_github_callback(params.code).await?;
    
    // 检查用户是否有密码
    let redirect_url = if !auth_response.user.has_password {
        // 重定向到设置密码页面，并传递 token
        format!("http://localhost:3000/initialize-password?token={}", auth_response.token)
    } else {
        // 正常重定向到前端，并传递 token
        format!("http://localhost:3000?token={}", auth_response.token)
    };

    Ok(axum::response::Redirect::to(&redirect_url).into_response())
}

// 初始化密码处理函数
async fn initialize_password(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
    Json(request): Json<InitializePasswordRequest>,
) -> Result<Json<UserResponse>> {
    let auth_service = AuthService::new(db, config)?;
    let user = auth_service.initialize_password(&claims.sub, &request.password).await?;
    Ok(Json(user.into()))
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
            AuthError::PasswordAlreadySet => (
                axum::http::StatusCode::CONFLICT,
                "Password already set",
            ),
            AuthError::InvalidUserId => (
                axum::http::StatusCode::BAD_REQUEST,
                "Invalid user ID",
            ),
        };

        let body = Json(serde_json::json!({
            "error": message
        }));

        (status, body).into_response()
    }
}
