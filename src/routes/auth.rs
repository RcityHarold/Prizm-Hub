use crate::{
    config::Config,
    error::{AuthError, Result},
    models::user::{CreateUserRequest, LoginRequest, AuthResponse, UserResponse, InitializePasswordRequest},
    models::password_reset::{RequestPasswordResetRequest, ResetPasswordRequest},
    models::session::{LogoutRequest, SessionInfo},
    services::auth::AuthService,
    utils::jwt::Claims,
};
use axum::{
    extract::{Query, State, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    routing::{get, post},
    Json, Router,
    Extension,
    response::IntoResponse,
};
use serde::Deserialize;
use std::sync::Arc;
use crate::services::database::Database;
use tracing::{error, info};

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
        .route("/request-password-reset", post(request_password_reset))
        .route("/reset-password", post(reset_password))
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/sessions", get(get_sessions))
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
) -> Result<&'static str> {
    tracing::info!("Starting user registration");
    let auth_service = AuthService::new(db, config)?;
    let result = auth_service.register(req).await;
    match result {
        Ok(auth_response) => {
            if auth_response.token.is_empty() {
                Ok("Registration successful. Please check your email to verify your account.")
            } else {
                Err(AuthError::ServerError("Unexpected response".to_string()))
            }
        },
        Err(e) => {
            error!("Registration failed: {:?}", e);
            Err(e)
        }
    }
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
) -> Result<Json<AuthResponse>> {
    tracing::info!("Starting email verification");
    let auth_service = AuthService::new(db, config)?;
    let result = auth_service.verify_email(token).await;
    match result {
        Ok(auth_response) => Ok(Json(auth_response)),
        Err(e) => {
            error!("Email verification failed: {:?}", e);
            Err(e)
        }
    }
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
    tracing::info!("Starting Google OAuth callback");
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

    tracing::info!("OAuth callback completed, redirecting user");
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

// 请求密码重置处理函数
async fn request_password_reset(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(request): Json<RequestPasswordResetRequest>,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.request_password_reset(request.email).await?;
    Ok("Password reset email sent if account exists")
}

// 重置密码处理函数
async fn reset_password(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    Json(request): Json<ResetPasswordRequest>,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.reset_password(request.token, request.new_password).await?;
    Ok("Password reset successfully")
}

// 登出处理函数
async fn logout(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    claims: Claims,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.logout(bearer.token().to_string()).await?;
    Ok("Logged out successfully")
}

// 登出所有会话处理函数
async fn logout_all(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    claims: Claims,
) -> Result<&'static str> {
    let auth_service = AuthService::new(db, config)?;
    auth_service.logout_all_sessions(&claims.sub).await?;
    Ok("All sessions logged out successfully")
}

// 获取用户会话列表处理函数
async fn get_sessions(
    State(db): State<Arc<Database>>,
    Extension(config): Extension<Config>,
    TypedHeader(Authorization(bearer)): TypedHeader<Authorization<Bearer>>,
    claims: Claims,
) -> Result<Json<Vec<SessionInfo>>> {
    let auth_service = AuthService::new(db, config)?;
    let sessions = auth_service.get_user_sessions(&claims.sub, bearer.token()).await?;
    Ok(Json(sessions))
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
