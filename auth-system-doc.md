# Rust 用户认证系统实现文档

## 目录

1. [概述](#概述)
2. [系统架构](#系统架构)
3. [技术栈选择](#技术栈选择)
4. [数据模型设计](#数据模型设计)
5. [核心功能实现](#核心功能实现)
   - [用户注册与登录](#用户注册与登录)
   - [第三方认证集成](#第三方认证集成)
   - [会话管理](#会话管理)
   - [权限控制](#权限控制)
6. [API 设计](#api-设计)
7. [安全考量](#安全考量)
8. [部署指南](#部署指南)
9. [测试策略](#测试策略)
10. [参考资源](#参考资源)

## 概述

本文档详细描述如何使用 Rust 语言实现一套完整的用户认证系统，该系统参考了 Supabase 的认证功能，包括电子邮件/密码认证和第三方登录（如谷歌、GitHub 等）。系统使用 SurrealDB 作为数据存储解决方案。

## 系统架构

认证系统将采用以下架构：

```
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   客户端应用   │◄───┤   认证 API    │◄───┤    SurrealDB  │
└───────────────┘    └───────────────┘    └───────────────┘
        ▲                    ▲
        │                    │
        │                    │
        │            ┌───────────────┐
        └───────────┤  第三方认证服务 │
                     └───────────────┘
```

- **客户端应用**：与用户交互的前端应用
- **认证 API**：使用 Rust 实现的 RESTful API 服务
- **SurrealDB**：存储用户数据、会话信息和认证记录
- **第三方认证服务**：与 Google、GitHub 等第三方服务集成

## 技术栈选择

- **后端框架**：Actix-web 或 Axum
- **数据库**：SurrealDB
- **认证库**：
  - JWT 处理：jsonwebtoken
  - 密码哈希：argon2
  - OAuth 实现：oauth2
- **辅助库**：
  - serde：序列化/反序列化
  - thiserror：错误处理
  - tracing：日志记录
  - config：配置管理

## 数据模型设计

### SurrealDB 数据模型

```surql
-- 用户表
DEFINE TABLE user SCHEMAFULL;
DEFINE FIELD email ON user TYPE string;
DEFINE FIELD password_hash ON user TYPE string;
DEFINE FIELD created_at ON user TYPE datetime;
DEFINE FIELD updated_at ON user TYPE datetime;
DEFINE FIELD email_verified ON user TYPE bool;
DEFINE FIELD verification_token ON user TYPE string;
DEFINE INDEX email_idx ON user COLUMNS email UNIQUE;

-- 第三方认证提供商
DEFINE TABLE identity_provider SCHEMAFULL;
DEFINE FIELD provider ON identity_provider TYPE string;
DEFINE FIELD provider_user_id ON identity_provider TYPE string;
DEFINE FIELD user_id ON identity_provider TYPE record(user);
DEFINE FIELD created_at ON identity_provider TYPE datetime;
DEFINE FIELD updated_at ON identity_provider TYPE datetime;
DEFINE INDEX provider_idx ON identity_provider COLUMNS provider, provider_user_id UNIQUE;

-- 会话表
DEFINE TABLE session SCHEMAFULL;
DEFINE FIELD user_id ON session TYPE record(user);
DEFINE FIELD token ON session TYPE string;
DEFINE FIELD expires_at ON session TYPE datetime;
DEFINE FIELD created_at ON session TYPE datetime;
DEFINE FIELD user_agent ON session TYPE string;
DEFINE FIELD ip_address ON session TYPE string;
DEFINE INDEX token_idx ON session COLUMNS token UNIQUE;
```

### Rust 数据模型

```rust
// src/models/user.rs
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Option<Thing>,
    pub email: String,
    pub password_hash: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub email_verified: bool,
    pub verification_token: Option<String>,
}

### 集成测试

```rust
// tests/integration_tests.rs
use actix_web::{test, web, App};
use auth_system::{
    config::Config,
    routes::auth_routes,
    models::requests::{SignupRequest, SigninRequest},
};

#[actix_web::test]
async fn test_auth_flow() {
    // 加载配置
    let config = Config::from_env().unwrap();
    
    // 创建测试数据库连接
    let db = setup_test_db(&config).await;
    
    // 创建测试应用
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(db.clone()))
            .configure(|cfg| auth_routes(cfg)),
    ).await;
    
    // 测试注册
    let signup_req = SignupRequest {
        email: "test_user@example.com".to_string(),
        password: "StrongP@ssw0rd".to_string(),
    };
    
    let signup_resp = test::TestRequest::post()
        .uri("/auth/signup")
        .set_json(&signup_req)
        .send_request(&app)
        .await;
    
    assert_eq!(signup_resp.status(), 201);
    
    // 获取验证令牌并模拟验证邮箱
    let user = get_user_by_email(&db, &signup_req.email).await.unwrap().unwrap();
    let token = user.verification_token.unwrap();
    verify_email(&db, token).await.unwrap();
    
    // 测试登录
    let signin_req = SigninRequest {
        email: signup_req.email,
        password: signup_req.password,
    };
    
    let signin_resp = test::TestRequest::post()
        .uri("/auth/signin")
        .set_json(&signin_req)
        .send_request(&app)
        .await;
    
    assert_eq!(signin_resp.status(), 200);
    
    let auth_resp: AuthResponse = test::read_body_json(signin_resp).await;
    
    // 测试获取当前用户信息
    let me_resp = test::TestRequest::get()
        .uri("/auth/me")
        .header("Authorization", format!("Bearer {}", auth_resp.token))
        .send_request(&app)
        .await;
    
    assert_eq!(me_resp.status(), 200);
    
    // 测试注销
    let signout_resp = test::TestRequest::post()
        .uri("/auth/signout")
        .header("Authorization", format!("Bearer {}", auth_resp.token))
        .send_request(&app)
        .await;
    
    assert_eq!(signout_resp.status(), 200);
    
    // 验证令牌已失效
    let me_resp_after_signout = test::TestRequest::get()
        .uri("/auth/me")
        .header("Authorization", format!("Bearer {}", auth_resp.token))
        .send_request(&app)
        .await;
    
    assert_eq!(me_resp_after_signout.status(), 401);
}
```

### 性能测试

```rust
// benches/auth_benchmarks.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use auth_system::{
    config::Config,
    auth::{signup, signin},
};
use tokio::runtime::Runtime;
use uuid::Uuid;

fn auth_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    // 加载配置
    let config = Config::from_env().unwrap();
    
    // 创建测试数据库连接
    let db = rt.block_on(async {
        setup_test_db(&config).await
    });
    
    // 预先创建一些测试用户
    let users = (0..100).map(|i| {
        let email = format!("bench_user_{}@example.com", i);
        let password = format!("StrongP@ssw0rd_{}", i);
        
        rt.block_on(async {
            let user = signup(&db, email.clone(), password.clone()).await.unwrap();
            let token = user.verification_token.unwrap();
            verify_email(&db, token).await.unwrap();
            
            (email, password)
        })
    }).collect::<Vec<_>>();
    
    // 基准测试：注册
    c.bench_function("signup", |b| {
        b.iter(|| {
            let random_id = Uuid::new_v4().to_string();
            let email = format!("bench_new_user_{}@example.com", random_id);
            let password = format!("StrongP@ssw0rd_{}", random_id);
            
            rt.block_on(async {
                black_box(signup(&db, email, password).await.unwrap())
            })
        })
    });
    
    // 基准测试：登录
    c.bench_function("signin", |b| {
        let mut counter = 0;
        b.iter(|| {
            let idx = counter % users.len();
            counter += 1;
            let (email, password) = &users[idx];
            
            rt.block_on(async {
                black_box(signin(&db, email.clone(), password.clone(), None, None).await.unwrap())
            })
        })
    });
}

criterion_group!(benches, auth_benchmark);
criterion_main!(benches);
```

### 安全测试

```rust
// tests/security_tests.rs
#[actix_web::test]
async fn test_password_reset_token_expiry() {
    // 设置测试数据库
    let db = setup_test_db().await;
    
    // 创建测试用户
    let email = "security_test@example.com";
    let password = "InitialPassword123";
    signup(&db, email.to_string(), password.to_string()).await.unwrap();
    
    // 请求密码重置令牌
    request_password_reset(&db, email.to_string()).await.unwrap();
    
    // 从数据库获取令牌
    let user = get_user_by_email(&db, email).await.unwrap().unwrap();
    let reset_token = user.reset_token.unwrap();
    
    // 模拟令牌过期（修改令牌过期时间为过去）
    let query = "UPDATE user SET reset_token_expires_at = $expired_time WHERE email = $email";
    db.query(query)
        .bind(("expired_time", Utc::now() - Duration::hours(1)))
        .bind(("email", email))
        .await.unwrap();
    
    // 尝试使用过期令牌重置密码
    let result = reset_password(
        &db,
        reset_token,
        "NewPassword456".to_string(),
    ).await;
    
    // 验证重置失败
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::TokenExpired));
    
    // 验证原密码仍然有效
    let signin_result = signin(
        &db,
        email.to_string(),
        password.to_string(),
        None,
        None,
    ).await;
    
    assert!(signin_result.is_ok());
}

#[actix_web::test]
async fn test_brute_force_protection() {
    // 设置测试数据库
    let db = setup_test_db().await;
    
    // 创建测试用户
    let email = "brute_force_test@example.com";
    let password = "SecurePassword123";
    signup(&db, email.to_string(), password.to_string()).await.unwrap();
    
    // 验证用户邮箱
    let user = get_user_by_email(&db, email).await.unwrap().unwrap();
    let token = user.verification_token.unwrap();
    verify_email(&db, token).await.unwrap();
    
    // 尝试多次登录失败
    let wrong_password = "WrongPassword123";
    let max_attempts = 5;
    
    for _ in 0..max_attempts {
        let result = signin(
            &db,
            email.to_string(),
            wrong_password.to_string(),
            Some("test-agent".to_string()),
            Some("127.0.0.1".to_string()),
        ).await;
        
        assert!(result.is_err());
    }
    
    // 验证账户是否被锁定
    let result = signin(
        &db,
        email.to_string(),
        password.to_string(), // 使用正确密码
        Some("test-agent".to_string()),
        Some("127.0.0.1".to_string()),
    ).await;
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AuthError::AccountLocked));
}
```

## 项目结构

```
auth-system/
├── .env
├── .gitignore
├── Cargo.toml
├── Dockerfile
├── README.md
├── migrations/
│   └── src/
│       └── main.rs
├── benches/
│   └── auth_benchmarks.rs
├── tests/
│   ├── integration_tests.rs
│   └── security_tests.rs
└── src/
    ├── main.rs
    ├── lib.rs
    ├── config/
    │   ├── mod.rs
    │   └── oauth.rs
    ├── models/
    │   ├── mod.rs
    │   ├── user.rs
    │   ├── requests.rs
    │   └── responses.rs
    ├── db/
    │   ├── mod.rs
    │   └── surrealdb.rs
    ├── auth/
    │   ├── mod.rs
    │   ├── signup.rs
    │   ├── signin.rs
    │   ├── signout.rs
    │   ├── verify_email.rs
    │   ├── password_reset.rs
    │   ├── session.rs
    │   └── providers/
    │       ├── mod.rs
    │       ├── google.rs
    │       └── github.rs
    ├── middleware/
    │   ├── mod.rs
    │   └── auth.rs
    ├── handlers/
    │   ├── mod.rs
    │   └── auth.rs
    ├── routes/
    │   ├── mod.rs
    │   └── auth.rs
    ├── error/
    │   ├── mod.rs
    │   └── auth_error.rs
    └── utils/
        ├── mod.rs
        ├── email.rs
        └── test_utils.rs
```

## 错误处理

```rust
// src/error/auth_error.rs
use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("Email not verified")]
    EmailNotVerified,
    
    #[error("Email already exists")]
    EmailAlreadyExists,
    
    #[error("Invalid verification token")]
    InvalidVerificationToken,
    
    #[error("Session expired")]
    SessionExpired,
    
    #[error("CSRF check failed")]
    CsrfCheckFailed,
    
    #[error("Token expired")]
    TokenExpired,
    
    #[error("Account locked")]
    AccountLocked,
    
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("JWT error: {0}")]
    JwtError(String),
    
    #[error("OAuth error: {0}")]
    OAuthError(String),
    
    #[error("Email error: {0}")]
    EmailError(String),
    
    #[error("Internal server error")]
    InternalServerError,
}

impl From<surrealdb::Error> for AuthError {
    fn from(err: surrealdb::Error) -> Self {
        AuthError::DatabaseError(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        AuthError::JwtError(err.to_string())
    }
}

impl From<oauth2::RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>> for AuthError {
    fn from(err: oauth2::RequestTokenError<oauth2::reqwest::Error<reqwest::Error>, oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>>) -> Self {
        AuthError::OAuthError(err.to_string())
    }
}

impl ResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            AuthError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            AuthError::EmailNotVerified => StatusCode::FORBIDDEN,
            AuthError::EmailAlreadyExists => StatusCode::CONFLICT,
            AuthError::InvalidVerificationToken => StatusCode::BAD_REQUEST,
            AuthError::SessionExpired => StatusCode::UNAUTHORIZED,
            AuthError::CsrfCheckFailed => StatusCode::BAD_REQUEST,
            AuthError::TokenExpired => StatusCode::BAD_REQUEST,
            AuthError::AccountLocked => StatusCode::FORBIDDEN,
            AuthError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::JwtError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::OAuthError(_) => StatusCode::BAD_GATEWAY,
            AuthError::EmailError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status_code = self.status_code();
        
        HttpResponse::build(status_code)
            .json(json!({
                "error": self.to_string()
            }))
    }
}
```

## 配置管理

```rust
// src/config/mod.rs
use serde::Deserialize;
use config::{Config as ConfigLib, ConfigError, Environment, File};
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub db: DatabaseConfig,
    pub jwt: JwtConfig,
    pub oauth: OAuthConfig,
    pub email: EmailConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub namespace: String,
    pub database: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
    pub expiry: Duration,
}

#[derive(Debug, Deserialize)]
pub struct OAuthConfig {
    pub google_client_id: String,
    pub google_client_secret: String,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub redirect_url: String,
}

#[derive(Debug, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    pub smtp_password: String,
    pub smtp_from: String,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let config = ConfigLib::builder()
            // 从默认配置文件读取
            .add_source(File::with_name("config/default"))
            // 从环境特定配置文件读取，允许覆盖默认值
            .add_source(
                File::with_name(&format!("config/{}", std::env::var("RUN_ENV").unwrap_or_else(|_| "development".into())))
                    .required(false),
            )
            // 从环境变量读取，允许覆盖所有值
            .add_source(Environment::with_prefix("APP").separator("__"))
            .build()?;

        config.try_deserialize()
    }
}
```

## 电子邮件发送

```rust
// src/utils/email.rs
use crate::error::AuthError;
use lettre::{
    message::{header::ContentType, Mailbox, MultiPart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use crate::config::EmailConfig;

pub struct EmailService {
    config: EmailConfig,
}

impl EmailService {
    pub fn new(config: EmailConfig) -> Self {
        Self { config }
    }

    pub fn send_verification_email(&self, to_email: &str, token: &str) -> Result<(), AuthError> {
        let from_address = self.config.smtp_from.parse::<Mailbox>()
            .map_err(|e| AuthError::EmailError(format!("Invalid from address: {}", e)))?;
        
        let to_address = to_email.parse::<Mailbox>()
            .map_err(|e| AuthError::EmailError(format!("Invalid to address: {}", e)))?;
        
        let verification_url = format!("{}/verify-email?token={}", self.config.redirect_url, token);
        
        let email = Message::builder()
            .from(from_address)
            .to(to_address)
            .subject("Verify your email address")
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        ContentType::TEXT_PLAIN,
                        format!(
                            "Please verify your email address by clicking the following link: {}\n\nIf you did not request this, please ignore this email.",
                            verification_url
                        ),
                    )
                    .singlepart(
                        ContentType::TEXT_HTML,
                        format!(
                            r#"<html>
                                <body>
                                    <h1>Email Verification</h1>
                                    <p>Please verify your email address by clicking the following link:</p>
                                    <p><a href="{}">Verify Email</a></p>
                                    <p>If you did not request this, please ignore this email.</p>
                                </body>
                            </html>"#,
                            verification_url
                        ),
                    ),
            )
            .map_err(|e| AuthError::EmailError(format!("Failed to build email: {}", e)))?;
        
        let creds = Credentials::new(
            self.config.smtp_username.clone(),
            self.config.smtp_password.clone(),
        );
        
        let mailer = SmtpTransport::relay(&self.config.smtp_host)
            .map_err(|e| AuthError::EmailError(format!("Failed to create SMTP transport: {}", e)))?
            .credentials(creds)
            .build();
        
        mailer.send(&email)
            .map_err(|e| AuthError::EmailError(format!("Failed to send email: {}", e)))?;
        
        Ok(())
    }

    pub fn send_password_reset_email(&self, to_email: &str, token: &str) -> Result<(), AuthError> {
        let from_address = self.config.smtp_from.parse::<Mailbox>()
            .map_err(|e| AuthError::EmailError(format!("Invalid from address: {}", e)))?;
        
        let to_address = to_email.parse::<Mailbox>()
            .map_err(|e| AuthError::EmailError(format!("Invalid to address: {}", e)))?;
        
        let reset_url = format!("{}/reset-password?token={}", self.config.redirect_url, token);
        
        let email = Message::builder()
            .from(from_address)
            .to(to_address)
            .subject("Reset your password")
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        ContentType::TEXT_PLAIN,
                        format!(
                            "You requested to reset your password. Please click the following link to set a new password: {}\n\nIf you did not request this, please ignore this email.",
                            reset_url
                        ),
                    )
                    .singlepart(
                        ContentType::TEXT_HTML,
                        format!(
                            r#"<html>
                                <body>
                                    <h1>Password Reset</h1>
                                    <p>You requested to reset your password. Please click the following link to set a new password:</p>
                                    <p><a href="{}">Reset Password</a></p>
                                    <p>This link will expire in 1 hour.</p>
                                    <p>If you did not request this, please ignore this email.</p>
                                </body>
                            </html>"#,
                            reset_url
                        ),
                    ),
            )
            .map_err(|e| AuthError::EmailError(format!("Failed to build email: {}", e)))?;
        
        let creds = Credentials::new(
            self.config.smtp_username.clone(),
            self.config.smtp_password.clone(),
        );
        
        let mailer = SmtpTransport::relay(&self.config.smtp_host)
            .map_err(|e| AuthError::EmailError(format!("Failed to create SMTP transport: {}", e)))?
            .credentials(creds)
            .build();
        
        mailer.send(&email)
            .map_err(|e| AuthError::EmailError(format!("Failed to send email: {}", e)))?;
        
        Ok(())
    }
}
```

## 参考资源

- [SurrealDB 官方文档](https://surrealdb.com/docs)
- [Actix Web 框架](https://actix.rs/)
- [Rust OAuth2 库](https://github.com/ramosbugs/oauth2-rs)
- [jsonwebtoken 库](https://github.com/Keats/jsonwebtoken)
- [argon2 密码哈希库](https://docs.rs/argon2)
- [Supabase Auth 文档](https://supabase.io/docs/guides/auth)

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityProvider {
    pub id: Option<Thing>,
    pub provider: String,
    pub provider_user_id: String,
    pub user_id: Thing,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: Option<Thing>,
    pub user_id: Thing,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}
```

## 核心功能实现

### 用户注册与登录

#### 用户注册

```rust
// src/auth/signup.rs
use argon2::{self, Config};
use chrono::Utc;
use uuid::Uuid;

pub async fn signup(
    db: &DatabaseConnection,
    email: String,
    password: String,
) -> Result<User, AuthError> {
    // 检查邮箱是否已存在
    if let Some(_) = get_user_by_email(db, &email).await? {
        return Err(AuthError::EmailAlreadyExists);
    }

    // 生成密码哈希
    let salt = Uuid::new_v4().to_string();
    let config = Config::default();
    let password_hash = argon2::hash_encoded(password.as_bytes(), salt.as_bytes(), &config)?;

    // 生成验证令牌
    let verification_token = Uuid::new_v4().to_string();
    
    let now = Utc::now();
    let user = User {
        id: None,
        email,
        password_hash: Some(password_hash),
        created_at: now,
        updated_at: now,
        email_verified: false,
        verification_token: Some(verification_token),
    };

    // 存储用户
    let created_user = db.create("user", user).await?;

    // 发送验证邮件
    send_verification_email(&created_user.email, &verification_token)?;

    Ok(created_user)
}
```

#### 电子邮件验证

```rust
// src/auth/verify_email.rs
pub async fn verify_email(
    db: &DatabaseConnection,
    token: String,
) -> Result<(), AuthError> {
    let query = "SELECT * FROM user WHERE verification_token = $token";
    let mut response = db.query(query)
        .bind(("token", token))
        .await?;
    
    let users: Vec<User> = response.take(0)?;
    
    if users.is_empty() {
        return Err(AuthError::InvalidVerificationToken);
    }
    
    let user = &users[0];
    let user_id = user.id.clone().unwrap();
    
    let query = "UPDATE $user_id SET email_verified = true, verification_token = NULL, updated_at = $now";
    db.query(query)
        .bind(("user_id", user_id))
        .bind(("now", Utc::now()))
        .await?;
    
    Ok(())
}
```

#### 用户登录

```rust
// src/auth/signin.rs
use argon2::verify_encoded;
use chrono::{Utc, Duration};
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};

pub async fn signin(
    db: &DatabaseConnection,
    email: String,
    password: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
) -> Result<(User, String), AuthError> {
    // 获取用户
    let user = match get_user_by_email(db, &email).await? {
        Some(user) => user,
        None => return Err(AuthError::InvalidCredentials),
    };
    
    // 验证密码
    if let Some(hash) = &user.password_hash {
        if !verify_encoded(hash, password.as_bytes())? {
            return Err(AuthError::InvalidCredentials);
        }
    } else {
        return Err(AuthError::InvalidCredentials);
    }
    
    // 检查邮箱是否已验证
    if !user.email_verified {
        return Err(AuthError::EmailNotVerified);
    }
    
    // 生成会话令牌
    let token = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + Duration::days(7);
    
    // 存储会话
    let session = Session {
        id: None,
        user_id: user.id.clone().unwrap(),
        token: token.clone(),
        expires_at,
        created_at: Utc::now(),
        user_agent,
        ip_address,
    };
    
    db.create("session", session).await?;
    
    // 生成 JWT
    let claims = Claims {
        sub: user.id.unwrap().to_string(),
        exp: expires_at.timestamp() as usize,
        email: user.email.clone(),
    };
    
    let jwt = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )?;
    
    Ok((user, jwt))
}
```

### 第三方认证集成

#### OAuth 配置

```rust
// src/config/oauth.rs
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl,
};

pub struct OAuthConfig {
    pub google_client: BasicClient,
    pub github_client: BasicClient,
    // 添加其他提供商...
}

impl OAuthConfig {
    pub fn new(config: &Config) -> Self {
        // 配置 Google OAuth
        let google_client = BasicClient::new(
            ClientId::new(config.google_client_id.clone()),
            Some(ClientSecret::new(config.google_client_secret.clone())),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
            Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_url.clone() + "/auth/google/callback").unwrap());

        // 配置 GitHub OAuth
        let github_client = BasicClient::new(
            ClientId::new(config.github_client_id.clone()),
            Some(ClientSecret::new(config.github_client_secret.clone())),
            AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap(),
            Some(TokenUrl::new("https://github.com/login/oauth/access_token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_url.clone() + "/auth/github/callback").unwrap());

        OAuthConfig {
            google_client,
            github_client,
        }
    }
}
```

#### Google 授权流程

```rust
// src/auth/providers/google.rs
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope, TokenResponse,
};
use reqwest::Client;

pub fn get_authorization_url(oauth_config: &OAuthConfig) -> (String, CsrfToken) {
    let (pkce_challenge, _pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    
    let (auth_url, csrf_token) = oauth_config
        .google_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    
    (auth_url.to_string(), csrf_token)
}

pub async fn handle_callback(
    db: &DatabaseConnection,
    oauth_config: &OAuthConfig,
    code: String,
    state: String,
    expected_state: String,
) -> Result<(User, String), AuthError> {
    // 验证状态参数
    if state != expected_state {
        return Err(AuthError::CsrfCheckFailed);
    }
    
    // 交换授权码获取令牌
    let token = oauth_config
        .google_client
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await?;
    
    // 使用访问令牌获取用户信息
    let client = Client::new();
    let user_info: GoogleUserInfo = client
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(token.access_token().secret())
        .send()
        .await?
        .json()
        .await?;
    
    // 查找或创建用户
    let user = find_or_create_user_from_google(db, &user_info).await?;
    
    // 创建会话并生成 JWT
    // ...与常规登录类似
    
    Ok((user, jwt))
}

async fn find_or_create_user_from_google(
    db: &DatabaseConnection,
    user_info: &GoogleUserInfo,
) -> Result<User, AuthError> {
    // 检查是否已存在此 Google 身份
    let query = "SELECT * FROM identity_provider WHERE provider = 'google' AND provider_user_id = $provider_id";
    let mut response = db.query(query)
        .bind(("provider_id", &user_info.sub))
        .await?;
    
    let providers: Vec<IdentityProvider> = response.take(0)?;
    
    if !providers.is_empty() {
        // 已存在此提供商身份，获取关联用户
        let user_id = &providers[0].user_id;
        let user = db.select(("user", user_id.id.to_string())).await?;
        return Ok(user);
    }
    
    // 检查是否存在此邮箱的用户
    if let Some(user) = get_user_by_email(db, &user_info.email).await? {
        // 存在此邮箱的用户，将 Google 身份关联到此用户
        link_provider_to_user(db, "google", &user_info.sub, user.id.unwrap()).await?;
        return Ok(user);
    }
    
    // 创建新用户
    let now = Utc::now();
    let user = User {
        id: None,
        email: user_info.email.clone(),
        password_hash: None, // 第三方登录用户没有密码
        created_at: now,
        updated_at: now,
        email_verified: true, // Google 已验证过邮箱
        verification_token: None,
    };
    
    let created_user = db.create("user", user).await?;
    
    // 关联提供商身份
    link_provider_to_user(db, "google", &user_info.sub, created_user.id.unwrap()).await?;
    
    Ok(created_user)
}
```

### 会话管理

#### 会话验证

```rust
// src/auth/session.rs
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

pub async fn validate_session(
    db: &DatabaseConnection,
    jwt: &str,
) -> Result<User, AuthError> {
    // 解码并验证 JWT
    let token_data = decode::<Claims>(
        jwt,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )?;
    
    let claims = token_data.claims;
    
    // 验证会话是否存在且未过期
    let query = "SELECT * FROM session WHERE token = $token AND expires_at > $now";
    let mut response = db.query(query)
        .bind(("token", claims.sub.clone()))
        .bind(("now", Utc::now()))
        .await?;
    
    let sessions: Vec<Session> = response.take(0)?;
    
    if sessions.is_empty() {
        return Err(AuthError::SessionExpired);
    }
    
    // 获取用户
    let user_id = sessions[0].user_id.clone();
    let user = db.select(("user", user_id.id.to_string())).await?;
    
    Ok(user)
}
```

#### 会话注销

```rust
// src/auth/signout.rs
pub async fn signout(
    db: &DatabaseConnection,
    jwt: &str,
) -> Result<(), AuthError> {
    // 解码 JWT 获取会话标识
    let token_data = decode::<Claims>(
        jwt,
        &DecodingKey::from_secret(JWT_SECRET.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )?;
    
    let claims = token_data.claims;
    
    // 删除会话
    let query = "DELETE FROM session WHERE token = $token";
    db.query(query)
        .bind(("token", claims.sub))
        .await?;
    
    Ok(())
}
```

### 权限控制

```rust
// src/middleware/auth.rs
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures::future::{ready, Ready, LocalBoxFuture};
use std::rc::Rc;

pub struct Auth;

impl<S, B> Transform<S, ServiceRequest> for Auth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddleware {
            service: Rc::new(service),
        }))
    }
}

pub struct AuthMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        
        Box::pin(async move {
            // 从请求头中获取 JWT
            let auth_header = req.headers().get("Authorization");
            
            if let Some(auth_header) = auth_header {
                let auth_str = auth_header.to_str().unwrap_or("");
                
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..]; // 去掉 "Bearer " 前缀
                    
                    // 获取数据库连接
                    let db = req.app_data::<web::Data<DatabaseConnection>>().unwrap();
                    
                    // 验证会话
                    match validate_session(&db, token).await {
                        Ok(user) => {
                            // 将用户信息附加到请求中
                            req.extensions_mut().insert(user);
                            let res = service.call(req).await?;
                            return Ok(res);
                        }
                        Err(_) => {
                            return Ok(req.into_response(
                                HttpResponse::Unauthorized()
                                    .json(json!({
                                        "error": "Invalid or expired session"
                                    }))
                                    .into_body(),
                            ));
                        }
                    }
                }
            }
            
            // 无授权头或格式错误
            Ok(req.into_response(
                HttpResponse::Unauthorized()
                    .json(json!({
                        "error": "Authorization required"
                    }))
                    .into_body(),
            ))
        })
    }
}
```

## API 设计

### 路由结构

```rust
// src/routes/auth.rs
use actix_web::{web, HttpResponse, Scope};

pub fn auth_routes() -> Scope {
    web::scope("/auth")
        // 基本认证路由
        .route("/signup", web::post().to(signup_handler))
        .route("/signin", web::post().to(signin_handler))
        .route("/signout", web::post().to(signout_handler))
        .route("/verify-email", web::get().to(verify_email_handler))
        .route("/request-password-reset", web::post().to(request_password_reset_handler))
        .route("/reset-password", web::post().to(reset_password_handler))
        
        // OAuth 路由
        .route("/google/authorize", web::get().to(google_authorize_handler))
        .route("/google/callback", web::get().to(google_callback_handler))
        .route("/github/authorize", web::get().to(github_authorize_handler))
        .route("/github/callback", web::get().to(github_callback_handler))
        
        // 用户信息路由
        .route("/me", web::get().to(get_current_user_handler))
        .wrap(Auth::default()) // 添加认证中间件
}
```

### 请求/响应模型

```rust
// src/models/requests.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct SigninRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct RequestPasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub password: String,
}

// src/models/responses.rs
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}
```

### 处理函数示例

```rust
// src/handlers/auth.rs
use actix_web::{web, HttpResponse, ResponseError};

async fn signup_handler(
    db: web::Data<DatabaseConnection>,
    req: web::Json<SignupRequest>,
) -> Result<HttpResponse, impl ResponseError> {
    let user = signup(&db, req.email.clone(), req.password.clone()).await?;
    
    let response = UserResponse {
        id: user.id.unwrap().to_string(),
        email: user.email,
        email_verified: user.email_verified,
        created_at: user.created_at,
    };
    
    Ok(HttpResponse::Created().json(response))
}

async fn signin_handler(
    db: web::Data<DatabaseConnection>,
    req: web::Json<SigninRequest>,
    req_parts: HttpRequest,
) -> Result<HttpResponse, impl ResponseError> {
    // 获取用户代理和 IP 地址
    let user_agent = req_parts
        .headers()
        .get("User-Agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    
    let ip_address = req_parts
        .connection_info()
        .realip_remote_addr()
        .map(|s| s.to_string());
    
    let (user, token) = signin(
        &db,
        req.email.clone(),
        req.password.clone(),
        user_agent,
        ip_address,
    ).await?;
    
    let response = AuthResponse {
        user: UserResponse {
            id: user.id.unwrap().to_string(),
            email: user.email,
            email_verified: user.email_verified,
            created_at: user.created_at,
        },
        token,
    };
    
    Ok(HttpResponse::Ok().json(response))
}
```

## 安全考量

### 密码安全

- **哈希算法**：使用 Argon2id 进行密码哈希
- **盐值**：每个密码使用唯一盐值
- **工作因子**：根据安全需求配置工作因子
- **密码策略**：实施最小长度和复杂度要求

### JWT 安全

- **签名算法**：使用 HMAC-SHA256 (HS256)
- **有效期**：设置合理的令牌过期时间
- **秘钥轮换**：定期轮换 JWT 秘钥
- **载荷最小化**：JWT 载荷中只包含必要信息

### OAuth 安全

- **状态参数**：使用 CSRF 令牌防御跨站请求伪造
- **PKCE**：实现 Proof Key for Code Exchange 增强安全性
- **重定向 URI**：严格验证重定向 URI
- **范围限制**：仅请求必要的 OAuth 范围

### 会话安全

- **会话超时**：实施合理的会话过期时间
- **并发控制**：控制每个用户的并发会话数
- **会话撤销**：提供立即撤销会话的机制
- **设备指纹**：记录用户代理和 IP 地址以便审计

## 部署指南

### 环境配置

创建 `.env` 文件配置环境变量：

```
# 服务器配置
SERVER_HOST=127.0.0.1
SERVER_PORT=8080

# SurrealDB 配置
SURREALDB_URL=ws://localhost:8000/rpc
SURREALDB_NAMESPACE=myapp
SURREALDB_DATABASE=auth
SURREALDB_USERNAME=root
SURREALDB_PASSWORD=root

# JWT 配置
JWT_SECRET=your-secret-key-here
JWT_EXPIRY=7d

# OAuth 配置
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
OAUTH_REDIRECT_URL=http://localhost:8080

# 邮件配置
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=user@example.com
SMTP_PASSWORD=password
SMTP_FROM=noreply@example.com
```

### 构建与运行

```bash
# 构建项目
cargo build --release

# 运行数据库迁移
cargo run --bin migrations

# 启动服务器
cargo run --bin server
```

### Docker 配置

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
WORKDIR /app
COPY --from=builder /app/target/release/auth-server /app/
COPY .env /app/
EXPOSE 8080
CMD ["./auth-server"]
```

## 测试策略

### 单元测试

```rust
// src/auth/tests/signin_tests.rs
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::setup_test_db;
    
    #[tokio::test]
    async fn test_signin_with_valid_credentials() {
        // 设置测试数据库
        let db = setup_test_db().await;
        
        // 创建测试用户
        let email = "test@example.com";
        let password = "password123";
        signup(&db, email.to_string(), password.to_string()).await.unwrap();
        
        // 验证用户邮箱
        let user = get_user_by_email(&db, email).await.unwrap().unwrap();
        let token = user.verification_token.unwrap();
        verify_email(&db, token).await.unwrap();
        
        // 测试登录
        let (user, jwt) = signin(
            &db,
            email.to_string(),
            password.to_string(),
            None,
            None,
        ).await.unwrap();
        
        assert_eq!(user.email, email);
        assert!(!jwt.is_empty());
    }
    
    #[tokio::test]
    async fn test_signin_with_invalid_credentials() {
        // 设置测试数据库
        let db = setup_test_db().await;
        
        // 创建测试用户
        let email = "test@example.com";
        let password = "password123";
        signup(&db, email.to_string(), password.to_string()).await.unwrap();
        
        // 尝试使用错误密码登录
        let result = signin(
            &db,
            email.to_string(),
            "wrong_password".to_string(),
            None,
            None,
        ).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::InvalidCredentials));
    }
}
