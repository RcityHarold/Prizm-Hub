use crate::{
    config::Config,
    error::{AuthError, Result},
    models::{
        user::{User, CreateUserRequest, AuthResponse, UserResponse},
        session::Session,
        identity_provider::{IdentityProvider, OAuthUserInfo},
    },
    services::{
        database::Database,
        email::EmailService,
        oauth::OAuthService,
    },
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::sync::Arc;
use surrealdb::sql::Thing;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: i64,
    iat: i64,
}

pub struct AuthService {
    db: Arc<Database>,
    config: Config,
    email_service: EmailService,
    oauth_service: OAuthService,
}

impl AuthService {
    pub fn new(db: Arc<Database>, config: Config) -> Result<Self> {
        let email_service = EmailService::new(config.clone());
        let oauth_service = OAuthService::new(config.clone())?;
        Ok(Self {
            db,
            config,
            email_service,
            oauth_service,
        })
    }

    pub fn get_google_auth_url(&self) -> Result<String> {
        self.oauth_service.get_google_auth_url()
    }

    pub async fn handle_google_callback(&self, code: String) -> Result<AuthResponse> {
        // 获取 Google 用户信息
        let user_info = self.oauth_service.handle_google_callback(code).await?;
        
        // 查找或创建用户
        let user = self.find_or_create_oauth_user(user_info).await?;
        
        // 创建会话
        self.create_session(user).await
    }

    pub fn get_github_auth_url(&self) -> Result<String> {
        self.oauth_service.get_github_auth_url()
    }

    pub async fn handle_github_callback(&self, code: String) -> Result<AuthResponse> {
        // 获取 GitHub 用户信息
        let user_info = self.oauth_service.handle_github_callback(code).await?;
        
        // 查找或创建用户
        let user = self.find_or_create_oauth_user(user_info).await?;
        
        // 创建会话
        self.create_session(user).await
    }

    async fn find_or_create_oauth_user(&self, user_info: OAuthUserInfo) -> Result<User> {
        // 首先通过 identity_provider 查找用户
        if let Some(identity) = self.db.find_record_by_field::<IdentityProvider>(
            "identity_provider",
            "provider_user_id",
            &user_info.provider_user_id,
        ).await?
        {
            // 如果找到身份提供商记录，返回对应的用户
            return self.db.find_record_by_field::<User>(
                "user",
                "id",
                &identity.user_id.to_string(),
            ).await?
            .ok_or(AuthError::UserNotFound);
        }

        // 检查邮箱是否已存在
        if let Some(existing_user) = self.db.find_record_by_field::<User>(
            "user",
            "email",
            &user_info.email,
        ).await?
        {
            // 如果找到用户，创建身份提供商记录
            let identity = IdentityProvider {
                id: None,
                provider: user_info.provider,
                provider_user_id: user_info.provider_user_id,
                user_id: existing_user.id.as_ref().unwrap().to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            self.db.create_record("identity_provider", &identity).await?;
            return Ok(existing_user);
        }

        // 创建新用户
        let now = Utc::now();
        let id = Thing {
            tb: "user".to_string(),
            id: Uuid::new_v4().to_string().into(),
        };
        let user = User {
            id: Some(id.clone()),
            email: user_info.email,
            password_hash: None, // OAuth 用户没有密码
            created_at: now,
            updated_at: now,
            is_email_verified: true, // OAuth 邮箱已验证
            verification_token: None,
        };

        let created_user = self.db.create_record("user", &user).await?;

        // 创建身份提供商记录
        let identity = IdentityProvider {
            id: None,
            provider: user_info.provider,
            provider_user_id: user_info.provider_user_id,
            user_id: id.id.to_string(),
            created_at: now,
            updated_at: now,
        };
        self.db.create_record("identity_provider", &identity).await?;

        Ok(created_user)
    }

    pub async fn register(&self, req: CreateUserRequest) -> Result<AuthResponse> {
        // 检查邮箱是否已存在
        if let Some(_) = self.db.find_record_by_field::<User>(
            "user",
            "email",
            &req.email,
        ).await?
        {
            return Err(AuthError::EmailExists);
        }

        // 生成密码哈希
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hashed_password = argon2
            .hash_password(req.password.as_bytes(), &salt)
            .map_err(|e| AuthError::ServerError(e.to_string()))?
            .to_string();

        // 创建用户
        let now = Utc::now();
        let verification_token = Uuid::new_v4().to_string();
        let id = Thing {
            tb: "user".to_string(),
            id: Uuid::new_v4().to_string().into(),
        };
        let user = User {
            id: Some(id),
            email: req.email.clone(),
            password_hash: Some(hashed_password),
            created_at: now,
            updated_at: now,
            is_email_verified: false,
            verification_token: Some(verification_token.clone()),
        };

        let created_user = self.db.create_record("user", &user).await?;
        
        // 发送验证邮件
        self.email_service.send_verification_email(&req.email, &verification_token).await?;
        
        // 创建会话
        self.create_session(created_user).await
    }

    pub async fn login(&self, email: String, password: String) -> Result<AuthResponse> {
        // 查找用户
        let user = self.db.find_record_by_field::<User>(
            "user",
            "email",
            &email,
        ).await?
        .ok_or(AuthError::InvalidCredentials)?;

        // 验证密码
        let password_hash = user.password_hash
            .as_ref()
            .ok_or(AuthError::InvalidCredentials)?;
        let parsed_hash = PasswordHash::new(password_hash)
            .map_err(|e| AuthError::ServerError(e.to_string()))?;
        
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .map_err(|_| AuthError::InvalidCredentials)?;

        // 检查邮箱验证状态
        if !user.is_email_verified {
            return Err(AuthError::EmailNotVerified);
        }

        // 创建会话
        self.create_session(user).await
    }

    async fn create_session(&self, user: User) -> Result<AuthResponse> {
        let now = Utc::now();
        let exp = now + Duration::hours(24); // 24小时后过期

        let claims = Claims {
            sub: user.id.as_ref().unwrap().to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| AuthError::TokenError(e.to_string()))?;

        Ok(AuthResponse {
            token,
            user: UserResponse {
                id: user.id.as_ref().unwrap().to_string(),
                email: user.email,
                is_email_verified: user.is_email_verified,
                created_at: user.created_at,
            },
        })
    }

    pub async fn verify_email(&self, token: String) -> Result<()> {
        let user = self.db.find_record_by_field::<User>(
            "user",
            "verification_token",
            &token,
        ).await?
        .ok_or(AuthError::InvalidToken)?;

        let mut updated_user = user.clone();
        updated_user.is_email_verified = true;
        updated_user.verification_token = None;
        updated_user.updated_at = Utc::now();
        // 保持原始 id
        updated_user.id = user.id.clone();

        self.db.update_record(
            "user",
            user.id.as_ref().unwrap(),
            &updated_user,
        ).await?;

        Ok(())
    }

    pub async fn get_user_by_id(&self, user_id: &str) -> Result<Option<User>> {
        self.db.find_record_by_field("user", "id", user_id).await
    }
}
