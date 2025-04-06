use crate::{
    config::Config,
    error::{AuthError, Result},
    models::identity_provider::OAuthUserInfo,
};
use oauth2::{
    basic::BasicClient,
    reqwest::async_http_client,
    AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    id: String,
    email: String,
    verified_email: bool,
    name: Option<String>,
    picture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUserInfo {
    id: i64,
    email: Option<String>,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

pub struct OAuthService {
    config: Config,
    google_client: BasicClient,
    github_client: BasicClient,
}

impl OAuthService {
    pub fn new(config: Config) -> Result<Self> {
        let google_client = BasicClient::new(
            ClientId::new(config.google_client_id.clone()),
            Some(ClientSecret::new(config.google_client_secret.clone())),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
            Some(
                TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
                    .map_err(|e| AuthError::OAuthError(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/google", config.oauth_redirect_url))
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
        );

        let github_client = BasicClient::new(
            ClientId::new(config.github_client_id.clone()),
            Some(ClientSecret::new(config.github_client_secret.clone())),
            AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
            Some(
                TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
                    .map_err(|e| AuthError::OAuthError(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(format!("{}/github", config.oauth_redirect_url))
                .map_err(|e| AuthError::OAuthError(e.to_string()))?,
        );

        Ok(Self {
            config,
            google_client,
            github_client,
        })
    }

    pub fn get_google_auth_url(&self) -> Result<String> {
        let (auth_url, _) = self
            .google_client
            .authorize_url(|| CsrfToken::new(uuid::Uuid::new_v4().to_string()))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.profile".to_string(),
            ))
            .url();

        Ok(auth_url.to_string())
    }

    pub fn get_github_auth_url(&self) -> Result<String> {
        let (auth_url, _) = self
            .github_client
            .authorize_url(|| CsrfToken::new(uuid::Uuid::new_v4().to_string()))
            .add_scope(Scope::new("user:email".to_string()))
            .url();

        Ok(auth_url.to_string())
    }

    pub async fn handle_google_callback(&self, code: String) -> Result<OAuthUserInfo> {
        // 交换授权码获取访问令牌
        let token = self
            .google_client
            .exchange_code(oauth2::AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 使用访问令牌获取用户信息
        let client = reqwest::Client::new();
        let user_info: GoogleUserInfo = client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .bearer_auth(token.access_token().secret())
            .send()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        if !user_info.verified_email {
            return Err(AuthError::EmailNotVerified);
        }

        Ok(OAuthUserInfo {
            provider: "google".to_string(),
            provider_user_id: user_info.id,
            email: user_info.email,
            name: user_info.name,
            picture: user_info.picture,
        })
    }

    pub async fn handle_github_callback(&self, code: String) -> Result<OAuthUserInfo> {
        // 交换授权码获取访问令牌
        let token = self
            .github_client
            .exchange_code(oauth2::AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        let client = reqwest::Client::new();
        
        // 获取用户信息
        let user_info: GitHubUserInfo = client
            .get("https://api.github.com/user")
            .bearer_auth(token.access_token().secret())
            .header("User-Agent", "rust-auth-system")
            .send()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 获取用户邮箱（因为某些用户可能没有公开邮箱）
        let emails: Vec<GitHubEmail> = client
            .get("https://api.github.com/user/emails")
            .bearer_auth(token.access_token().secret())
            .header("User-Agent", "rust-auth-system")
            .send()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::OAuthError(e.to_string()))?;

        // 获取主要且已验证的邮箱
        let primary_email = emails
            .into_iter()
            .find(|e| e.primary && e.verified)
            .ok_or_else(|| AuthError::EmailNotVerified)?;

        Ok(OAuthUserInfo {
            provider: "github".to_string(),
            provider_user_id: user_info.id.to_string(),
            email: primary_email.email,
            name: user_info.name,
            picture: user_info.avatar_url,
        })
    }
}
