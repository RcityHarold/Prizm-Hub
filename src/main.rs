use std::{sync::Arc, net::SocketAddr};
use axum::{
    routing::Router,
    Extension,
};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing::info;
use tokio::time::{interval, Duration};

mod routes;
mod models;
mod services;
mod config;
mod error;
mod utils;

use crate::{
    config::Config,
    services::{
        database::Database, 
        rate_limiter::{RateLimiter, RateLimitRules},
        account_lockout::AccountLockoutService,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
    pub rate_limiter: Arc<RateLimiter>,
    pub lockout_service: Arc<AccountLockoutService>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 初始化日志
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("rust_auth=debug,tower_http=debug"))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting auth service...");

    // 加载配置
    dotenv::dotenv().ok();
    let config = Config::from_env()?;

    // 初始化数据库连接
    let db = Database::new(&config).await?;
    db.verify_connection().await?;
    
    info!("Database connection established. Please ensure database schema is initialized with schema.sql and initial_data.sql");

    // 创建共享的数据库实例
    let shared_db = Arc::new(db.clone());

    // 创建速率限制器
    let rate_limiter = Arc::new(
        RateLimiter::new()
            .with_default_rule(RateLimitRules::general_api())
            .with_endpoint_rule("/api/auth/login".to_string(), RateLimitRules::login())
            .with_endpoint_rule("/api/auth/register".to_string(), RateLimitRules::register())
            .with_endpoint_rule("/api/auth/forgot-password".to_string(), RateLimitRules::password_reset())
            .with_endpoint_rule("/api/auth/verify-email".to_string(), RateLimitRules::email_verification())
    );

    // 创建账户锁定服务
    let lockout_service = Arc::new(AccountLockoutService::new(shared_db.clone(), config.clone())?);

    // 启动定期清理任务
    let cleanup_limiter = rate_limiter.clone();
    let cleanup_lockout = lockout_service.clone();
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(3600)); // 每小时清理一次
        loop {
            interval.tick().await;
            cleanup_limiter.cleanup_expired_records().await;
            let _ = cleanup_lockout.cleanup_expired_lockouts().await;
        }
    });

    // 创建 app state
    let app_state = AppState {
        db,
        config: config.clone(),
        rate_limiter: rate_limiter.clone(),
        lockout_service: lockout_service.clone(),
    };

    // 创建路由
    let app = Router::new()
        .nest("/api/auth", routes::auth::router(shared_db.clone()))
        .nest("/api/rbac", routes::rbac::router())
        .nest("/api/users", routes::user_management::router())
        .layer(Extension(shared_db))
        .layer(Extension(Arc::new(app_state)))
        .layer(Extension(config.clone()))  // 添加 Config 扩展
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // 启动服务器
    let addr = "0.0.0.0:8080";
    info!("Server listening on {}", addr);
    axum::Server::bind(&addr.parse()?)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    Ok(())
}
