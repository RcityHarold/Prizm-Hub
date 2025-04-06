use std::sync::Arc;
use axum::{
    routing::Router,
    Extension,
};
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing::info;

mod routes;
mod models;
mod services;
mod config;
mod error;
mod utils;

use crate::{
    config::Config,
    services::database::Database,
};

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
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

    // 初始化数据库
    let db = Database::new(&config).await?;
    db.initialize_schema().await?;

    // 创建共享的数据库实例
    let shared_db = Arc::new(db.clone());

    // 创建 app state
    let app_state = AppState {
        db,
        config: config.clone(),
    };

    // 创建路由
    let app = Router::new()
        .nest("/api/auth", routes::auth::router(shared_db))
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
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
