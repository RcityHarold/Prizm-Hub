use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode, Request},
    middleware::Next,
    response::Response,
    Json,
};
use serde_json::json;
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;

use crate::services::rate_limiter::RateLimiter;

/// 简单的速率限制中间件
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    req: Request<axum::body::Body>,
    next: Next<axum::body::Body>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // 从请求扩展中获取速率限制器 (将在路由层添加)
    // 这里先实现一个简单的版本，后续优化
    let client_id = get_client_identifier(&addr, &headers);
    let endpoint = req.uri().path().to_string();
    
    // 临时创建一个速率限制器用于测试
    // 在实际使用中，这应该从应用状态中获取
    let limiter = RateLimiter::new();
    
    match limiter.check_rate_limit(&client_id, &endpoint).await {
        Ok(true) => {
            let response = next.run(req).await;
            let remaining = limiter.get_remaining_requests(&client_id, &endpoint).await;
            
            let mut response = response;
            let headers = response.headers_mut();
            headers.insert("X-RateLimit-Remaining", remaining.to_string().parse().unwrap());
            
            Ok(response)
        }
        Ok(false) => {
            warn!("Rate limit exceeded for client: {}, endpoint: {}", client_id, endpoint);
            
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                    "code": "RATE_LIMIT_EXCEEDED"
                })),
            ))
        }
        Err(e) => {
            warn!("Rate limiter error: {}", e);
            Ok(next.run(req).await)
        }
    }
}

/// 获取客户端标识符
fn get_client_identifier(addr: &SocketAddr, headers: &HeaderMap) -> String {
    // 尝试从头部获取真实IP
    if let Some(forwarded_for) = headers.get("X-Forwarded-For") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            // 取第一个IP地址
            if let Some(ip) = forwarded_str.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    if let Some(real_ip) = headers.get("X-Real-IP") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.to_string();
        }
    }

    // 回退到连接地址
    addr.ip().to_string()
}

/// 速率限制检查辅助函数
/// 这个函数可以在路由处理器中直接调用来实现速率限制
pub async fn check_rate_limit_for_request(
    limiter: &RateLimiter,
    client_ip: &str,
    endpoint: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    match limiter.check_rate_limit(client_ip, endpoint).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            warn!("Rate limit exceeded for client: {}, endpoint: {}", client_ip, endpoint);
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                    "code": "RATE_LIMIT_EXCEEDED"
                })),
            ))
        }
        Err(e) => {
            warn!("Rate limiter error: {}", e);
            Ok(()) // 发生错误时允许请求继续
        }
    }
}

/// 从JWT token中提取用户ID (可选功能)
fn extract_user_id_from_token(headers: &HeaderMap) -> Option<String> {
    let auth_header = headers.get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;
    
    if !auth_str.starts_with("Bearer ") {
        return None;
    }
    
    let token = &auth_str[7..];
    
    use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
    use serde::{Deserialize, Serialize};
    
    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: usize,
    }
    
    let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "default_secret".to_string());
    let key = DecodingKey::from_secret(secret.as_ref());
    let validation = Validation::new(Algorithm::HS256);
    
    match decode::<Claims>(token, &key, &validation) {
        Ok(token_data) => Some(token_data.claims.sub),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_get_client_identifier_from_forwarded_for() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let mut headers = HeaderMap::new();
        headers.insert("X-Forwarded-For", "192.168.1.1, 10.0.0.1".parse().unwrap());
        
        let client_id = get_client_identifier(&addr, &headers);
        assert_eq!(client_id, "192.168.1.1");
    }

    #[test]
    fn test_get_client_identifier_from_real_ip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let mut headers = HeaderMap::new();
        headers.insert("X-Real-IP", "192.168.1.100".parse().unwrap());
        
        let client_id = get_client_identifier(&addr, &headers);
        assert_eq!(client_id, "192.168.1.100");
    }

    #[test]
    fn test_get_client_identifier_fallback() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), 8080);
        let headers = HeaderMap::new();
        
        let client_id = get_client_identifier(&addr, &headers);
        assert_eq!(client_id, "192.168.1.50");
    }
}