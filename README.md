# Rust Auth System

一个使用 Rust 构建的现代化认证系统，支持多种认证方式和用户管理功能。

## 功能特点

### 用户认证
- ✅ 邮箱密码注册和登录
- ✅ Google OAuth 登录
- ✅ GitHub OAuth 登录
- ✅ JWT 令牌认证
- ✅ 邮箱验证
- ✅ 密码加密存储 (Argon2)

### 用户管理
- ✅ 用户注册
- ✅ 用户登录
- ✅ 邮箱验证
- ✅ 获取用户信息
- ✅ OAuth 用户管理
- ✅ 会话管理

## 技术栈

- **后端框架**: [Axum](https://github.com/tokio-rs/axum)
- **数据库**: [SurrealDB](https://surrealdb.com/)
- **认证**: [jsonwebtoken](https://github.com/Keats/jsonwebtoken)
- **密码加密**: [Argon2](https://github.com/RustCrypto/password-hashes/tree/master/argon2)
- **邮件服务**: [lettre](https://github.com/lettre/lettre)
- **OAuth**: [oauth2](https://github.com/ramosbugs/oauth2-rs)

## 快速开始

### 环境要求
- Rust 1.70.0 或更高版本
- SurrealDB
- SMTP 服务器（用于发送邮件）

### 配置

1. 克隆项目
```bash
git clone https://github.com/yourusername/rust-auth.git
cd rust-auth
```

2. 配置环境变量
创建 `.env` 文件并添加以下配置：

```env
# 数据库配置
DATABASE_URL=memory

# JWT配置
JWT_SECRET=your-jwt-secret
JWT_EXPIRATION=24h

# Google OAuth配置
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# GitHub OAuth配置
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# OAuth回调URL
OAUTH_REDIRECT_URL=http://localhost:8080/api/auth/callback

# SMTP配置
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-username
SMTP_PASSWORD=your-password
SMTP_FROM=noreply@example.com

# 应用配置
APP_URL=http://localhost:8080
```

3. 构建和运行
```bash
cargo build
cargo run
```

## API 端点

### 用户认证
- `POST /api/auth/register` - 用户注册
- `POST /api/auth/login` - 用户登录
- `GET /api/auth/verify-email/:token` - 验证邮箱
- `GET /api/auth/me` - 获取当前用户信息

### OAuth认证
- `GET /api/auth/login/google` - Google登录
- `GET /api/auth/callback/google` - Google回调处理
- `GET /api/auth/login/github` - GitHub登录
- `GET /api/auth/callback/github` - GitHub回调处理

## API 示例

所有接口在出错时会返回统一的错误格式：
```json
{
    "error": "错误信息描述"
}
```

### 注册新用户
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

# 成功响应 (200 OK)
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": "user_2x8j9z",
        "email": "user@example.com",
        "email_verified": false,
        "created_at": "2025-04-01T02:45:29Z"
    }
}

# 可能的错误响应
# 409 Conflict - 邮箱已存在
{
    "error": "Email already exists"
}
# 400 Bad Request - 无效的邮箱格式
{
    "error": "Invalid email format"
}
```

### 用户登录
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'

# 成功响应 (200 OK)
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "user": {
        "id": "user_2x8j9z",
        "email": "user@example.com",
        "email_verified": true,
        "created_at": "2025-04-01T02:45:29Z"
    }
}

# 可能的错误响应
# 401 Unauthorized - 凭据无效
{
    "error": "Invalid credentials"
}
# 403 Forbidden - 邮箱未验证
{
    "error": "Email not verified"
}
```

### 获取用户信息
```bash
# 请求
curl http://localhost:8080/api/auth/me \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
{
    "id": "user_2x8j9z",
    "email": "user@example.com",
    "email_verified": true,
    "created_at": "2025-04-01T02:45:29Z",
    "oauth_providers": [
        {
            "provider": "google",
            "email": "user@gmail.com"
        }
    ]
}

# 可能的错误响应
# 401 Unauthorized - 无效或过期的令牌
{
    "error": "Invalid token"
}
```

### 验证邮箱
```bash
# 请求
curl http://localhost:8080/api/auth/verify-email/verification-token-here

# 成功响应 (200 OK)
"Email verified successfully"

# 可能的错误响应
# 400 Bad Request - 无效的验证令牌
{
    "error": "Invalid token"
}
```

### OAuth 登录回调
```bash
# Google/GitHub OAuth 回调响应
# 成功时重定向到：
/login/success?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# 失败时重定向到：
/login/error?error=授权失败的原因
```

### OAuth 用户信息示例
```json
# OAuth 登录成功后的用户信息
{
    "id": "user_2x8j9z",
    "email": "user@gmail.com",
    "email_verified": true,
    "created_at": "2025-04-01T02:45:29Z",
    "oauth_providers": [
        {
            "provider": "google",
            "email": "user@gmail.com",
            "name": "John Doe",
            "picture": "https://lh3.googleusercontent.com/..."
        }
    ]
}
```

所有 API 都支持跨域请求（CORS），并使用标准的 HTTP 状态码：
- 200: 成功
- 400: 请求参数错误
- 401: 未授权
- 403: 禁止访问
- 404: 资源不存在
- 409: 资源冲突
- 500: 服务器错误

## 前端集成

### OAuth登录示例
```javascript
// Google登录
function loginWithGoogle() {
  window.location.href = '/api/auth/login/google';
}

// GitHub登录
function loginWithGithub() {
  window.location.href = '/api/auth/login/github';
}

// 处理OAuth回调
if (window.location.pathname === '/login/success') {
  const token = new URLSearchParams(window.location.search).get('token');
  if (token) {
    localStorage.setItem('auth_token', token);
    window.location.href = '/';
  }
}
```

## 安全特性

- 密码使用 Argon2 加密存储
- JWT 用于会话管理
- 强制邮箱验证
- OAuth 用户自动验证
- 安全的密码重置流程

## 开发路线图

- [ ] 添加账号关联功能（多个OAuth账号关联）
- [ ] 实现密码重置功能
- [ ] 添加用户角色和权限管理
- [ ] 实现双因素认证
- [ ] 添加社交账号绑定功能
- [ ] 实现 API 限流

## 贡献

欢迎提交 Pull Request 和 Issue！

## 许可证

MIT License
