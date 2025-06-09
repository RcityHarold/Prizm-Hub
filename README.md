# Rust Auth System

一个使用 Rust 构建的现代化认证系统，支持多种认证方式和用户管理功能。

## 功能特点

### 用户认证
- 邮箱密码注册和登录
- Google OAuth 登录
- GitHub OAuth 登录
- JWT 令牌认证
- 邮箱验证
- 密码加密存储 (Argon2)
- 密码重置功能
- 安全会话管理

### 用户管理
- 用户注册（需邮箱验证）
- 用户登录
- 强制邮箱验证
- 获取用户信息
- OAuth 用户管理
- 完整的会话管理
- 密码重置和恢复

### 安全增强功能
- 基于数据库的会话存储
- 会话主动失效（登出）
- 批量会话管理（全部登出）
- 防止邮箱枚举攻击
- 时效性密码重置令牌
- 安全的JWT密钥管理

### 最新更新 (安全修复版本)
- 🔒 **安全修复**: 移除JWT密钥硬编码，强制使用环境变量
- 🔒 **安全修复**: 移除敏感信息日志泄露（邮箱、令牌等）
- 🔒 **数据库安全**: 添加连接超时和错误处理改进
- ✨ **新功能**: 完整的密码重置流程（请求重置、验证令牌、重置密码）
- ✨ **新功能**: 真正的会话管理系统（登出、会话列表、批量登出）
- 🔧 **修复**: 邮箱验证逻辑优化（注册后强制验证才能登录）
- 🔧 **修复**: OAuth 用户记录处理改进
- 📊 **数据库**: 新增 password_reset_token 和 session 表

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
DATABASE_URL=http://localhost:8000
DATABASE_USER=root
DATABASE_PASS=root
DATABASE_CONNECTION_TIMEOUT=30
DATABASE_MAX_CONNECTIONS=10

# JWT配置 (必需)
JWT_SECRET=your-super-secure-jwt-secret-key-here
JWT_EXPIRATION=86400

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

# 代理配置（可选）
PROXY_ENABLED=false
PROXY_URL=http://your-proxy:port
```

3. 构建和运行
```bash
cargo build
cargo run
```

## 数据库结构

### 用户表 (user)
```sql
DEFINE TABLE user SCHEMALESS;
```

字段:
- id: Thing - 用户唯一标识符
- email: string - 用户邮箱
- password: string - 加密后的密码
- email_verified: bool - 邮箱验证状态
- created_at: datetime - 创建时间
- updated_at: datetime - 更新时间

### 身份提供商表 (identity_provider)
```sql
DEFINE TABLE identity_provider SCHEMAFULL;
```

字段:
- id: Thing - 记录唯一标识符
- provider: string - 提供商名称 (google/github)
- provider_user_id: string - 提供商用户ID
- user_id: Thing - 关联的用户ID
- created_at: number - 创建时间戳
- updated_at: number - 更新时间戳

### 会话表 (session)
```sql
DEFINE TABLE session SCHEMAFULL;
```

字段:
- id: Thing - 会话唯一标识符
- user_id: Thing - 关联的用户ID
- token: string - JWT令牌
- expires_at: number - 过期时间戳
- created_at: number - 创建时间戳
- user_agent: string - 用户代理
- ip_address: string - IP地址

### 密码重置令牌表 (password_reset_token)
```sql
DEFINE TABLE password_reset_token SCHEMAFULL;
```

字段:
- id: Thing - 令牌唯一标识符
- email: string - 用户邮箱
- token: string - 重置令牌
- expires_at: datetime - 过期时间
- used: bool - 是否已使用
- created_at: datetime - 创建时间

## API 端点

### 用户认证
- `POST /api/auth/register` - 用户注册（需验证邮箱）
- `POST /api/auth/login` - 用户登录
- `GET /api/auth/verify-email/:token` - 验证邮箱（返回JWT令牌）
- `GET /api/auth/me` - 获取当前用户信息
- `POST /api/auth/initialize-password` - 初始化密码（OAuth用户）

### 密码管理
- `POST /api/auth/request-password-reset` - 请求密码重置
- `POST /api/auth/reset-password` - 重置密码

### 会话管理
- `POST /api/auth/logout` - 登出当前会话
- `POST /api/auth/logout-all` - 登出所有会话
- `GET /api/auth/sessions` - 获取用户所有会话

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
"Registration successful. Please check your email to verify your account."

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

# 成功响应 (200 OK) - 验证成功并返回JWT令牌
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
# 400 Bad Request - 无效的验证令牌
{
    "error": "Invalid token"
}
```

### 请求密码重置
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/request-password-reset \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'

# 成功响应 (200 OK)
"Password reset email sent if account exists"
```

### 重置密码
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset-token-from-email",
    "new_password": "newpassword123"
  }'

# 成功响应 (200 OK)
"Password reset successfully"

# 可能的错误响应
# 400 Bad Request - 无效或过期的重置令牌
{
    "error": "Invalid token"
}
```

### 登出当前会话
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/logout \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
"Logged out successfully"
```

### 登出所有会话
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/logout-all \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
"All sessions logged out successfully"
```

### 获取用户会话列表
```bash
# 请求
curl http://localhost:8080/api/auth/sessions \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
[
    {
        "id": "session_abc123",
        "created_at": "2025-04-01T02:45:29Z",
        "user_agent": "Mozilla/5.0...",
        "ip_address": "192.168.1.100",
        "is_current": true
    },
    {
        "id": "session_def456",
        "created_at": "2025-03-31T18:30:15Z",
        "user_agent": "Chrome/91.0...",
        "ip_address": "192.168.1.101",
        "is_current": false
    }
]
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

### 认证安全
- 密码使用 Argon2 加密存储
- JWT 用于会话管理，包含会话ID
- 强制邮箱验证（注册后必须验证才能登录）
- OAuth 用户自动验证
- 安全的JWT密钥管理（强制环境变量配置）

### 会话安全
- 基于数据库的真实会话存储
- 会话主动失效机制（登出功能）
- 支持批量会话管理（全部登出）
- 会话过期时间控制
- 用户设备和IP跟踪

### 密码安全
- 安全的密码重置流程
- 时效性密码重置令牌（1小时过期）
- 一次性使用的重置令牌
- 防止邮箱枚举攻击

### 系统安全
- 敏感信息日志保护
- 数据库连接超时保护
- CSRF 保护准备
- 输入验证和错误处理

## 开发路线图

### 已完成 ✅
- [x] 实现密码重置功能
- [x] 完整的会话管理系统
- [x] 安全漏洞修复
- [x] 邮箱验证流程优化
- [x] 敏感信息保护

### 计划中 📋
- [ ] 添加API请求频率限制 (Rate Limiting)
- [ ] 实现双因素认证 (2FA/TOTP)
- [ ] 添加用户角色和权限管理 (RBAC)
- [ ] 账户安全增强（登录失败锁定、异常检测）
- [ ] 添加更多OAuth提供商支持
- [ ] 实现账号关联功能（多个OAuth账号关联）
- [ ] 添加审计日志和监控
- [ ] 密码复杂度策略
- [ ] 设备指纹识别

## ⚠️ 重要安全注意事项

### 生产环境部署前必读

1. **JWT密钥安全**
   - `JWT_SECRET` 必须是强随机密钥（至少32字符）
   - 绝不要在代码中硬编码JWT密钥
   - 定期轮换JWT密钥

2. **环境变量配置**
   - 所有敏感配置必须通过环境变量设置
   - 使用 `.env` 文件仅用于开发环境
   - 生产环境使用安全的密钥管理服务

3. **数据库安全**
   - 确保数据库连接使用强密码
   - 启用数据库连接加密
   - 限制数据库访问权限

4. **HTTPS部署**
   - 生产环境必须使用HTTPS
   - 配置安全的TLS证书
   - 启用HSTS等安全头

5. **邮件安全**
   - 使用可信的SMTP服务提供商
   - 配置SPF、DKIM、DMARC记录
   - 监控邮件发送状态

## 贡献

欢迎提交 Pull Request 和 Issue！

## 许可证

MIT License
