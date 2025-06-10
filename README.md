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

### 安全防护层 🛡️
- **速率限制 (Rate Limiting)**: 防止暴力破解和API滥用
- **多因素认证 (MFA)**: TOTP/Google Authenticator支持
- **账户锁定机制**: 多次失败登录后自动锁定账户
- **智能安全检查**: 基于IP和用户的双重保护
- **自动安全管理**: 过期记录清理和动态解锁

### 安全增强功能
- 基于数据库的会话存储
- 会话主动失效（登出）
- 批量会话管理（全部登出）
- 防止邮箱枚举攻击
- 时效性密码重置令牌
- 安全的JWT密钥管理

### 最新更新 (安全防护层完成版本) 🎉
- 🛡️ **安全防护层完成**: 全面的安全防护体系
  - ✅ **速率限制**: 智能API请求频率控制，防止暴力破解
  - ✅ **多因素认证**: 完整TOTP/Google Authenticator支持
  - ✅ **账户锁定**: 自动锁定机制，多维度安全保护
  - ✅ **设备安全**: IP和用户双重锁定策略
  - ✅ **自动管理**: 定期清理和智能解锁
- 🔒 **安全修复**: 移除JWT密钥硬编码，强制使用环境变量
- 🔒 **安全修复**: 移除敏感信息日志泄露（邮箱、令牌等）
- 🔒 **数据库安全**: 添加连接超时和错误处理改进
- ✨ **新功能**: 完整的密码重置流程（请求重置、验证令牌、重置密码）
- ✨ **新功能**: 真正的会话管理系统（登出、会话列表、批量登出）
- 🔧 **修复**: 邮箱验证逻辑优化（注册后强制验证才能登录）
- 🔧 **修复**: OAuth 用户记录处理改进
- 📊 **数据库**: 新增 password_reset_token、session、user_mfa、account_lockout 表

## 技术栈

- **后端框架**: [Axum](https://github.com/tokio-rs/axum)
- **数据库**: [SurrealDB](https://surrealdb.com/)
- **认证**: [jsonwebtoken](https://github.com/Keats/jsonwebtoken)
- **密码加密**: [Argon2](https://github.com/RustCrypto/password-hashes/tree/master/argon2)
- **邮件服务**: [lettre](https://github.com/lettre/lettre)
- **OAuth**: [oauth2](https://github.com/ramosbugs/oauth2-rs)
- **多因素认证**: [totp-rs](https://github.com/constantoine/totp-rs) + [qrcode](https://github.com/kennytm/qrcode-rust)
- **速率限制**: 自研高性能内存缓存系统
- **安全组件**: Tower middleware + 自定义安全层

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

### 多因素认证表 (user_mfa)
```sql
DEFINE TABLE user_mfa SCHEMAFULL;
```

字段:
- id: Thing - MFA记录唯一标识符
- user_id: string - 用户ID
- status: string - MFA状态 (Disabled/Pending/Enabled)
- method: string - MFA方法 (Totp/Sms/Email)
- totp_secret: string - TOTP密钥（加密存储）
- backup_codes: array - 备用恢复代码列表
- created_at: datetime - 创建时间
- updated_at: datetime - 更新时间
- last_used_at: datetime - 最后使用时间

### 账户锁定表 (account_lockout)
```sql
DEFINE TABLE account_lockout SCHEMAFULL;
```

字段:
- id: Thing - 锁定记录唯一标识符
- identifier: string - 标识符（用户ID或IP地址）
- lockout_type: string - 锁定类型 (User/IpAddress)
- failed_attempts: number - 失败尝试次数
- status: string - 锁定状态 (Normal/Locked/TemporaryLocked)
- locked_at: datetime - 锁定开始时间
- locked_until: datetime - 锁定结束时间
- last_attempt_at: datetime - 最后尝试时间
- created_at: datetime - 创建时间
- updated_at: datetime - 更新时间

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

### 多因素认证 (MFA) 🔐
- `POST /api/auth/mfa/setup-totp` - 初始化TOTP设置（获取QR码）
- `POST /api/auth/mfa/enable-totp` - 启用TOTP（验证初始代码）
- `POST /api/auth/mfa/verify-totp` - 验证TOTP代码
- `POST /api/auth/mfa/use-backup-code` - 使用备用恢复代码
- `POST /api/auth/mfa/disable` - 禁用MFA
- `GET /api/auth/mfa/status` - 获取MFA状态

### 安全管理 🛡️
- `GET /api/auth/security/lockout-status` - 查看账户锁定状态
- `POST /api/auth/security/unlock-account` - 管理员解锁账户
- `GET /api/auth/security/rate-limit-status` - 查看速率限制状态

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

### MFA (多因素认证) 示例

#### 设置TOTP
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/mfa/setup-totp \
  -H "Authorization: Bearer your-jwt-token"

# 成功响应 (200 OK)
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAwIiBoZWlnaHQ9IjIwMCI+Li4uPC9zdmc+",
  "backup_codes": [
    "ABCD1234", "EFGH5678", "IJKL9012", "MNOP3456",
    "QRST7890", "UVWX1234", "YZAB5678", "CDEF9012"
  ]
}
```

#### 启用TOTP
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/mfa/enable-totp \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "totp_code": "123456"
  }'

# 成功响应 (200 OK)
{
  "success": true,
  "message": "TOTP enabled successfully"
}
```

#### 验证TOTP
```bash
# 请求
curl -X POST http://localhost:8080/api/auth/mfa/verify-totp \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "totp_code": "654321"
  }'

# 成功响应 (200 OK)
{
  "verified": true,
  "message": "TOTP verification successful"
}
```

### 安全状态检查示例

#### 检查账户锁定状态
```bash
# 请求
curl http://localhost:8080/api/auth/security/lockout-status \
  -H "Authorization: Bearer your-jwt-token"

# 正常状态响应 (200 OK)
{
  "is_locked": false,
  "remaining_attempts": 3,
  "message": "Account is not locked"
}

# 锁定状态响应 (423 Locked)
{
  "is_locked": true,
  "remaining_attempts": 0,
  "remaining_lockout_seconds": 890,
  "message": "Account locked. Try again in 14 minutes."
}
```

### 安全错误响应示例

#### 速率限制超出
```json
# 429 Too Many Requests
{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Please try again later.",
  "code": "RATE_LIMIT_EXCEEDED"
}
```

#### 账户锁定
```json
# 423 Locked
{
  "error": "Account locked",
  "message": "Account locked due to multiple failed attempts. Try again in 15 minutes.",
  "locked_until_seconds": 900
}
```

## 安全特性

### 🛡️ 安全防护层（核心安全系统）

#### 速率限制 (Rate Limiting)
- **智能频率控制**: 基于IP和端点的多维度限制
- **自适应规则**: 登录(5次/5分钟)、注册(3次/5分钟)、密码重置(3次/15分钟)
- **内存高效**: 自研缓存系统，定期清理过期记录
- **实时响应**: 毫秒级检查，不影响用户体验
- **防护范围**: 覆盖所有认证相关端点

#### 多因素认证 (MFA)
- **TOTP支持**: 完全兼容Google Authenticator等认证器
- **QR码生成**: SVG格式，支持多种显示方式
- **备用恢复**: 8个一次性使用的恢复代码
- **安全密钥**: Base32编码，20字节强随机密钥
- **生命周期管理**: 设置→验证→启用→使用→禁用完整流程

#### 账户锁定机制
- **多维度保护**: 用户账户 + IP地址双重锁定
- **智能锁定**: 5次失败尝试后锁定15分钟
- **自动解锁**: 时间到期自动解除锁定
- **防暴力破解**: 有效防止密码暴力破解攻击
- **灵活配置**: 可调整尝试次数、锁定时长等参数

#### 安全管理
- **异步处理**: 安全检查不阻塞正常请求流程
- **定期清理**: 每小时自动清理过期安全记录
- **详细日志**: 完整的安全事件记录和追踪
- **状态监控**: 实时安全状态查询接口
- **管理接口**: 支持管理员手动解锁等操作

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

### 🎉 第一阶段：安全防护层 ✅ (已完成)
- [x] **速率限制系统**: 智能API频率控制，防暴力破解
- [x] **多因素认证**: 完整TOTP/Google Authenticator支持
- [x] **账户锁定机制**: 多维度安全保护，自动锁定解锁
- [x] **安全基础设施**: 实时监控、异步处理、定期清理
- [x] **密码重置功能**: 安全的重置流程
- [x] **会话管理系统**: 完整的会话生命周期管理
- [x] **安全漏洞修复**: JWT密钥管理、敏感信息保护
- [x] **邮箱验证流程**: 强制验证优化

### 📋 第二阶段：权限系统 (规划中)
- [ ] 添加用户角色和权限管理 (RBAC)
- [ ] 实现基于资源的访问控制
- [ ] 组织和团队管理功能
- [ ] 权限继承和委派机制
- [ ] 细粒度权限控制

### 📋 第三阶段：用户管理 (规划中)
- [ ] 完善的用户生命周期管理
- [ ] 用户资料管理和更新
- [ ] 账户删除和数据清理
- [ ] 用户偏好设置
- [ ] 头像和个人信息管理

### 📋 第四阶段：监控审计 (规划中)
- [x] **基础安全日志**: 速率限制、账户锁定、MFA事件记录 ✅
- [x] **登录历史追踪**: IP地址、设备信息记录 ✅  
- [ ] 高级审计日志和监控仪表板
- [ ] 安全事件实时告警系统
- [ ] 深度用户行为分析
- [ ] 安全报告和统计图表

### 📋 未来增强功能
- [x] **设备指纹识别**: 基础IP和设备信息追踪 ✅
- [ ] 添加更多OAuth提供商支持 (Apple, Microsoft, Twitter等)
- [ ] 实现账号关联功能（多个OAuth账号关联）
- [ ] 密码复杂度策略和安全建议
- [ ] 高级设备指纹识别和异常检测
- [ ] API密钥管理
- [ ] SSO单点登录支持
- [ ] SAML协议支持

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
