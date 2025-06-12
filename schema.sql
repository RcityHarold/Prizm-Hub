-- Rust Auth System Database Schema
-- 运行此文件以创建所有必需的数据库表和索引

-- 用户表
DEFINE TABLE user SCHEMAFULL;
DEFINE FIELD email ON user TYPE string;
DEFINE FIELD password ON user TYPE option<string>;
DEFINE FIELD verified ON user TYPE bool;
DEFINE FIELD verification_token ON user TYPE option<string>;
DEFINE FIELD created_at ON user TYPE number;
DEFINE FIELD updated_at ON user TYPE number;
DEFINE INDEX email_idx ON user COLUMNS email UNIQUE;

-- 身份提供商表
DEFINE TABLE identity_provider SCHEMAFULL;
DEFINE FIELD provider ON identity_provider TYPE string;
DEFINE FIELD provider_user_id ON identity_provider TYPE string;
DEFINE FIELD user_id ON identity_provider TYPE record(user);
DEFINE FIELD created_at ON identity_provider TYPE number;
DEFINE FIELD updated_at ON identity_provider TYPE number;
DEFINE INDEX provider_idx ON identity_provider COLUMNS provider, provider_user_id UNIQUE;

-- 会话表
DEFINE TABLE session SCHEMAFULL;
DEFINE FIELD user_id ON session TYPE record(user);
DEFINE FIELD token ON session TYPE string;
DEFINE FIELD expires_at ON session TYPE number;
DEFINE FIELD created_at ON session TYPE number;
DEFINE FIELD user_agent ON session TYPE string;
DEFINE FIELD ip_address ON session TYPE string;
DEFINE INDEX token_idx ON session COLUMNS token UNIQUE;

-- 密码重置令牌表
DEFINE TABLE password_reset_token SCHEMAFULL;
DEFINE FIELD email ON password_reset_token TYPE string;
DEFINE FIELD token ON password_reset_token TYPE string;
DEFINE FIELD expires_at ON password_reset_token TYPE datetime;
DEFINE FIELD used ON password_reset_token TYPE bool;
DEFINE FIELD created_at ON password_reset_token TYPE datetime;
DEFINE INDEX reset_token_idx ON password_reset_token COLUMNS token UNIQUE;
DEFINE INDEX reset_email_idx ON password_reset_token COLUMNS email;

-- 多因素认证表
DEFINE TABLE user_mfa SCHEMAFULL;
DEFINE FIELD user_id ON user_mfa TYPE string;
DEFINE FIELD status ON user_mfa TYPE string;
DEFINE FIELD method ON user_mfa TYPE string;
DEFINE FIELD totp_secret ON user_mfa TYPE string;
DEFINE FIELD backup_codes ON user_mfa TYPE array;
DEFINE FIELD created_at ON user_mfa TYPE datetime;
DEFINE FIELD updated_at ON user_mfa TYPE datetime;
DEFINE FIELD last_used_at ON user_mfa TYPE option<datetime>;
DEFINE INDEX user_mfa_user_idx ON user_mfa COLUMNS user_id UNIQUE;

-- 账户锁定表
DEFINE TABLE account_lockout SCHEMAFULL;
DEFINE FIELD identifier ON account_lockout TYPE string;
DEFINE FIELD lockout_type ON account_lockout TYPE string;
DEFINE FIELD failed_attempts ON account_lockout TYPE number;
DEFINE FIELD status ON account_lockout TYPE string;
DEFINE FIELD locked_at ON account_lockout TYPE option<datetime>;
DEFINE FIELD locked_until ON account_lockout TYPE option<datetime>;
DEFINE FIELD last_attempt_at ON account_lockout TYPE option<datetime>;
DEFINE FIELD created_at ON account_lockout TYPE datetime;
DEFINE FIELD updated_at ON account_lockout TYPE datetime;
DEFINE INDEX lockout_identifier_idx ON account_lockout COLUMNS identifier, lockout_type UNIQUE;

-- 角色表
DEFINE TABLE role SCHEMAFULL;
DEFINE FIELD name ON role TYPE string;
DEFINE FIELD display_name ON role TYPE string;
DEFINE FIELD description ON role TYPE option<string>;
DEFINE FIELD is_system ON role TYPE bool;
DEFINE FIELD created_at ON role TYPE number;
DEFINE FIELD updated_at ON role TYPE number;
DEFINE INDEX role_name_idx ON role COLUMNS name UNIQUE;

-- 权限表
DEFINE TABLE permission SCHEMAFULL;
DEFINE FIELD name ON permission TYPE string;
DEFINE FIELD display_name ON permission TYPE string;
DEFINE FIELD description ON permission TYPE option<string>;
DEFINE FIELD resource ON permission TYPE string;
DEFINE FIELD action ON permission TYPE string;
DEFINE FIELD is_system ON permission TYPE bool;
DEFINE FIELD created_at ON permission TYPE number;
DEFINE FIELD updated_at ON permission TYPE number;
DEFINE INDEX permission_name_idx ON permission COLUMNS name UNIQUE;
DEFINE INDEX permission_resource_action_idx ON permission COLUMNS resource, action;

-- 用户角色关联表
DEFINE TABLE user_role SCHEMAFULL;
DEFINE FIELD user_id ON user_role TYPE record(user);
DEFINE FIELD role_id ON user_role TYPE record(role);
DEFINE FIELD assigned_at ON user_role TYPE number;
DEFINE FIELD assigned_by ON user_role TYPE record(user);
DEFINE INDEX user_role_unique_idx ON user_role COLUMNS user_id, role_id UNIQUE;
DEFINE INDEX user_role_user_idx ON user_role COLUMNS user_id;
DEFINE INDEX user_role_role_idx ON user_role COLUMNS role_id;

-- 角色权限关联表
DEFINE TABLE role_permission SCHEMAFULL;
DEFINE FIELD role_id ON role_permission TYPE record(role);
DEFINE FIELD permission_id ON role_permission TYPE record(permission);
DEFINE FIELD granted_at ON role_permission TYPE number;
DEFINE FIELD granted_by ON role_permission TYPE record(user);
DEFINE INDEX role_permission_unique_idx ON role_permission COLUMNS role_id, permission_id UNIQUE;
DEFINE INDEX role_permission_role_idx ON role_permission COLUMNS role_id;
DEFINE INDEX role_permission_permission_idx ON role_permission COLUMNS permission_id;