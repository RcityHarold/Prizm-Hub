use std::fmt::Debug;
use std::time::Duration;
use surrealdb::engine::remote::http::{Client, Http};
use surrealdb::opt::auth::Root;
use surrealdb::sql::Thing;
use surrealdb::{Surreal, Response};
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::{config::Config, error::{Result, AuthError}};

#[derive(Clone)]
pub struct Database {
    pub client: Surreal<Client>,
}

impl Database {
    pub async fn new(config: &Config) -> Result<Self> {
        let mut retry_count = 0;
        let max_retries = 5;
        let retry_delay = Duration::from_secs(1);

        loop {
            match Self::try_connect(config).await {
                Ok(db) => return Ok(db),
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        return Err(e);
                    }
                    warn!("Failed to connect to database (attempt {}/{}): {}", retry_count, max_retries, e);
                    sleep(retry_delay).await;
                }
            }
        }
    }

    async fn try_connect(config: &Config) -> Result<Self> {
        debug!("Connecting to database");
        
        // 设置连接超时
        let client = tokio::time::timeout(
            Duration::from_secs(config.database_connection_timeout),
            Surreal::<Client>::new::<Http>(&config.database_url)
        ).await
        .map_err(|_| AuthError::DatabaseError("Database connection timeout".to_string()))?
        .map_err(|e| AuthError::DatabaseError(format!("Failed to connect: {}", e)))?;
            
        debug!("Authenticating with database");
        tokio::time::timeout(
            Duration::from_secs(config.database_connection_timeout),
            client.signin(Root {
                username: &config.database_user,
                password: &config.database_pass,
            })
        ).await
        .map_err(|_| AuthError::DatabaseError("Database authentication timeout".to_string()))?
        .map_err(|e| AuthError::DatabaseError(format!("Failed to authenticate: {}", e)))?;
        
        debug!("Selecting namespace and database");
        client.use_ns("test").use_db("test").await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to select namespace/database: {}", e)))?;
        
        debug!("Database connection established successfully");
        Ok(Database { client })
    }

    pub async fn initialize_schema(&self) -> Result<()> {
        // 检查表是否存在的函数
        async fn table_exists(db: &Database, table_name: &str) -> Result<bool> {
            let sql = format!(
                "SELECT name FROM information_schema.tables WHERE name = '{}'",
                table_name
            );
            let mut result = db.client.query(sql).await?;
            let exists: Vec<serde_json::Value> = result.take(0)
                .map_err(|_| AuthError::DatabaseError("Failed to check table existence".into()))?;
            Ok(!exists.is_empty())
        }

        // 用户表
        if !table_exists(self, "user").await? {
            let user_table = r#"
                DEFINE TABLE user SCHEMAFULL;
                DEFINE FIELD email ON user TYPE string;
                DEFINE FIELD password ON user TYPE option<string>;
                DEFINE FIELD verified ON user TYPE bool;
                DEFINE FIELD verification_token ON user TYPE option<string>;
                DEFINE FIELD created_at ON user TYPE number;
                DEFINE FIELD updated_at ON user TYPE number;
                DEFINE INDEX email_idx ON user COLUMNS email UNIQUE;
            "#;
            self.client.query(user_table).await?;
        } else {
            // 更新现有表的 schema
            let update_user_table = r#"
                DEFINE FIELD password ON user TYPE option<string>;
                DEFINE FIELD verification_token ON user TYPE option<string>;
            "#;
            self.client.query(update_user_table).await?;
        }

        // 身份提供商表
        if !table_exists(self, "identity_provider").await? {
            let identity_provider = r#"
                DEFINE TABLE identity_provider SCHEMAFULL;
                DEFINE FIELD provider ON identity_provider TYPE string;
                DEFINE FIELD provider_user_id ON identity_provider TYPE string;
                DEFINE FIELD user_id ON identity_provider TYPE record(user);
                DEFINE FIELD created_at ON identity_provider TYPE number;
                DEFINE FIELD updated_at ON identity_provider TYPE number;
                DEFINE INDEX provider_idx ON identity_provider COLUMNS provider, provider_user_id UNIQUE;
            "#;
            self.client.query(identity_provider).await?;
        }

        // 会话表
        if !table_exists(self, "session").await? {
            let session = r#"
                DEFINE TABLE session SCHEMAFULL;
                DEFINE FIELD user_id ON session TYPE record(user);
                DEFINE FIELD token ON session TYPE string;
                DEFINE FIELD expires_at ON session TYPE number;
                DEFINE FIELD created_at ON session TYPE number;
                DEFINE FIELD user_agent ON session TYPE string;
                DEFINE FIELD ip_address ON session TYPE string;
                DEFINE INDEX token_idx ON session COLUMNS token UNIQUE;
            "#;
            self.client.query(session).await?;
        }

        // 密码重置令牌表
        if !table_exists(self, "password_reset_token").await? {
            let password_reset_token = r#"
                DEFINE TABLE password_reset_token SCHEMAFULL;
                DEFINE FIELD email ON password_reset_token TYPE string;
                DEFINE FIELD token ON password_reset_token TYPE string;
                DEFINE FIELD expires_at ON password_reset_token TYPE datetime;
                DEFINE FIELD used ON password_reset_token TYPE bool;
                DEFINE FIELD created_at ON password_reset_token TYPE datetime;
                DEFINE INDEX reset_token_idx ON password_reset_token COLUMNS token UNIQUE;
                DEFINE INDEX reset_email_idx ON password_reset_token COLUMNS email;
            "#;
            self.client.query(password_reset_token).await?;
        }

        // 多因素认证表
        if !table_exists(self, "user_mfa").await? {
            let user_mfa = r#"
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
            "#;
            self.client.query(user_mfa).await?;
        }

        // 账户锁定表
        if !table_exists(self, "account_lockout").await? {
            let account_lockout = r#"
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
            "#;
            self.client.query(account_lockout).await?;
        }

        // 角色表
        if !table_exists(self, "role").await? {
            let role = r#"
                DEFINE TABLE role SCHEMAFULL;
                DEFINE FIELD name ON role TYPE string;
                DEFINE FIELD display_name ON role TYPE string;
                DEFINE FIELD description ON role TYPE option<string>;
                DEFINE FIELD is_system ON role TYPE bool;
                DEFINE FIELD created_at ON role TYPE number;
                DEFINE FIELD updated_at ON role TYPE number;
                DEFINE INDEX role_name_idx ON role COLUMNS name UNIQUE;
            "#;
            self.client.query(role).await?;
        }

        // 权限表
        if !table_exists(self, "permission").await? {
            let permission = r#"
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
            "#;
            self.client.query(permission).await?;
        }

        // 用户角色关联表
        if !table_exists(self, "user_role").await? {
            let user_role = r#"
                DEFINE TABLE user_role SCHEMAFULL;
                DEFINE FIELD user_id ON user_role TYPE record(user);
                DEFINE FIELD role_id ON user_role TYPE record(role);
                DEFINE FIELD assigned_at ON user_role TYPE number;
                DEFINE FIELD assigned_by ON user_role TYPE record(user);
                DEFINE INDEX user_role_unique_idx ON user_role COLUMNS user_id, role_id UNIQUE;
                DEFINE INDEX user_role_user_idx ON user_role COLUMNS user_id;
                DEFINE INDEX user_role_role_idx ON user_role COLUMNS role_id;
            "#;
            self.client.query(user_role).await?;
        }

        // 角色权限关联表
        if !table_exists(self, "role_permission").await? {
            let role_permission = r#"
                DEFINE TABLE role_permission SCHEMAFULL;
                DEFINE FIELD role_id ON role_permission TYPE record(role);
                DEFINE FIELD permission_id ON role_permission TYPE record(permission);
                DEFINE FIELD granted_at ON role_permission TYPE number;
                DEFINE FIELD granted_by ON role_permission TYPE record(user);
                DEFINE INDEX role_permission_unique_idx ON role_permission COLUMNS role_id, permission_id UNIQUE;
                DEFINE INDEX role_permission_role_idx ON role_permission COLUMNS role_id;
                DEFINE INDEX role_permission_permission_idx ON role_permission COLUMNS permission_id;
            "#;
            self.client.query(role_permission).await?;
        }

        Ok(())
    }

    pub async fn create_record<T>(&self, table: &str, record: &T) -> Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + Debug,
    {
        debug!("Creating record in table {}: {:?}", table, record);
        
        let created: Vec<T> = self.client
            .create(table)
            .content(record)
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to create record: {}", e)))?;
            
        created.into_iter()
            .next()
            .ok_or_else(|| AuthError::DatabaseError("Failed to create record".into()))
    }

    pub async fn find_record_by_field<T>(&self, table: &str, field: &str, value: &str) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned + Clone + Debug,
    {
        debug!("Finding record in table {} where {} = {}", table, field, value);
        
        let query = if field == "id" {
            format!("SELECT * FROM {} WHERE id = type::thing($value)", table)
        } else {
            format!("SELECT * FROM {} WHERE {} = $value", table, field)
        };

        let mut result = self.client
            .query(&query)
            .bind(("value", value))
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to execute query: {}", e)))?;
        
        let records: Vec<T> = result
            .take(0)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse records: {}", e)))?;
            
        dbg!(&records);
        Ok(records.into_iter().next())
    }

    pub async fn update_record<T>(&self, table: &str, thing: &Thing, record: &T) -> Result<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + Debug,
    {
        debug!("Updating record in table {} with thing {:?}: {:?}", table, thing, record);
        
        let updated = self.client
            .update(thing.clone())
            .content(record)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to update record".into()))?;
            
        updated.ok_or_else(|| AuthError::DatabaseError("Record not found".into()))
    }

    pub async fn delete_record<T>(&self, table: &str, id: &str) -> Result<Option<T>>
    where
        T: serde::de::DeserializeOwned + Clone + Debug,
    {
        debug!("Deleting record from table {} with id {}", table, id);
        
        let thing: Thing = format!("{}:{}", table, id).parse()
            .map_err(|_| AuthError::DatabaseError("Invalid record ID format".into()))?;
            
        let deleted = self.client
            .delete(thing)
            .await
            .map_err(|_| AuthError::DatabaseError("Failed to delete record".into()))?;
            
        Ok(deleted)
    }

    pub async fn delete_session_by_token(&self, token: &str) -> Result<()> {
        let query = "DELETE session WHERE token = $token";
        self.client
            .query(query)
            .bind(("token", token))
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to delete session: {}", e)))?;
        Ok(())
    }

    pub async fn delete_sessions_by_user_id(&self, user_id: &str) -> Result<()> {
        let query = "DELETE session WHERE user_id = type::thing($user_id)";
        self.client
            .query(query)
            .bind(("user_id", format!("user:{}", user_id)))
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to delete sessions: {}", e)))?;
        Ok(())
    }

    pub async fn get_sessions_by_user_id(&self, user_id: &str) -> Result<Vec<crate::models::session::Session>> {
        let query = "SELECT * FROM session WHERE user_id = type::thing($user_id) ORDER BY created_at DESC";
        let mut result = self.client
            .query(query)
            .bind(("user_id", format!("user:{}", user_id)))
            .await
            .map_err(|e| AuthError::DatabaseError(format!("Failed to query sessions: {}", e)))?;
        
        let sessions = result
            .take(0)
            .map_err(|e| AuthError::DatabaseError(format!("Failed to parse sessions: {}", e)))?;
            
        Ok(sessions)
    }

    /// 公开的查询方法，供其他服务使用  
    pub fn query(&self, sql: &str) -> surrealdb::method::Query<'_, Client> {
        self.client.query(sql)
    }
}
