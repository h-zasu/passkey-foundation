//! Configuration management for the Passkey authentication system.
//!
//! This module provides centralized configuration management for AWS services,
//! WebAuthn settings, and application-specific configurations. It handles
//! environment variable loading and provides type-safe configuration objects.

use crate::{AppConfig, PasskeyError};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::str::FromStr;

/// DynamoDB encryption levels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionLevel {
    /// Standard encryption with AWS managed keys
    Standard,
    /// Enterprise encryption with customer managed keys
    Enterprise,
}

impl fmt::Display for EncryptionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionLevel::Standard => write!(f, "standard"),
            EncryptionLevel::Enterprise => write!(f, "enterprise"),
        }
    }
}

impl FromStr for EncryptionLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "standard" => Ok(EncryptionLevel::Standard),
            "enterprise" => Ok(EncryptionLevel::Enterprise),
            _ => Err(format!("Invalid encryption level: {}. Must be 'standard' or 'enterprise'", s)),
        }
    }
}

impl Default for EncryptionLevel {
    fn default() -> Self {
        EncryptionLevel::Standard
    }
}

/// Global service configuration.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Environment name (dev, staging, prod)
    pub environment: String,
    /// DynamoDB table prefix
    pub table_prefix: String,
    /// CORS allowed origins
    pub cors_origins: Vec<String>,
    /// Default JWT expiration (seconds)
    pub default_jwt_expires_in: u64,
    /// Default session timeout (seconds)
    pub default_session_timeout: u64,
    /// Default OTP expiration (seconds)
    pub default_otp_expires_in: u64,
    /// DynamoDB encryption level
    pub encryption_level: EncryptionLevel,
    /// KMS key ARN for Enterprise encryption (optional)
    pub kms_key_arn: Option<String>,
}

impl ServiceConfig {
    /// Loads configuration from environment variables.
    pub fn from_env() -> Result<Self, PasskeyError> {
        let encryption_level = env::var("ENCRYPTION_LEVEL")
            .unwrap_or_else(|_| "standard".to_string())
            .parse()
            .map_err(|e: String| PasskeyError::ConfigError(e))?;
        
        let kms_key_arn = env::var("KMS_KEY_ARN").ok()
            .filter(|s| !s.trim().is_empty());

        // Validate KMS key ARN if encryption level is Enterprise
        if matches!(encryption_level, EncryptionLevel::Enterprise) && kms_key_arn.is_none() {
            return Err(PasskeyError::ConfigError(
                "KMS_KEY_ARN is required when ENCRYPTION_LEVEL is 'enterprise'".to_string()
            ));
        }

        Ok(Self {
            environment: env::var("ENVIRONMENT").unwrap_or_else(|_| "dev".to_string()),
            table_prefix: env::var("TABLE_PREFIX").unwrap_or_else(|_| "passkey".to_string()),
            cors_origins: env::var("CORS_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:3000".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            default_jwt_expires_in: env::var("DEFAULT_JWT_EXPIRES_IN")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .map_err(|_| {
                    PasskeyError::Configuration("Invalid DEFAULT_JWT_EXPIRES_IN".to_string())
                })?,
            default_session_timeout: env::var("DEFAULT_SESSION_TIMEOUT")
                .unwrap_or_else(|_| "300".to_string())
                .parse()
                .map_err(|_| {
                    PasskeyError::ConfigError("Invalid DEFAULT_SESSION_TIMEOUT".to_string())
                })?,
            default_otp_expires_in: env::var("DEFAULT_OTP_EXPIRES_IN")
                .unwrap_or_else(|_| "1800".to_string())
                .parse()
                .map_err(|_| {
                    PasskeyError::ConfigError("Invalid DEFAULT_OTP_EXPIRES_IN".to_string())
                })?,
            encryption_level,
            kms_key_arn,
        })
    }

    /// Gets the full table name for a given table type.
    pub fn table_name(&self, table_type: &str) -> String {
        format!("{}-{}-{}", self.table_prefix, table_type, self.environment)
    }

    /// Validates encryption configuration.
    pub fn validate_encryption_config(&self) -> Result<(), PasskeyError> {
        if matches!(self.encryption_level, EncryptionLevel::Enterprise) && self.kms_key_arn.is_none() {
            return Err(PasskeyError::ConfigError(
                "KMS key ARN is required for Enterprise encryption level".to_string()
            ));
        }
        Ok(())
    }

    /// Returns true if customer managed keys should be used for encryption.
    pub fn uses_customer_managed_keys(&self) -> bool {
        matches!(self.encryption_level, EncryptionLevel::Enterprise)
    }
}

/// AWS client configuration and initialization.
#[derive(Debug, Clone)]
pub struct AwsConfig {
    /// DynamoDB client
    pub dynamodb: aws_sdk_dynamodb::Client,
    /// SES client
    pub ses: aws_sdk_ses::Client,
    /// AWS configuration
    pub config: aws_config::SdkConfig,
}

impl AwsConfig {
    /// Creates a new AWS configuration with initialized clients using AWS standard configuration resolution.
    pub async fn new() -> Result<Self, PasskeyError> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;

        let dynamodb = aws_sdk_dynamodb::Client::new(&config);
        let ses = aws_sdk_ses::Client::new(&config);

        Ok(Self {
            dynamodb,
            ses,
            config,
        })
    }

    /// Creates a test AWS configuration for local development and testing.
    /// This method attempts to create AWS clients but falls back gracefully if AWS is not configured.
    #[cfg(test)]
    pub async fn local_test() -> Result<Self, PasskeyError> {
        // For local tests, we'll create a basic config that may or may not work
        // depending on whether AWS credentials are available
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .load()
            .await;

        let dynamodb = aws_sdk_dynamodb::Client::new(&config);
        let ses = aws_sdk_ses::Client::new(&config);

        Ok(Self {
            dynamodb,
            ses,
            config,
        })
    }
}

/// WebAuthn configuration manager.
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    /// Cache of WebAuthn instances per app
    instances: HashMap<String, webauthn_rs::Webauthn>,
}

impl WebAuthnConfig {
    /// Creates a new WebAuthn configuration manager.
    pub fn new() -> Self {
        Self {
            instances: HashMap::new(),
        }
    }

    /// Gets or creates a WebAuthn instance for the given app configuration.
    pub fn get_or_create_instance(
        &mut self,
        app_config: &AppConfig,
    ) -> Result<&webauthn_rs::Webauthn, PasskeyError> {
        if !self.instances.contains_key(&app_config.app_id) {
            let webauthn = create_webauthn_instance(app_config)?;
            self.instances.insert(app_config.app_id.clone(), webauthn);
        }

        Ok(self.instances.get(&app_config.app_id).unwrap())
    }

    /// Removes a WebAuthn instance from cache.
    pub fn remove_instance(&mut self, app_id: &str) {
        self.instances.remove(app_id);
    }

    /// Clears all cached instances.
    pub fn clear_cache(&mut self) {
        self.instances.clear();
    }
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Creates a WebAuthn instance for the given application configuration.
fn create_webauthn_instance(app_config: &AppConfig) -> Result<webauthn_rs::Webauthn, PasskeyError> {
    use webauthn_rs::WebauthnBuilder;

    // Parse the first allowed origin for WebAuthn configuration
    let origin_url = app_config
        .allowed_origins
        .first()
        .ok_or_else(|| PasskeyError::ConfigError("No allowed origins configured".to_string()))?;

    let url = url::Url::parse(origin_url)
        .map_err(|e| PasskeyError::ConfigError(format!("Invalid origin URL: {e}")))?;

    WebauthnBuilder::new(&app_config.relying_party_id, &url)
        .map_err(|e| PasskeyError::WebAuthn(format!("WebAuthn builder error: {e:?}")))?
        .rp_name(&app_config.relying_party_name)
        .build()
        .map_err(|e| PasskeyError::WebAuthn(format!("WebAuthn build error: {e:?}")))
}

/// Application configuration cache manager.
#[derive(Debug, Clone)]
pub struct AppConfigCache {
    /// Cached configurations
    cache: HashMap<String, AppConfig>,
}

impl AppConfigCache {
    /// Creates a new app configuration cache.
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Gets a configuration from cache.
    pub fn get(&self, app_id: &str) -> Option<&AppConfig> {
        self.cache.get(app_id)
    }

    /// Inserts a configuration into cache.
    pub fn insert(&mut self, app_config: AppConfig) {
        self.cache.insert(app_config.app_id.clone(), app_config);
    }

    /// Removes a configuration from cache.
    pub fn remove(&mut self, app_id: &str) -> Option<AppConfig> {
        self.cache.remove(app_id)
    }

    /// Clears all cached configurations.
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Gets all cached app IDs.
    pub fn app_ids(&self) -> Vec<String> {
        self.cache.keys().cloned().collect()
    }
}

impl Default for AppConfigCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_config_table_name() {
        let config = ServiceConfig {
            environment: "test".to_string(),
            table_prefix: "passkey".to_string(),
            cors_origins: vec!["http://localhost:3000".to_string()],
            default_jwt_expires_in: 3600,
            default_session_timeout: 300,
            default_otp_expires_in: 1800,
            encryption_level: EncryptionLevel::Standard,
            kms_key_arn: None,
        };

        assert_eq!(config.table_name("users"), "passkey-users-test");
        assert_eq!(config.table_name("sessions"), "passkey-sessions-test");
    }

    #[test]
    fn test_app_config_cache() {
        let mut cache = AppConfigCache::new();

        let app_config = AppConfig::default_dev("testapp".to_string());
        cache.insert(app_config.clone());

        assert!(cache.get("testapp").is_some());
        assert!(cache.get("nonexistent").is_none());

        cache.remove("testapp");
        assert!(cache.get("testapp").is_none());
    }

    #[test]
    fn test_app_config_cache_operations() {
        let mut cache = AppConfigCache::new();

        // Test empty cache
        assert!(cache.get("test").is_none());
        assert_eq!(cache.app_ids().len(), 0);

        // Insert multiple configs
        let config1 = AppConfig::default_dev("app1".to_string());
        let config2 = AppConfig::default_dev("app2".to_string());

        cache.insert(config1.clone());
        cache.insert(config2.clone());

        assert_eq!(cache.app_ids().len(), 2);
        assert!(cache.app_ids().contains(&"app1".to_string()));
        assert!(cache.app_ids().contains(&"app2".to_string()));

        // Test clear
        cache.clear();
        assert_eq!(cache.app_ids().len(), 0);
        assert!(cache.get("app1").is_none());
    }

    #[test]
    fn test_webauthn_config_new() {
        let config = WebAuthnConfig::new();
        // Test that new creates empty cache
        assert_eq!(config.instances.len(), 0);
    }

    #[test]
    fn test_webauthn_config_default() {
        let config = WebAuthnConfig::default();
        assert_eq!(config.instances.len(), 0);
    }

    #[test]
    fn test_webauthn_config_cache_operations() {
        let mut config = WebAuthnConfig::new();

        // Test remove from empty cache
        config.remove_instance("nonexistent");

        // Test clear empty cache
        config.clear_cache();
        assert_eq!(config.instances.len(), 0);
    }

    #[test]
    fn test_service_config_from_env_defaults() {
        // Test that ServiceConfig::from_env() works with default values
        // Note: This test doesn't clear environment variables to avoid test isolation issues
        let config = ServiceConfig::from_env().unwrap();

        // Just test that the config is created successfully with some reasonable values
        assert!(!config.environment.is_empty());
        assert!(!config.table_prefix.is_empty());
        assert!(!config.cors_origins.is_empty());
        assert!(config.default_jwt_expires_in > 0);
        assert!(config.default_session_timeout > 0);
        assert!(config.default_otp_expires_in > 0);
    }

    #[test]
    fn test_service_config_table_name_with_prefix() {
        // Test table_name function without environment variable manipulation
        let config = ServiceConfig {
            environment: "test".to_string(),
            table_prefix: "custom".to_string(),
            cors_origins: vec!["http://localhost:3000".to_string()],
            default_jwt_expires_in: 7200,
            default_session_timeout: 600,
            default_otp_expires_in: 3600,
            encryption_level: EncryptionLevel::Standard,
            kms_key_arn: None,
        };

        assert_eq!(config.table_name("users"), "custom-users-test");
        assert_eq!(config.table_name("sessions"), "custom-sessions-test");
        assert_eq!(config.environment, "test");
        assert_eq!(config.default_jwt_expires_in, 7200);
        assert_eq!(config.default_session_timeout, 600);
        assert_eq!(config.default_otp_expires_in, 3600);
    }

    #[test]
    fn test_service_config_cors_parsing() {
        // Test CORS origins parsing without environment manipulation
        let config = ServiceConfig {
            environment: "test".to_string(),
            table_prefix: "passkey".to_string(),
            cors_origins: vec![
                "https://app1.com".to_string(),
                "https://app2.com".to_string(),
            ],
            default_jwt_expires_in: 3600,
            default_session_timeout: 300,
            default_otp_expires_in: 1800,
            encryption_level: EncryptionLevel::Standard,
            kms_key_arn: None,
        };

        assert_eq!(config.cors_origins.len(), 2);
        assert!(
            config
                .cors_origins
                .contains(&"https://app1.com".to_string())
        );
        assert!(
            config
                .cors_origins
                .contains(&"https://app2.com".to_string())
        );
    }

    #[test]
    fn test_encryption_level_display() {
        assert_eq!(EncryptionLevel::Standard.to_string(), "standard");
        assert_eq!(EncryptionLevel::Enterprise.to_string(), "enterprise");
    }

    #[test]
    fn test_encryption_level_from_str() {
        assert_eq!("standard".parse::<EncryptionLevel>().unwrap(), EncryptionLevel::Standard);
        assert_eq!("enterprise".parse::<EncryptionLevel>().unwrap(), EncryptionLevel::Enterprise);
        assert_eq!("STANDARD".parse::<EncryptionLevel>().unwrap(), EncryptionLevel::Standard);
        assert_eq!("ENTERPRISE".parse::<EncryptionLevel>().unwrap(), EncryptionLevel::Enterprise);
        
        assert!("invalid".parse::<EncryptionLevel>().is_err());
    }

    #[test]
    fn test_encryption_level_default() {
        assert_eq!(EncryptionLevel::default(), EncryptionLevel::Standard);
    }

    #[test]
    fn test_service_config_encryption_validation() {
        // Standard encryption should always be valid
        let standard_config = ServiceConfig {
            environment: "test".to_string(),
            table_prefix: "passkey".to_string(),
            cors_origins: vec!["http://localhost:3000".to_string()],
            default_jwt_expires_in: 3600,
            default_session_timeout: 300,
            default_otp_expires_in: 1800,
            encryption_level: EncryptionLevel::Standard,
            kms_key_arn: None,
        };
        
        assert!(standard_config.validate_encryption_config().is_ok());
        assert!(!standard_config.uses_customer_managed_keys());

        // Enterprise encryption without KMS key should fail
        let enterprise_no_key_config = ServiceConfig {
            encryption_level: EncryptionLevel::Enterprise,
            kms_key_arn: None,
            ..standard_config.clone()
        };
        
        assert!(enterprise_no_key_config.validate_encryption_config().is_err());
        assert!(enterprise_no_key_config.uses_customer_managed_keys());

        // Enterprise encryption with KMS key should succeed
        let enterprise_with_key_config = ServiceConfig {
            encryption_level: EncryptionLevel::Enterprise,
            kms_key_arn: Some("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012".to_string()),
            ..standard_config
        };
        
        assert!(enterprise_with_key_config.validate_encryption_config().is_ok());
        assert!(enterprise_with_key_config.uses_customer_managed_keys());
    }
}
