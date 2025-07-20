//! Configuration management for the Passkey authentication system.
//!
//! This module provides centralized configuration management for AWS services,
//! WebAuthn settings, and application-specific configurations. It handles
//! environment variable loading and provides type-safe configuration objects.

use crate::{AppConfig, PasskeyError};
use std::collections::HashMap;
use std::env;

/// Global service configuration.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// AWS region
    pub aws_region: String,
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
}

impl ServiceConfig {
    /// Loads configuration from environment variables.
    pub fn from_env() -> Result<Self, PasskeyError> {
        Ok(Self {
            aws_region: env::var("AWS_REGION").unwrap_or_else(|_| "us-west-2".to_string()),
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
                    PasskeyError::ConfigError("Invalid DEFAULT_JWT_EXPIRES_IN".to_string())
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
        })
    }

    /// Gets the full table name for a given table type.
    pub fn table_name(&self, table_type: &str) -> String {
        format!("{}-{}-{}", self.table_prefix, table_type, self.environment)
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
    /// Creates a new AWS configuration with initialized clients.
    pub async fn new(region: &str) -> Result<Self, PasskeyError> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
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
            aws_region: "us-west-2".to_string(),
            environment: "test".to_string(),
            table_prefix: "passkey".to_string(),
            cors_origins: vec!["http://localhost:3000".to_string()],
            default_jwt_expires_in: 3600,
            default_session_timeout: 300,
            default_otp_expires_in: 1800,
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
        assert!(!config.aws_region.is_empty());
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
            aws_region: "us-west-2".to_string(),
            environment: "test".to_string(),
            table_prefix: "custom".to_string(),
            cors_origins: vec!["http://localhost:3000".to_string()],
            default_jwt_expires_in: 7200,
            default_session_timeout: 600,
            default_otp_expires_in: 3600,
        };

        assert_eq!(config.table_name("users"), "custom-users-test");
        assert_eq!(config.table_name("sessions"), "custom-sessions-test");
        assert_eq!(config.aws_region, "us-west-2");
        assert_eq!(config.environment, "test");
        assert_eq!(config.default_jwt_expires_in, 7200);
        assert_eq!(config.default_session_timeout, 600);
        assert_eq!(config.default_otp_expires_in, 3600);
    }

    #[test]
    fn test_service_config_cors_parsing() {
        // Test CORS origins parsing without environment manipulation
        let config = ServiceConfig {
            aws_region: "us-west-2".to_string(),
            environment: "test".to_string(),
            table_prefix: "passkey".to_string(),
            cors_origins: vec![
                "https://app1.com".to_string(),
                "https://app2.com".to_string(),
            ],
            default_jwt_expires_in: 3600,
            default_session_timeout: 300,
            default_otp_expires_in: 1800,
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
}
