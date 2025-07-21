//! GraphQL context for the Passkey authentication system
//!
//! This module provides the GraphQL context that holds AWS clients,
//! service configuration, and shared state for GraphQL resolvers.

use std::collections::HashMap;
use std::sync::Arc;

use shared::{
    AppConfig, AppConfigCache, AwsConfig, EmailService, JwtService, OtpService, ServiceConfig,
    WebAuthnService, WebAuthnConfig,
};
use tokio::sync::RwLock;
use tracing::info;

/// GraphQL context containing all necessary services and configurations
#[derive(Debug, Clone)]
pub struct GraphQLContext {
    /// AWS configuration with DynamoDB and SES clients
    pub aws_config: AwsConfig,
    /// Service configuration loaded from environment variables
    pub service_config: ServiceConfig,
    /// WebAuthn service for Passkey operations
    pub webauthn_service: Arc<RwLock<WebAuthnService>>,
    /// OTP service for one-time password operations
    pub otp_service: OtpService,
    /// Email service for sending notifications
    pub email_service: EmailService,
    /// JWT service for token management
    pub jwt_service: Arc<RwLock<JwtService>>,
    /// Application configuration cache
    pub app_config_cache: Arc<RwLock<AppConfigCache>>,
    /// WebAuthn configuration manager
    pub webauthn_config: Arc<RwLock<WebAuthnConfig>>,
}

impl GraphQLContext {
    /// Creates a new GraphQL context with initialized services
    pub async fn new(
        aws_config: AwsConfig,
        service_config: ServiceConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!("Initializing GraphQL context");

        // Initialize OTP service
        let otp_service = OtpService::new();

        // Initialize email service
        let email_config = shared::EmailConfig::new("noreply@passkey.example.com".to_string())
            .with_reply_to("support@passkey.example.com".to_string())
            .with_retry_config(3, 1000, true);
        let email_service = EmailService::new(aws_config.ses.clone(), email_config);

        // Initialize JWT service
        let jwt_config = shared::JwtConfig::new(
            "passkey-auth".to_string(),
            "passkey-api".to_string(),
        )
        .with_expiry(
            service_config.default_jwt_expires_in,
            86400 * 7, // 7 days for refresh tokens
        );
        let jwt_service = Arc::new(RwLock::new(JwtService::new(jwt_config)));

        // Initialize application configuration cache
        let app_config_cache = Arc::new(RwLock::new(AppConfigCache::new()));

        // Initialize WebAuthn configuration manager
        let webauthn_config = Arc::new(RwLock::new(WebAuthnConfig::new()));

        // Initialize WebAuthn service with empty configuration (will be populated on demand)
        let webauthn_service = Arc::new(RwLock::new(
            WebAuthnService::new(HashMap::new())
                .map_err(|e| format!("Failed to initialize WebAuthn service: {e}"))?,
        ));

        info!("GraphQL context initialized successfully");

        Ok(Self {
            aws_config,
            service_config,
            webauthn_service,
            otp_service,
            email_service,
            jwt_service,
            app_config_cache,
            webauthn_config,
        })
    }

    /// Gets an application configuration, loading from cache or database
    pub async fn get_app_config(&self, app_id: &str) -> Result<AppConfig, shared::PasskeyError> {
        // Check cache first
        {
            let cache = self.app_config_cache.read().await;
            if let Some(config) = cache.get(app_id) {
                return Ok(config.clone());
            }
        }

        // Load from database
        let table_name = self.service_config.table_name("app-configs");
        let config = shared::get_app_config(&self.aws_config.dynamodb, &table_name, app_id)
            .await?
            .ok_or_else(|| shared::PasskeyError::InvalidAppId(app_id.to_string()))?;

        // Cache the configuration
        {
            let mut cache = self.app_config_cache.write().await;
            cache.insert(config.clone());
        }

        Ok(config)
    }

    /// Ensures WebAuthn service is configured for the given application
    pub async fn ensure_webauthn_configured(
        &self,
        app_id: &str,
    ) -> Result<(), shared::PasskeyError> {
        // Check if already configured
        {
            let service = self.webauthn_service.read().await;
            if service.registered_apps().contains(&app_id.to_string()) {
                return Ok(());
            }
        }

        // Get application configuration
        let app_config = self.get_app_config(app_id).await?;

        // Configure WebAuthn for this application
        {
            let mut webauthn_config = self.webauthn_config.write().await;
            webauthn_config.get_or_create_instance(&app_config)?;
        }

        info!("WebAuthn configured for application: {}", app_id);
        Ok(())
    }

    /// Ensures JWT service is configured with signing key for the given application
    pub async fn ensure_jwt_configured(&self, app_id: &str) -> Result<(), shared::PasskeyError> {
        // Check if already configured
        {
            let service = self.jwt_service.read().await;
            if service.registered_apps().contains(&app_id.to_string()) {
                return Ok(());
            }
        }

        // Get application configuration
        let app_config = self.get_app_config(app_id).await?;

        // Configure JWT service with app's signing key
        {
            let mut service = self.jwt_service.write().await;
            let secret_bytes = app_config.jwt_secret.as_bytes().to_vec();
            service.register_app_key(app_id.to_string(), secret_bytes)?;
        }

        info!("JWT service configured for application: {}", app_id);
        Ok(())
    }

    /// Gets the DynamoDB table name for a given table type
    pub fn table_name(&self, table_type: &str) -> String {
        self.service_config.table_name(table_type)
    }

    /// Validates application access and returns application configuration
    pub async fn validate_app_access(&self, app_id: &str) -> Result<AppConfig, shared::PasskeyError> {
        let app_config = self.get_app_config(app_id).await?;
        
        if !app_config.is_active {
            return Err(shared::PasskeyError::InvalidAppId(format!(
                "Application {} is not active",
                app_id
            )));
        }

        Ok(app_config)
    }

    /// Invalidates cached application configuration
    pub async fn invalidate_app_cache(&self, app_id: &str) {
        let mut cache = self.app_config_cache.write().await;
        cache.remove(app_id);
        info!("Invalidated cache for application: {}", app_id);
    }

    /// Gets service health information
    pub async fn get_health_info(&self) -> HealthInfo {
        let cache = self.app_config_cache.read().await;
        let jwt_service = self.jwt_service.read().await;
        let webauthn_service = self.webauthn_service.read().await;
        
        HealthInfo {
            cached_apps: cache.app_ids(),
            jwt_configured_apps: jwt_service.registered_apps(),
            webauthn_configured_apps: webauthn_service.registered_apps(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Verifies JWT token and extracts user information
    pub async fn verify_jwt_token(&self, token: &str, app_id: &str) -> Result<shared::AccessTokenClaims, Box<dyn std::error::Error + Send + Sync>> {
        let jwt_service = self.jwt_service.read().await;
        
        match jwt_service.verify_access_token(token, app_id) {
            Ok(claims) => Ok(claims),
            Err(e) => {
                tracing::warn!("JWT token verification failed: {:?}", e);
                Err(Box::new(e))
            }
        }
    }

    /// Checks if the user has admin permissions for the given application
    pub async fn verify_admin_permission(
        &self, 
        token: &str, 
        app_id: &str
    ) -> Result<shared::AccessTokenClaims, Box<dyn std::error::Error + Send + Sync>> {
        let claims = self.verify_jwt_token(token, app_id).await?;
        
        // Check if user has admin or super admin role
        match claims.role {
            shared::UserRole::Admin | shared::UserRole::SuperAdmin => {
                tracing::info!("Admin permission verified for user: {} in app: {}", claims.sub, app_id);
                Ok(claims)
            }
            _ => {
                tracing::warn!(
                    "Insufficient permissions: user {} has role {:?} but needs Admin or SuperAdmin",
                    claims.sub, claims.role
                );
                Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Admin permission required"
                )))
            }
        }
    }

    /// Checks if the user owns the resource or has admin permissions
    pub async fn verify_owner_or_admin_permission(
        &self,
        token: &str,
        app_id: &str,
        resource_user_id: &str,
    ) -> Result<(shared::AccessTokenClaims, bool), Box<dyn std::error::Error + Send + Sync>> {
        let claims = self.verify_jwt_token(token, app_id).await?;
        
        // Check if user is the owner of the resource
        let is_owner = claims.sub == resource_user_id;
        
        // Check if user has admin permissions
        let is_admin = matches!(claims.role, shared::UserRole::Admin | shared::UserRole::SuperAdmin);
        
        if is_owner || is_admin {
            tracing::info!(
                "Permission verified for user: {} in app: {} (owner: {}, admin: {})",
                claims.sub, app_id, is_owner, is_admin
            );
            Ok((claims, is_admin))
        } else {
            tracing::warn!(
                "Insufficient permissions: user {} cannot access resource for user {} in app {}",
                claims.sub, resource_user_id, app_id
            );
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Resource access denied: must be owner or admin"
            )))
        }
    }

    /// Extracts JWT token from GraphQL context headers
    pub fn extract_auth_token(&self, ctx: &async_graphql::Context<'_>) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // In a real implementation, you would extract the Authorization header
        // For now, we'll simulate token extraction
        
        // TODO: Extract from HTTP headers in the GraphQL request
        // This would typically be done by getting the headers from the request context
        // For development purposes, we'll return an error indicating missing implementation
        
        tracing::warn!("JWT token extraction not yet implemented - would extract from Authorization header");
        
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Authorization token extraction not implemented"
        )))
    }
}

/// Health information for the GraphQL service
#[derive(Debug, Clone)]
pub struct HealthInfo {
    /// List of applications with cached configurations
    pub cached_apps: Vec<String>,
    /// List of applications with configured JWT services
    pub jwt_configured_apps: Vec<String>,
    /// List of applications with configured WebAuthn services
    pub webauthn_configured_apps: Vec<String>,
    /// Service version
    pub service_version: String,
}