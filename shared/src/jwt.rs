//! JWT token management for authentication and authorization.
//!
//! This module provides secure JWT token generation and validation for the Passkey
//! authentication system. It supports application-specific signing keys, custom claims,
//! and refresh token functionality for enhanced security.

use crate::{PasskeyError, UserRole};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::{Duration, OffsetDateTime};
use tracing::{error, info, warn};

/// JWT token service configuration
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// Default token expiration time in seconds
    pub default_expiry_seconds: u64,
    /// Refresh token expiration time in seconds  
    pub refresh_token_expiry_seconds: u64,
    /// Algorithm used for signing tokens
    pub algorithm: Algorithm,
    /// Issuer name for JWT tokens
    pub issuer: String,
    /// Audience for JWT tokens
    pub audience: String,
}

impl JwtConfig {
    /// Creates a new JWT configuration with defaults.
    pub fn new(issuer: String, audience: String) -> Self {
        Self {
            default_expiry_seconds: 3600, // 1 hour
            refresh_token_expiry_seconds: 86400 * 7, // 7 days
            algorithm: Algorithm::HS256,
            issuer,
            audience,
        }
    }

    /// Sets custom expiry times.
    pub fn with_expiry(mut self, access_seconds: u64, refresh_seconds: u64) -> Self {
        self.default_expiry_seconds = access_seconds;
        self.refresh_token_expiry_seconds = refresh_seconds;
        self
    }

    /// Sets custom algorithm.
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }
}

/// JWT claims for access tokens
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessTokenClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Application ID
    pub app_id: String,
    /// User's email address
    pub email: String,
    /// User's display name
    pub display_name: String,
    /// User's role within the application
    pub role: UserRole,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Token type
    pub typ: String,
    /// Custom claims (optional)
    #[serde(flatten)]
    pub custom_claims: HashMap<String, serde_json::Value>,
}

impl AccessTokenClaims {
    /// Creates new access token claims.
    pub fn new(
        user_id: String,
        app_id: String,
        email: String,
        display_name: String,
        role: UserRole,
        issuer: String,
        audience: String,
        expiry_duration: Duration,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        let exp_time = now + expiry_duration;

        Self {
            sub: user_id,
            app_id,
            email,
            display_name,
            role,
            iat: now.unix_timestamp(),
            exp: exp_time.unix_timestamp(),
            iss: issuer,
            aud: audience,
            typ: "access".to_string(),
            custom_claims: HashMap::new(),
        }
    }

    /// Adds a custom claim to the token.
    pub fn with_custom_claim(mut self, key: String, value: serde_json::Value) -> Self {
        self.custom_claims.insert(key, value);
        self
    }

    /// Checks if the token has expired.
    pub fn is_expired(&self) -> bool {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        now >= self.exp
    }

    /// Gets the time remaining until expiration.
    pub fn time_until_expiry(&self) -> Option<Duration> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if now >= self.exp {
            None
        } else {
            Some(Duration::seconds(self.exp - now))
        }
    }
}

/// JWT claims for refresh tokens
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshTokenClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Application ID
    pub app_id: String,
    /// Issued at timestamp
    pub iat: i64,
    /// Expiration timestamp
    pub exp: i64,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Token type
    pub typ: String,
    /// Token ID for revocation tracking
    pub jti: String,
}

impl RefreshTokenClaims {
    /// Creates new refresh token claims.
    pub fn new(
        user_id: String,
        app_id: String,
        issuer: String,
        audience: String,
        expiry_duration: Duration,
        token_id: String,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        let exp_time = now + expiry_duration;

        Self {
            sub: user_id,
            app_id,
            iat: now.unix_timestamp(),
            exp: exp_time.unix_timestamp(),
            iss: issuer,
            aud: audience,
            typ: "refresh".to_string(),
            jti: token_id,
        }
    }

    /// Checks if the token has expired.
    pub fn is_expired(&self) -> bool {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        now >= self.exp
    }
}

/// JWT token pair containing access and refresh tokens
#[derive(Debug, Clone)]
pub struct TokenPair {
    /// Access token (short-lived)
    pub access_token: String,
    /// Refresh token (long-lived)
    pub refresh_token: String,
    /// Access token expiration timestamp
    pub access_expires_at: i64,
    /// Refresh token expiration timestamp  
    pub refresh_expires_at: i64,
    /// Token type (always "Bearer")
    pub token_type: String,
}

impl TokenPair {
    /// Creates a new token pair.
    pub fn new(
        access_token: String,
        refresh_token: String,
        access_expires_at: i64,
        refresh_expires_at: i64,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            access_expires_at,
            refresh_expires_at,
            token_type: "Bearer".to_string(),
        }
    }
}

/// JWT service for token management per application
#[derive(Debug)]
pub struct JwtService {
    /// JWT configuration
    config: JwtConfig,
    /// Application-specific signing keys (app_id -> secret)
    signing_keys: HashMap<String, Vec<u8>>,
    /// Revoked refresh token IDs (for future use)
    revoked_tokens: std::collections::HashSet<String>,
}

impl JwtService {
    /// Creates a new JWT service.
    pub fn new(config: JwtConfig) -> Self {
        Self {
            config,
            signing_keys: HashMap::new(),
            revoked_tokens: std::collections::HashSet::new(),
        }
    }

    /// Registers a signing key for an application.
    ///
    /// # Arguments
    ///
    /// * `app_id` - Application identifier
    /// * `secret` - Secret key for signing tokens (should be cryptographically secure)
    ///
    /// # Security Note
    ///
    /// The secret should be at least 256 bits (32 bytes) for HS256 algorithm.
    pub fn register_app_key(&mut self, app_id: String, secret: Vec<u8>) -> Result<(), PasskeyError> {
        if secret.len() < 32 {
            return Err(PasskeyError::ConfigError(
                "JWT secret must be at least 32 bytes for security".to_string(),
            ));
        }

        self.signing_keys.insert(app_id, secret);
        Ok(())
    }

    /// Generates an access token for a user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - User identifier
    /// * `app_id` - Application identifier  
    /// * `email` - User's email address
    /// * `display_name` - User's display name
    /// * `role` - User's role
    /// * `custom_expiry` - Optional custom expiry duration
    ///
    /// # Returns
    ///
    /// Returns the signed JWT token string or an error.
    pub fn generate_access_token(
        &self,
        user_id: String,
        app_id: String,
        email: String,
        display_name: String,
        role: UserRole,
        custom_expiry: Option<Duration>,
    ) -> Result<String, PasskeyError> {
        let secret = self.get_app_secret(&app_id)?;
        let encoding_key = EncodingKey::from_secret(secret);

        let expiry = custom_expiry.unwrap_or_else(|| {
            Duration::seconds(self.config.default_expiry_seconds as i64)
        });

        let claims = AccessTokenClaims::new(
            user_id,
            app_id.clone(),
            email,
            display_name,
            role,
            self.config.issuer.clone(),
            self.config.audience.clone(),
            expiry,
        );

        let header = Header::new(self.config.algorithm);

        encode(&header, &claims, &encoding_key).map_err(|e| {
            error!("Failed to generate access token for app {}: {}", app_id, e);
            PasskeyError::JWT(format!("Token generation failed: {e}"))
        })
    }

    /// Generates a refresh token for a user.
    pub fn generate_refresh_token(
        &self,
        user_id: String,
        app_id: String,
        token_id: String,
    ) -> Result<String, PasskeyError> {
        let secret = self.get_app_secret(&app_id)?;
        let encoding_key = EncodingKey::from_secret(secret);

        let expiry = Duration::seconds(self.config.refresh_token_expiry_seconds as i64);

        let claims = RefreshTokenClaims::new(
            user_id,
            app_id.clone(),
            self.config.issuer.clone(),
            self.config.audience.clone(),
            expiry,
            token_id,
        );

        let header = Header::new(self.config.algorithm);

        encode(&header, &claims, &encoding_key).map_err(|e| {
            error!("Failed to generate refresh token for app {}: {}", app_id, e);
            PasskeyError::JWT(format!("Refresh token generation failed: {e}"))
        })
    }

    /// Generates a token pair (access + refresh tokens).
    pub fn generate_token_pair(
        &self,
        user_id: String,
        app_id: String,
        email: String,
        display_name: String,
        role: UserRole,
    ) -> Result<TokenPair, PasskeyError> {
        let token_id = uuid::Uuid::new_v4().to_string();

        let access_token = self.generate_access_token(
            user_id.clone(),
            app_id.clone(),
            email,
            display_name,
            role,
            None,
        )?;

        let refresh_token = self.generate_refresh_token(user_id, app_id, token_id)?;

        // Calculate expiration timestamps
        let now = OffsetDateTime::now_utc();
        let access_expires_at = (now + Duration::seconds(self.config.default_expiry_seconds as i64))
            .unix_timestamp();
        let refresh_expires_at = (now + Duration::seconds(self.config.refresh_token_expiry_seconds as i64))
            .unix_timestamp();

        Ok(TokenPair::new(
            access_token,
            refresh_token,
            access_expires_at,
            refresh_expires_at,
        ))
    }

    /// Verifies and decodes an access token.
    pub fn verify_access_token(
        &self,
        token: &str,
        app_id: &str,
    ) -> Result<AccessTokenClaims, PasskeyError> {
        let secret = self.get_app_secret(app_id)?;
        let decoding_key = DecodingKey::from_secret(secret);

        let mut validation = Validation::new(self.config.algorithm);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        let token_data = decode::<AccessTokenClaims>(token, &decoding_key, &validation).map_err(|e| {
            warn!("Failed to verify access token for app {}: {}", app_id, e);
            PasskeyError::JWT(format!("Token verification failed: {e}"))
        })?;

        let claims = token_data.claims;

        // Additional validation
        if claims.app_id != app_id {
            return Err(PasskeyError::JWT("Token app_id mismatch".to_string()));
        }

        if claims.typ != "access" {
            return Err(PasskeyError::JWT("Invalid token type".to_string()));
        }

        if claims.is_expired() {
            return Err(PasskeyError::JWT("Token has expired".to_string()));
        }

        info!("Access token verified successfully for user {} in app {}", claims.sub, app_id);
        Ok(claims)
    }

    /// Verifies and decodes a refresh token.
    pub fn verify_refresh_token(
        &self,
        token: &str,
        app_id: &str,
    ) -> Result<RefreshTokenClaims, PasskeyError> {
        let secret = self.get_app_secret(app_id)?;
        let decoding_key = DecodingKey::from_secret(secret);

        let mut validation = Validation::new(self.config.algorithm);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        let token_data = decode::<RefreshTokenClaims>(token, &decoding_key, &validation).map_err(|e| {
            warn!("Failed to verify refresh token for app {}: {}", app_id, e);
            PasskeyError::JWT(format!("Refresh token verification failed: {e}"))
        })?;

        let claims = token_data.claims;

        // Additional validation
        if claims.app_id != app_id {
            return Err(PasskeyError::JWT("Token app_id mismatch".to_string()));
        }

        if claims.typ != "refresh" {
            return Err(PasskeyError::JWT("Invalid token type".to_string()));
        }

        if claims.is_expired() {
            return Err(PasskeyError::JWT("Token has expired".to_string()));
        }

        // Check if token is revoked
        if self.revoked_tokens.contains(&claims.jti) {
            return Err(PasskeyError::JWT("Token has been revoked".to_string()));
        }

        info!("Refresh token verified successfully for user {} in app {}", claims.sub, app_id);
        Ok(claims)
    }

    /// Refreshes an access token using a refresh token.
    pub fn refresh_access_token(
        &self,
        refresh_token: &str,
        app_id: &str,
        user_email: String,
        user_display_name: String,
        user_role: UserRole,
    ) -> Result<TokenPair, PasskeyError> {
        // Verify refresh token first
        let refresh_claims = self.verify_refresh_token(refresh_token, app_id)?;

        // Generate new token pair
        self.generate_token_pair(
            refresh_claims.sub,
            app_id.to_string(),
            user_email,
            user_display_name,
            user_role,
        )
    }

    /// Revokes a refresh token by adding its ID to the revoked list.
    ///
    /// Note: In a production system, this should be persisted to a database
    /// and shared across service instances.
    pub fn revoke_refresh_token(&mut self, token: &str, app_id: &str) -> Result<(), PasskeyError> {
        let claims = self.verify_refresh_token(token, app_id)?;
        self.revoked_tokens.insert(claims.jti.clone());
        
        info!("Revoked refresh token {} for user {} in app {}", 
              claims.jti, claims.sub, app_id);
        Ok(())
    }

    /// Revokes all refresh tokens for a user (logout from all devices).
    ///
    /// Note: This is a placeholder implementation. In production, you would
    /// need to track user tokens in a persistent store.
    pub fn revoke_all_user_tokens(&mut self, _user_id: &str, _app_id: &str) -> Result<(), PasskeyError> {
        // In a real implementation, you would:
        // 1. Query all refresh tokens for the user
        // 2. Add them to the revoked list
        // 3. Persist the changes
        
        warn!("revoke_all_user_tokens is not fully implemented - requires persistent token storage");
        Ok(())
    }

    /// Gets the signing secret for an application.
    fn get_app_secret(&self, app_id: &str) -> Result<&[u8], PasskeyError> {
        self.signing_keys
            .get(app_id)
            .map(|secret| secret.as_slice())
            .ok_or_else(|| {
                PasskeyError::JWT(format!("No signing key registered for app: {app_id}"))
            })
    }

    /// Gets the list of registered applications.
    pub fn registered_apps(&self) -> Vec<String> {
        self.signing_keys.keys().cloned().collect()
    }

    /// Removes signing key for an application.
    pub fn unregister_app_key(&mut self, app_id: &str) -> bool {
        self.signing_keys.remove(app_id).is_some()
    }
}

/// Utility function to generate a cryptographically secure secret for JWT signing.
pub fn generate_jwt_secret() -> Vec<u8> {
    let mut secret = vec![0u8; 32]; // 256 bits
    rand::rng().fill_bytes(&mut secret);
    secret
}

/// Utility function to encode secret as base64 for storage.
pub fn encode_secret_base64(secret: &[u8]) -> String {
    STANDARD.encode(secret)
}

/// Utility function to decode secret from base64.
pub fn decode_secret_base64(encoded: &str) -> Result<Vec<u8>, PasskeyError> {
    STANDARD.decode(encoded).map_err(|e| {
        PasskeyError::ConfigError(format!("Failed to decode JWT secret: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_config_new() {
        let config = JwtConfig::new("issuer".to_string(), "audience".to_string());
        assert_eq!(config.issuer, "issuer");
        assert_eq!(config.audience, "audience");
        assert_eq!(config.default_expiry_seconds, 3600);
        assert_eq!(config.refresh_token_expiry_seconds, 86400 * 7);
        assert_eq!(config.algorithm, Algorithm::HS256);
    }

    #[test]
    fn test_jwt_config_with_expiry() {
        let config = JwtConfig::new("issuer".to_string(), "audience".to_string())
            .with_expiry(1800, 86400);
        assert_eq!(config.default_expiry_seconds, 1800);
        assert_eq!(config.refresh_token_expiry_seconds, 86400);
    }

    #[test]
    fn test_access_token_claims_new() {
        let claims = AccessTokenClaims::new(
            "user123".to_string(),
            "app456".to_string(),
            "user@example.com".to_string(),
            "John Doe".to_string(),
            UserRole::User,
            "issuer".to_string(),
            "audience".to_string(),
            Duration::hours(1),
        );

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.app_id, "app456");
        assert_eq!(claims.email, "user@example.com");
        assert_eq!(claims.display_name, "John Doe");
        assert_eq!(claims.role, UserRole::User);
        assert_eq!(claims.iss, "issuer");
        assert_eq!(claims.aud, "audience");
        assert_eq!(claims.typ, "access");
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_access_token_claims_with_custom_claim() {
        let claims = AccessTokenClaims::new(
            "user123".to_string(),
            "app456".to_string(),
            "user@example.com".to_string(),
            "John Doe".to_string(),
            UserRole::User,
            "issuer".to_string(),
            "audience".to_string(),
            Duration::hours(1),
        ).with_custom_claim("department".to_string(), serde_json::Value::String("Engineering".to_string()));

        assert_eq!(
            claims.custom_claims.get("department"),
            Some(&serde_json::Value::String("Engineering".to_string()))
        );
    }

    #[test]
    fn test_refresh_token_claims_new() {
        let claims = RefreshTokenClaims::new(
            "user123".to_string(),
            "app456".to_string(),
            "issuer".to_string(),
            "audience".to_string(),
            Duration::days(7),
            "token123".to_string(),
        );

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.app_id, "app456");
        assert_eq!(claims.iss, "issuer");
        assert_eq!(claims.aud, "audience");
        assert_eq!(claims.typ, "refresh");
        assert_eq!(claims.jti, "token123");
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_token_pair_new() {
        let pair = TokenPair::new(
            "access_token".to_string(),
            "refresh_token".to_string(),
            1234567890,
            1234567890,
        );

        assert_eq!(pair.access_token, "access_token");
        assert_eq!(pair.refresh_token, "refresh_token");
        assert_eq!(pair.access_expires_at, 1234567890);
        assert_eq!(pair.refresh_expires_at, 1234567890);
        assert_eq!(pair.token_type, "Bearer");
    }

    #[test]
    fn test_jwt_service_new() {
        let config = JwtConfig::new("issuer".to_string(), "audience".to_string());
        let service = JwtService::new(config);
        
        assert_eq!(service.config.issuer, "issuer");
        assert_eq!(service.signing_keys.len(), 0);
    }

    #[test]
    fn test_register_app_key() {
        let config = JwtConfig::new("issuer".to_string(), "audience".to_string());
        let mut service = JwtService::new(config);

        let secret = generate_jwt_secret();
        let result = service.register_app_key("app1".to_string(), secret.clone());
        assert!(result.is_ok());

        let apps = service.registered_apps();
        assert!(apps.contains(&"app1".to_string()));
    }

    #[test]
    fn test_register_app_key_too_short() {
        let config = JwtConfig::new("issuer".to_string(), "audience".to_string());
        let mut service = JwtService::new(config);

        let short_secret = vec![0u8; 16]; // Too short
        let result = service.register_app_key("app1".to_string(), short_secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_and_verify_access_token() {
        let config = JwtConfig::new("issuer".to_string(), "audience".to_string());
        let mut service = JwtService::new(config);

        let secret = generate_jwt_secret();
        service.register_app_key("app1".to_string(), secret).unwrap();

        let token = service.generate_access_token(
            "user123".to_string(),
            "app1".to_string(),
            "user@example.com".to_string(),
            "John Doe".to_string(),
            UserRole::User,
            None,
        ).unwrap();

        let claims = service.verify_access_token(&token, "app1").unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.app_id, "app1");
        assert_eq!(claims.email, "user@example.com");
    }

    #[test]
    fn test_generate_and_verify_refresh_token() {
        let config = JwtConfig::new("issuer".to_string(), "audience".to_string());
        let mut service = JwtService::new(config);

        let secret = generate_jwt_secret();
        service.register_app_key("app1".to_string(), secret).unwrap();

        let token = service.generate_refresh_token(
            "user123".to_string(),
            "app1".to_string(),
            "token123".to_string(),
        ).unwrap();

        let claims = service.verify_refresh_token(&token, "app1").unwrap();
        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.app_id, "app1");
        assert_eq!(claims.jti, "token123");
    }

    #[test]
    fn test_generate_token_pair() {
        let config = JwtConfig::new("issuer".to_string(), "audience".to_string());
        let mut service = JwtService::new(config);

        let secret = generate_jwt_secret();
        service.register_app_key("app1".to_string(), secret).unwrap();

        let pair = service.generate_token_pair(
            "user123".to_string(),
            "app1".to_string(),
            "user@example.com".to_string(),
            "John Doe".to_string(),
            UserRole::User,
        ).unwrap();

        assert!(!pair.access_token.is_empty());
        assert!(!pair.refresh_token.is_empty());
        assert_eq!(pair.token_type, "Bearer");

        // Verify both tokens
        let access_claims = service.verify_access_token(&pair.access_token, "app1").unwrap();
        let refresh_claims = service.verify_refresh_token(&pair.refresh_token, "app1").unwrap();

        assert_eq!(access_claims.sub, refresh_claims.sub);
        assert_eq!(access_claims.app_id, refresh_claims.app_id);
    }

    #[test]
    fn test_revoke_refresh_token() {
        let config = JwtConfig::new("issuer".to_string(), "audience".to_string());
        let mut service = JwtService::new(config);

        let secret = generate_jwt_secret();
        service.register_app_key("app1".to_string(), secret).unwrap();

        let token = service.generate_refresh_token(
            "user123".to_string(),
            "app1".to_string(),
            "token123".to_string(),
        ).unwrap();

        // First verification should succeed
        assert!(service.verify_refresh_token(&token, "app1").is_ok());

        // Revoke the token
        service.revoke_refresh_token(&token, "app1").unwrap();

        // Second verification should fail
        assert!(service.verify_refresh_token(&token, "app1").is_err());
    }

    #[test]
    fn test_generate_jwt_secret() {
        let secret1 = generate_jwt_secret();
        let secret2 = generate_jwt_secret();

        assert_eq!(secret1.len(), 32);
        assert_eq!(secret2.len(), 32);
        assert_ne!(secret1, secret2); // Should be different
    }

    #[test]
    fn test_encode_decode_secret_base64() {
        let original_secret = generate_jwt_secret();
        let encoded = encode_secret_base64(&original_secret);
        let decoded = decode_secret_base64(&encoded).unwrap();

        assert_eq!(original_secret, decoded);
    }

    #[test]
    fn test_unregister_app_key() {
        let config = JwtConfig::new("issuer".to_string(), "audience".to_string());
        let mut service = JwtService::new(config);

        let secret = generate_jwt_secret();
        service.register_app_key("app1".to_string(), secret).unwrap();

        assert!(service.registered_apps().contains(&"app1".to_string()));

        let removed = service.unregister_app_key("app1");
        assert!(removed);
        assert!(!service.registered_apps().contains(&"app1".to_string()));

        let removed_again = service.unregister_app_key("app1");
        assert!(!removed_again);
    }
}