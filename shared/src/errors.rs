//! Error handling for the Passkey authentication system.
//!
//! This module defines the main error types used throughout the system,
//! with support for thiserror-based error handling and GraphQL error conversion.
//! All errors implement appropriate display messages while maintaining security
//! by not exposing sensitive internal details.

use thiserror::Error;

/// Main error type for the Passkey authentication system.
#[derive(Error, Debug, Clone)]
pub enum PasskeyError {
    /// Authentication failed with a specific reason
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Authorization failed - user lacks required permissions
    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),

    /// Input validation failed
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    /// User not found in the system
    #[error("User not found")]
    UserNotFound,

    /// Credential not found or invalid
    #[error("Credential not found")]
    CredentialNotFound,

    /// Session not found or expired
    #[error("Session not found or expired")]
    SessionNotFound,

    /// Application configuration not found
    #[error("Application configuration not found")]
    AppConfigNotFound,

    /// Pending user not found or expired
    #[error("Pending user not found or expired")]
    PendingUserNotFound,

    /// Invalid OTP provided
    #[error("Invalid OTP: {0}")]
    InvalidOtp(String),

    /// OTP has expired
    #[error("OTP has expired")]
    OtpExpired,

    /// OTP attempt limit exceeded
    #[error("OTP attempt limit exceeded")]
    OtpMaxAttemptsExceeded,

    /// System time error
    #[error("System time error: {0}")]
    SystemTime(String),

    /// WebAuthn operation failed
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),

    /// JWT token operation failed
    #[error("JWT error: {0}")]
    JWT(String),

    /// Database operation failed
    #[error("Database error")]
    Database(#[from] DatabaseError),

    /// Email service error
    #[error("Email service error")]
    EmailService(#[from] EmailError),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Configuration error (alias)
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Invalid application ID
    #[error("Invalid application ID: {0}")]
    InvalidAppId(String),

    /// Invalid user ID format
    #[error("Invalid user ID: {0}")]
    InvalidUserId(String),

    /// Invalid credential
    #[error("Invalid credential: {0}")]
    InvalidCredential(String),

    /// Rate limiting error
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Generic internal server error (should not expose details)
    #[error("Internal server error")]
    InternalError,
}

/// Database-specific errors.
#[derive(Error, Debug, Clone)]
pub enum DatabaseError {
    /// Connection to database failed
    #[error("Database connection failed")]
    ConnectionFailed,

    /// Query execution failed
    #[error("Query execution failed")]
    QueryFailed(String),

    /// Item not found in database
    #[error("Item not found")]
    ItemNotFound,

    /// Constraint violation (e.g., unique key)
    #[error("Constraint violation: {0}")]
    ConstraintViolation(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// DynamoDB-specific error
    #[error("DynamoDB error: {0}")]
    DynamoDB(String),
}

/// Email service specific errors.
#[derive(Error, Debug, Clone)]
pub enum EmailError {
    /// Failed to send email
    #[error("Failed to send email")]
    SendFailed,

    /// Invalid email address
    #[error("Invalid email address: {0}")]
    InvalidAddress(String),

    /// Email template error
    #[error("Email template error: {0}")]
    TemplateError(String),

    /// SES service error
    #[error("SES error: {0}")]
    SESError(String),

    /// Rate limit exceeded for email sending
    #[error("Email rate limit exceeded")]
    RateLimitExceeded,
}

/// Result type alias for Passkey operations.
pub type PasskeyResult<T> = Result<T, PasskeyError>;

impl PasskeyError {
    /// Creates an authentication failed error.
    pub fn auth_failed(reason: impl Into<String>) -> Self {
        Self::AuthenticationFailed(reason.into())
    }

    /// Creates an authorization failed error.
    pub fn auth_denied(reason: impl Into<String>) -> Self {
        Self::AuthorizationFailed(reason.into())
    }

    /// Creates a validation failed error.
    pub fn validation(reason: impl Into<String>) -> Self {
        Self::ValidationFailed(reason.into())
    }

    /// Creates a WebAuthn error.
    pub fn webauthn(reason: impl Into<String>) -> Self {
        Self::WebAuthn(reason.into())
    }

    /// Creates a JWT error.
    pub fn jwt(reason: impl Into<String>) -> Self {
        Self::JWT(reason.into())
    }

    /// Creates a configuration error.
    pub fn config(reason: impl Into<String>) -> Self {
        Self::ConfigError(reason.into())
    }

    /// Returns true if this error should be logged with details.
    pub fn should_log_details(&self) -> bool {
        matches!(
            self,
            PasskeyError::Database(_)
                | PasskeyError::EmailService(_)
                | PasskeyError::Configuration(_)
                | PasskeyError::ConfigError(_)
                | PasskeyError::InternalError
        )
    }

    /// Returns the error code for client responses.
    pub fn error_code(&self) -> &'static str {
        match self {
            PasskeyError::AuthenticationFailed(_) => "AUTH_FAILED",
            PasskeyError::AuthorizationFailed(_) => "AUTH_DENIED",
            PasskeyError::ValidationFailed(_) => "VALIDATION_FAILED",
            PasskeyError::UserNotFound => "USER_NOT_FOUND",
            PasskeyError::CredentialNotFound => "CREDENTIAL_NOT_FOUND",
            PasskeyError::SessionNotFound => "SESSION_NOT_FOUND",
            PasskeyError::AppConfigNotFound => "APP_CONFIG_NOT_FOUND",
            PasskeyError::PendingUserNotFound => "PENDING_USER_NOT_FOUND",
            PasskeyError::InvalidOtp(_) => "INVALID_OTP",
            PasskeyError::OtpExpired => "OTP_EXPIRED",
            PasskeyError::OtpMaxAttemptsExceeded => "OTP_ATTEMPTS_EXCEEDED",
            PasskeyError::SystemTime(_) => "SYSTEM_TIME_ERROR",
            PasskeyError::WebAuthn(_) => "WEBAUTHN_ERROR",
            PasskeyError::JWT(_) => "JWT_ERROR",
            PasskeyError::Database(_) => "DATABASE_ERROR",
            PasskeyError::EmailService(_) => "EMAIL_ERROR",
            PasskeyError::Configuration(_) => "CONFIG_ERROR",
            PasskeyError::ConfigError(_) => "CONFIG_ERROR",
            PasskeyError::InvalidAppId(_) => "INVALID_APP_ID",
            PasskeyError::InvalidUserId(_) => "INVALID_USER_ID",
            PasskeyError::InvalidCredential(_) => "INVALID_CREDENTIAL",
            PasskeyError::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            PasskeyError::InternalError => "INTERNAL_ERROR",
        }
    }

    /// Returns a safe client message (without sensitive details).
    pub fn client_message(&self) -> String {
        match self {
            PasskeyError::AuthenticationFailed(_) => "Authentication failed".to_string(),
            PasskeyError::AuthorizationFailed(_) => "Access denied".to_string(),
            PasskeyError::ValidationFailed(msg) => format!("Validation failed: {msg}"),
            PasskeyError::UserNotFound => "User not found".to_string(),
            PasskeyError::CredentialNotFound => "Credential not found".to_string(),
            PasskeyError::SessionNotFound => "Session not found or expired".to_string(),
            PasskeyError::AppConfigNotFound => "Application not found".to_string(),
            PasskeyError::PendingUserNotFound => "Invitation not found or expired".to_string(),
            PasskeyError::InvalidOtp(_) => "Invalid verification code".to_string(),
            PasskeyError::OtpExpired => "Verification code has expired".to_string(),
            PasskeyError::OtpMaxAttemptsExceeded => "Too many verification attempts".to_string(),
            PasskeyError::SystemTime(_) => "System time error".to_string(),
            PasskeyError::WebAuthn(_) => "WebAuthn operation failed".to_string(),
            PasskeyError::JWT(_) => "Token validation failed".to_string(),
            PasskeyError::Database(_) => "Service temporarily unavailable".to_string(),
            PasskeyError::EmailService(_) => "Email service temporarily unavailable".to_string(),
            PasskeyError::Configuration(_) => "Service configuration error".to_string(),
            PasskeyError::ConfigError(_) => "Service configuration error".to_string(),
            PasskeyError::InvalidAppId(_) => "Invalid application".to_string(),
            PasskeyError::InvalidUserId(_) => "Invalid user".to_string(),
            PasskeyError::InvalidCredential(_) => "Invalid credential".to_string(),
            PasskeyError::RateLimitExceeded => {
                "Rate limit exceeded, please try again later".to_string()
            }
            PasskeyError::InternalError => "Internal server error".to_string(),
        }
    }
}

// AWS SDK error conversions
impl From<aws_sdk_dynamodb::Error> for DatabaseError {
    fn from(err: aws_sdk_dynamodb::Error) -> Self {
        DatabaseError::DynamoDB(format!("DynamoDB error: {err}"))
    }
}

impl From<aws_sdk_ses::Error> for EmailError {
    fn from(err: aws_sdk_ses::Error) -> Self {
        EmailError::SESError(format!("SES error: {err}"))
    }
}

// Serialization error conversions
impl From<serde_json::Error> for DatabaseError {
    fn from(err: serde_json::Error) -> Self {
        DatabaseError::SerializationError(format!("JSON error: {err}"))
    }
}

// WebAuthn error conversion
impl From<webauthn_rs::prelude::WebauthnError> for PasskeyError {
    fn from(err: webauthn_rs::prelude::WebauthnError) -> Self {
        PasskeyError::WebAuthn(format!("WebAuthn error: {:?}", err))
    }
}

// JWT error conversion
impl From<jsonwebtoken::errors::Error> for PasskeyError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        PasskeyError::JWT(format!("JWT error: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(PasskeyError::UserNotFound.error_code(), "USER_NOT_FOUND");
        assert_eq!(PasskeyError::InvalidOtp("test".to_string()).error_code(), "INVALID_OTP");
        assert_eq!(
            PasskeyError::RateLimitExceeded.error_code(),
            "RATE_LIMIT_EXCEEDED"
        );
    }

    #[test]
    fn test_client_messages() {
        let auth_error = PasskeyError::AuthenticationFailed("Invalid credentials".to_string());
        assert_eq!(auth_error.client_message(), "Authentication failed");

        let validation_error = PasskeyError::ValidationFailed("Email required".to_string());
        assert_eq!(
            validation_error.client_message(),
            "Validation failed: Email required"
        );
    }

    #[test]
    fn test_should_log_details() {
        assert!(PasskeyError::InternalError.should_log_details());
        assert!(PasskeyError::ConfigError("test".to_string()).should_log_details());
        assert!(!PasskeyError::UserNotFound.should_log_details());
        assert!(!PasskeyError::InvalidOtp("test".to_string()).should_log_details());
    }

    #[test]
    fn test_error_constructors() {
        let auth_err = PasskeyError::auth_failed("test reason");
        assert!(matches!(auth_err, PasskeyError::AuthenticationFailed(_)));

        let webauthn_err = PasskeyError::webauthn("test webauthn");
        assert!(matches!(webauthn_err, PasskeyError::WebAuthn(_)));

        let auth_denied_err = PasskeyError::auth_denied("access denied");
        assert!(matches!(
            auth_denied_err,
            PasskeyError::AuthorizationFailed(_)
        ));

        let validation_err = PasskeyError::validation("invalid input");
        assert!(matches!(validation_err, PasskeyError::ValidationFailed(_)));

        let jwt_err = PasskeyError::jwt("token expired");
        assert!(matches!(jwt_err, PasskeyError::JWT(_)));

        let config_err = PasskeyError::config("missing config");
        assert!(matches!(config_err, PasskeyError::ConfigError(_)));
    }

    #[test]
    fn test_all_error_codes() {
        assert_eq!(
            PasskeyError::AuthenticationFailed("test".to_string()).error_code(),
            "AUTH_FAILED"
        );
        assert_eq!(
            PasskeyError::AuthorizationFailed("test".to_string()).error_code(),
            "AUTH_DENIED"
        );
        assert_eq!(
            PasskeyError::ValidationFailed("test".to_string()).error_code(),
            "VALIDATION_FAILED"
        );
        assert_eq!(PasskeyError::UserNotFound.error_code(), "USER_NOT_FOUND");
        assert_eq!(
            PasskeyError::CredentialNotFound.error_code(),
            "CREDENTIAL_NOT_FOUND"
        );
        assert_eq!(
            PasskeyError::SessionNotFound.error_code(),
            "SESSION_NOT_FOUND"
        );
        assert_eq!(
            PasskeyError::AppConfigNotFound.error_code(),
            "APP_CONFIG_NOT_FOUND"
        );
        assert_eq!(
            PasskeyError::PendingUserNotFound.error_code(),
            "PENDING_USER_NOT_FOUND"
        );
        assert_eq!(PasskeyError::InvalidOtp("test".to_string()).error_code(), "INVALID_OTP");
        assert_eq!(PasskeyError::OtpExpired.error_code(), "OTP_EXPIRED");
        assert_eq!(
            PasskeyError::OtpMaxAttemptsExceeded.error_code(),
            "OTP_ATTEMPTS_EXCEEDED"
        );
        assert_eq!(
            PasskeyError::SystemTime("test".to_string()).error_code(),
            "SYSTEM_TIME_ERROR"
        );
        assert_eq!(
            PasskeyError::WebAuthn("test".to_string()).error_code(),
            "WEBAUTHN_ERROR"
        );
        assert_eq!(
            PasskeyError::JWT("test".to_string()).error_code(),
            "JWT_ERROR"
        );
        assert_eq!(
            PasskeyError::Database(DatabaseError::ItemNotFound).error_code(),
            "DATABASE_ERROR"
        );
        assert_eq!(
            PasskeyError::EmailService(EmailError::SendFailed).error_code(),
            "EMAIL_ERROR"
        );
        assert_eq!(
            PasskeyError::ConfigError("test".to_string()).error_code(),
            "CONFIG_ERROR"
        );
        assert_eq!(
            PasskeyError::RateLimitExceeded.error_code(),
            "RATE_LIMIT_EXCEEDED"
        );
        assert_eq!(PasskeyError::InternalError.error_code(), "INTERNAL_ERROR");
    }

    #[test]
    fn test_all_client_messages() {
        assert_eq!(
            PasskeyError::AuthenticationFailed("details".to_string()).client_message(),
            "Authentication failed"
        );
        assert_eq!(
            PasskeyError::AuthorizationFailed("details".to_string()).client_message(),
            "Access denied"
        );
        assert_eq!(
            PasskeyError::ValidationFailed("Email required".to_string()).client_message(),
            "Validation failed: Email required"
        );
        assert_eq!(
            PasskeyError::UserNotFound.client_message(),
            "User not found"
        );
        assert_eq!(
            PasskeyError::CredentialNotFound.client_message(),
            "Credential not found"
        );
        assert_eq!(
            PasskeyError::SessionNotFound.client_message(),
            "Session not found or expired"
        );
        assert_eq!(
            PasskeyError::AppConfigNotFound.client_message(),
            "Application not found"
        );
        assert_eq!(
            PasskeyError::PendingUserNotFound.client_message(),
            "Invitation not found or expired"
        );
        assert_eq!(
            PasskeyError::InvalidOtp("test".to_string()).client_message(),
            "Invalid verification code"
        );
        assert_eq!(
            PasskeyError::OtpExpired.client_message(),
            "Verification code has expired"
        );
        assert_eq!(
            PasskeyError::OtpMaxAttemptsExceeded.client_message(),
            "Too many verification attempts"
        );
        assert_eq!(
            PasskeyError::SystemTime("test".to_string()).client_message(),
            "System time error"
        );
        assert_eq!(
            PasskeyError::WebAuthn("details".to_string()).client_message(),
            "WebAuthn operation failed"
        );
        assert_eq!(
            PasskeyError::JWT("details".to_string()).client_message(),
            "Token validation failed"
        );
        assert_eq!(
            PasskeyError::Database(DatabaseError::ItemNotFound).client_message(),
            "Service temporarily unavailable"
        );
        assert_eq!(
            PasskeyError::EmailService(EmailError::SendFailed).client_message(),
            "Email service temporarily unavailable"
        );
        assert_eq!(
            PasskeyError::ConfigError("details".to_string()).client_message(),
            "Service configuration error"
        );
        assert_eq!(
            PasskeyError::RateLimitExceeded.client_message(),
            "Rate limit exceeded, please try again later"
        );
        assert_eq!(
            PasskeyError::InternalError.client_message(),
            "Internal server error"
        );
    }

    #[test]
    fn test_should_log_details_comprehensive() {
        // Errors that should log details (internal/infrastructure)
        assert!(PasskeyError::Database(DatabaseError::ItemNotFound).should_log_details());
        assert!(PasskeyError::EmailService(EmailError::SendFailed).should_log_details());
        assert!(PasskeyError::ConfigError("test".to_string()).should_log_details());
        assert!(PasskeyError::InternalError.should_log_details());

        // Errors that should NOT log details (client-facing)
        assert!(!PasskeyError::AuthenticationFailed("test".to_string()).should_log_details());
        assert!(!PasskeyError::AuthorizationFailed("test".to_string()).should_log_details());
        assert!(!PasskeyError::ValidationFailed("test".to_string()).should_log_details());
        assert!(!PasskeyError::UserNotFound.should_log_details());
        assert!(!PasskeyError::CredentialNotFound.should_log_details());
        assert!(!PasskeyError::SessionNotFound.should_log_details());
        assert!(!PasskeyError::AppConfigNotFound.should_log_details());
        assert!(!PasskeyError::PendingUserNotFound.should_log_details());
        assert!(!PasskeyError::InvalidOtp("test".to_string()).should_log_details());
        assert!(!PasskeyError::OtpExpired.should_log_details());
        assert!(!PasskeyError::OtpMaxAttemptsExceeded.should_log_details());
        assert!(!PasskeyError::SystemTime("test".to_string()).should_log_details());
        assert!(!PasskeyError::WebAuthn("test".to_string()).should_log_details());
        assert!(!PasskeyError::JWT("test".to_string()).should_log_details());
        assert!(!PasskeyError::RateLimitExceeded.should_log_details());
    }

    #[test]
    fn test_database_error_variants() {
        let db_error = DatabaseError::ConnectionFailed;
        assert_eq!(db_error.to_string(), "Database connection failed");

        let query_error = DatabaseError::QueryFailed("SELECT failed".to_string());
        assert_eq!(query_error.to_string(), "Query execution failed");

        let not_found = DatabaseError::ItemNotFound;
        assert_eq!(not_found.to_string(), "Item not found");

        let constraint = DatabaseError::ConstraintViolation("unique key".to_string());
        assert_eq!(constraint.to_string(), "Constraint violation: unique key");

        let serialization = DatabaseError::SerializationError("JSON error".to_string());
        assert_eq!(serialization.to_string(), "Serialization error: JSON error");

        let dynamodb = DatabaseError::DynamoDB("AWS error".to_string());
        assert_eq!(dynamodb.to_string(), "DynamoDB error: AWS error");
    }

    #[test]
    fn test_email_error_variants() {
        let send_failed = EmailError::SendFailed;
        assert_eq!(send_failed.to_string(), "Failed to send email");

        let invalid_addr = EmailError::InvalidAddress("not-email".to_string());
        assert_eq!(invalid_addr.to_string(), "Invalid email address: not-email");

        let template_err = EmailError::TemplateError("missing variable".to_string());
        assert_eq!(
            template_err.to_string(),
            "Email template error: missing variable"
        );

        let ses_err = EmailError::SESError("quota exceeded".to_string());
        assert_eq!(ses_err.to_string(), "SES error: quota exceeded");

        let rate_limit = EmailError::RateLimitExceeded;
        assert_eq!(rate_limit.to_string(), "Email rate limit exceeded");
    }

    #[test]
    fn test_error_conversions() {
        // Test From implementations for error conversions
        let db_error = DatabaseError::ItemNotFound;
        let passkey_error: PasskeyError = db_error.into();
        assert!(matches!(passkey_error, PasskeyError::Database(_)));

        let email_error = EmailError::SendFailed;
        let passkey_error: PasskeyError = email_error.into();
        assert!(matches!(passkey_error, PasskeyError::EmailService(_)));

        // Test JSON error conversion
        let json_str = "{invalid json";
        let json_error = serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
        let db_error: DatabaseError = json_error.into();
        assert!(matches!(db_error, DatabaseError::SerializationError(_)));
    }
}
