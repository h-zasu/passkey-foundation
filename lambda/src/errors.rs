//! GraphQL error handling for the Passkey authentication system
//!
//! This module provides comprehensive error handling for GraphQL operations,
//! including error classification, user-safe messages, and structured logging.

use async_graphql::{Error as GraphQLError, ErrorExtensions};
use serde_json::Value;
use shared::PasskeyError;
use std::collections::HashMap;
use tracing::{error, warn, info};

/// GraphQL-specific error codes for client handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphQLErrorCode {
    /// Internal server error (500)
    InternalError,
    /// Authentication required (401)
    Unauthorized,
    /// Insufficient permissions (403)
    Forbidden,
    /// Resource not found (404)
    NotFound,
    /// Invalid input data (400)
    BadRequest,
    /// Rate limit exceeded (429)
    RateLimited,
    /// External service unavailable (503)
    ServiceUnavailable,
    /// Database operation failed
    DatabaseError,
    /// WebAuthn operation failed
    WebAuthnError,
    /// JWT token error
    TokenError,
    /// OTP validation failed
    OTPError,
}

impl GraphQLErrorCode {
    /// Returns the string representation of the error code
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InternalError => "INTERNAL_ERROR",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden => "FORBIDDEN",
            Self::NotFound => "NOT_FOUND", 
            Self::BadRequest => "BAD_REQUEST",
            Self::RateLimited => "RATE_LIMITED",
            Self::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            Self::DatabaseError => "DATABASE_ERROR",
            Self::WebAuthnError => "WEBAUTHN_ERROR",
            Self::TokenError => "TOKEN_ERROR",
            Self::OTPError => "OTP_ERROR",
        }
    }

    /// Returns the HTTP status code equivalent
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InternalError => 500,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::BadRequest => 400,
            Self::RateLimited => 429,
            Self::ServiceUnavailable => 503,
            Self::DatabaseError => 500,
            Self::WebAuthnError => 400,
            Self::TokenError => 401,
            Self::OTPError => 400,
        }
    }

    /// Returns whether this error should be logged with full details
    pub fn should_log_details(&self) -> bool {
        match self {
            Self::InternalError | Self::DatabaseError | Self::ServiceUnavailable => true,
            _ => false,
        }
    }

    /// Returns a user-safe error message
    pub fn user_message(&self) -> &'static str {
        match self {
            Self::InternalError => "An internal server error occurred",
            Self::Unauthorized => "Authentication required",
            Self::Forbidden => "Insufficient permissions",
            Self::NotFound => "Resource not found",
            Self::BadRequest => "Invalid request data",
            Self::RateLimited => "Too many requests, please try again later",
            Self::ServiceUnavailable => "Service temporarily unavailable",
            Self::DatabaseError => "Database error",
            Self::WebAuthnError => "WebAuthn operation failed",
            Self::TokenError => "Invalid or expired token",
            Self::OTPError => "Invalid or expired verification code",
        }
    }
}

/// Enhanced GraphQL error with structured information
#[derive(Debug)]
pub struct PasskeyGraphQLError {
    pub code: GraphQLErrorCode,
    pub message: String,
    pub details: Option<String>,
    pub request_id: Option<String>,
    pub user_id: Option<String>,
    pub app_id: Option<String>,
}

impl PasskeyGraphQLError {
    /// Creates a new PasskeyGraphQLError
    pub fn new(code: GraphQLErrorCode, message: String) -> Self {
        Self {
            code,
            message,
            details: None,
            request_id: None,
            user_id: None,
            app_id: None,
        }
    }

    /// Adds contextual details to the error
    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    /// Adds request ID for tracing
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Adds user context
    pub fn with_user(mut self, user_id: String, app_id: String) -> Self {
        self.user_id = Some(user_id);
        self.app_id = Some(app_id);
        self
    }

    /// Converts to GraphQL error with extensions
    pub fn into_graphql_error(self) -> GraphQLError {
        // Log the error appropriately
        self.log_error();

        // Create user-safe message
        let user_message = if self.code.should_log_details() {
            // For sensitive errors, use generic message
            self.code.user_message().to_string()
        } else {
            // For client errors, can show more specific message
            self.message.clone()
        };

        // Build extensions with error metadata
        let mut error = GraphQLError::new(user_message);
        error = error.extend_with(|_, e| {
            e.set("code", self.code.as_str());
            e.set("statusCode", self.code.http_status() as i32);
            
            if let Some(request_id) = &self.request_id {
                e.set("requestId", request_id.as_str());
            }
        });

        error
    }

    /// Logs the error with appropriate level and context
    fn log_error(&self) {
        let base_message = format!(
            "GraphQL Error [{}]: {}",
            self.code.as_str(),
            self.message
        );

        let context = self.build_log_context();

        match self.code {
            GraphQLErrorCode::InternalError | GraphQLErrorCode::DatabaseError => {
                error!(
                    message = %base_message,
                    error_code = %self.code.as_str(),
                    details = ?self.details,
                    request_id = ?self.request_id,
                    user_id = ?self.user_id,
                    app_id = ?self.app_id,
                    "Internal error occurred"
                );
            }
            GraphQLErrorCode::Unauthorized | GraphQLErrorCode::Forbidden => {
                warn!(
                    message = %base_message,
                    error_code = %self.code.as_str(),
                    request_id = ?self.request_id,
                    user_id = ?self.user_id,
                    app_id = ?self.app_id,
                    "Authorization error"
                );
            }
            _ => {
                info!(
                    message = %base_message,
                    error_code = %self.code.as_str(),
                    request_id = ?self.request_id,
                    user_id = ?self.user_id,
                    app_id = ?self.app_id,
                    "Client error"
                );
            }
        }
    }

    /// Builds structured log context
    fn build_log_context(&self) -> HashMap<&'static str, Value> {
        let mut context = HashMap::new();
        
        context.insert("error_code", Value::String(self.code.as_str().to_string()));
        context.insert("http_status", Value::Number(self.code.http_status().into()));
        
        if let Some(request_id) = &self.request_id {
            context.insert("request_id", Value::String(request_id.clone()));
        }
        
        if let Some(user_id) = &self.user_id {
            context.insert("user_id", Value::String(user_id.clone()));
        }
        
        if let Some(app_id) = &self.app_id {
            context.insert("app_id", Value::String(app_id.clone()));
        }
        
        if let Some(details) = &self.details {
            // Only include details for internal errors
            if self.code.should_log_details() {
                context.insert("error_details", Value::String(details.clone()));
            }
        }
        
        context
    }
}

/// Converts shared::PasskeyError to GraphQL error
impl From<PasskeyError> for PasskeyGraphQLError {
    fn from(error: PasskeyError) -> Self {
        let (code, message) = match &error {
            PasskeyError::Database(_) => (GraphQLErrorCode::DatabaseError, "Database error".to_string()),
            PasskeyError::WebAuthn(_) => (GraphQLErrorCode::WebAuthnError, "WebAuthn operation failed".to_string()),
            PasskeyError::JWT(_) => (GraphQLErrorCode::TokenError, "Token error".to_string()),
            PasskeyError::InvalidOtp(_) | PasskeyError::OtpExpired | PasskeyError::OtpMaxAttemptsExceeded => {
                (GraphQLErrorCode::OTPError, "OTP verification failed".to_string())
            },
            PasskeyError::EmailService(_) => (GraphQLErrorCode::ServiceUnavailable, "Email service error".to_string()),
            PasskeyError::Configuration(_) | PasskeyError::ConfigError(_) => {
                (GraphQLErrorCode::InternalError, "Configuration error".to_string())
            },
            PasskeyError::UserNotFound | PasskeyError::CredentialNotFound | PasskeyError::SessionNotFound 
            | PasskeyError::AppConfigNotFound | PasskeyError::PendingUserNotFound => {
                (GraphQLErrorCode::NotFound, "Resource not found".to_string())
            },
            PasskeyError::ValidationFailed(_) => (GraphQLErrorCode::BadRequest, "Invalid input".to_string()),
            PasskeyError::AuthenticationFailed(_) => (GraphQLErrorCode::Unauthorized, "Authentication failed".to_string()),
            PasskeyError::AuthorizationFailed(_) => (GraphQLErrorCode::Forbidden, "Authorization failed".to_string()),
            PasskeyError::InvalidAppId(_) | PasskeyError::InvalidUserId(_) | PasskeyError::InvalidCredential(_) => {
                (GraphQLErrorCode::BadRequest, "Invalid request".to_string())
            },
            PasskeyError::RateLimitExceeded => (GraphQLErrorCode::RateLimited, "Rate limit exceeded".to_string()),
            PasskeyError::SystemTime(_) | PasskeyError::InternalError => {
                (GraphQLErrorCode::InternalError, "Internal server error".to_string())
            },
        };

        Self::new(code, message).with_details(error.to_string())
    }
}

/// Converts any std::error::Error to GraphQL error
impl From<Box<dyn std::error::Error + Send + Sync>> for PasskeyGraphQLError {
    fn from(error: Box<dyn std::error::Error + Send + Sync>) -> Self {
        // Try to downcast to known error types first
        if let Some(passkey_error) = error.downcast_ref::<PasskeyError>() {
            return (*passkey_error).clone().into();
        }

        // Check for permission denied errors
        if let Some(io_error) = error.downcast_ref::<std::io::Error>() {
            match io_error.kind() {
                std::io::ErrorKind::PermissionDenied => {
                    return Self::new(GraphQLErrorCode::Forbidden, "Insufficient permissions".to_string())
                        .with_details(error.to_string());
                }
                std::io::ErrorKind::NotFound => {
                    return Self::new(GraphQLErrorCode::NotFound, "Resource not found".to_string())
                        .with_details(error.to_string());
                }
                _ => {}
            }
        }

        // Default to internal error for unknown errors
        Self::new(GraphQLErrorCode::InternalError, "Internal server error".to_string())
            .with_details(error.to_string())
    }
}

/// Helper trait for easy error conversion
pub trait IntoGraphQLError {
    fn into_graphql_error(self) -> GraphQLError;
    fn into_graphql_error_with_context(self, app_id: &str, user_id: Option<&str>) -> GraphQLError;
}

impl<E> IntoGraphQLError for E 
where 
    E: Into<PasskeyGraphQLError>
{
    fn into_graphql_error(self) -> GraphQLError {
        let passkey_error: PasskeyGraphQLError = self.into();
        passkey_error.into_graphql_error()
    }

    fn into_graphql_error_with_context(self, app_id: &str, user_id: Option<&str>) -> GraphQLError {
        let mut passkey_error: PasskeyGraphQLError = self.into();
        
        passkey_error.app_id = Some(app_id.to_string());
        if let Some(uid) = user_id {
            passkey_error.user_id = Some(uid.to_string());
        }

        // Generate request ID for tracing
        passkey_error.request_id = Some(uuid::Uuid::new_v4().to_string());
        
        passkey_error.into_graphql_error()
    }
}

/// Convenience functions for common error scenarios
pub fn unauthorized_error(message: &str) -> GraphQLError {
    PasskeyGraphQLError::new(GraphQLErrorCode::Unauthorized, message.to_string())
        .into_graphql_error()
}

pub fn forbidden_error(message: &str) -> GraphQLError {
    PasskeyGraphQLError::new(GraphQLErrorCode::Forbidden, message.to_string())
        .into_graphql_error()
}

pub fn not_found_error(message: &str) -> GraphQLError {
    PasskeyGraphQLError::new(GraphQLErrorCode::NotFound, message.to_string())
        .into_graphql_error()
}

pub fn bad_request_error(message: &str) -> GraphQLError {
    PasskeyGraphQLError::new(GraphQLErrorCode::BadRequest, message.to_string())
        .into_graphql_error()
}

pub fn internal_error(message: &str) -> GraphQLError {
    PasskeyGraphQLError::new(GraphQLErrorCode::InternalError, message.to_string())
        .into_graphql_error()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_properties() {
        let code = GraphQLErrorCode::Unauthorized;
        assert_eq!(code.as_str(), "UNAUTHORIZED");
        assert_eq!(code.http_status(), 401);
        assert_eq!(code.user_message(), "Authentication required");
        assert!(!code.should_log_details());
    }

    #[test]
    fn test_internal_error_logging() {
        let code = GraphQLErrorCode::InternalError;
        assert!(code.should_log_details());
        assert_eq!(code.http_status(), 500);
    }

    #[test]
    fn test_passkey_error_conversion() {
        let database_error = shared::DatabaseError::QueryFailed("Connection failed".to_string());
        let passkey_error = PasskeyError::Database(database_error);
        let graphql_error: PasskeyGraphQLError = passkey_error.into();
        
        assert_eq!(graphql_error.code, GraphQLErrorCode::DatabaseError);
        assert_eq!(graphql_error.message, "Database error");
        assert!(graphql_error.details.is_some());
    }

    #[test]
    fn test_error_with_context() {
        let error = PasskeyGraphQLError::new(
            GraphQLErrorCode::NotFound, 
            "User not found".to_string()
        )
        .with_user("user123".to_string(), "app456".to_string())
        .with_request_id("req789".to_string());

        assert_eq!(error.user_id.as_ref().unwrap(), "user123");
        assert_eq!(error.app_id.as_ref().unwrap(), "app456");
        assert_eq!(error.request_id.as_ref().unwrap(), "req789");
    }

    #[test]
    fn test_convenience_functions() {
        let error = unauthorized_error("Token missing");
        assert!(error.message.contains("Token missing"));
        
        let error = forbidden_error("Admin required");
        assert!(error.message.contains("Admin required"));
    }
}