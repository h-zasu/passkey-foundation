//! Common data types for the multi-application authentication system.
//!
//! This module defines shared data structures used across different components
//! of the authentication system, including user data, credentials, sessions,
//! and application configurations. All data types support multi-application
//! isolation through application identifiers (app_id).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// User account information with application isolation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Application identifier for data isolation
    pub app_id: String,
    /// Unique user identifier (UUID v4) within the application
    pub user_id: String,
    /// User's email address (unique within the application)
    pub email: String,
    /// User's display name
    pub display_name: String,
    /// Account creation timestamp (ISO 8601)
    pub created_at: String,
    /// Last update timestamp (ISO 8601)
    pub updated_at: String,
    /// Account active status
    pub is_active: bool,
    /// Last login timestamp (ISO 8601)
    pub last_login: Option<String>,
}

impl User {
    /// Creates a new user with the given application ID, email and display name.
    pub fn new(app_id: String, email: String, display_name: String) -> Self {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        Self {
            app_id,
            user_id: Uuid::new_v4().to_string(),
            email,
            display_name,
            created_at: now.clone(),
            updated_at: now,
            is_active: true,
            last_login: None,
        }
    }

    /// Gets the DynamoDB primary key with app_id prefix.
    pub fn primary_key(&self) -> String {
        format!("{}#{}", self.app_id, self.user_id)
    }
}

/// WebAuthn credential information with application isolation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    /// Application identifier for data isolation
    pub app_id: String,
    /// Base64 encoded authenticator ID
    pub credential_id: String,
    /// User UUID v4 within the application
    pub user_id: String,
    /// Base64 encoded public key
    pub public_key: String,
    /// Usage counter (replay attack prevention)
    pub counter: u32,
    /// Authenticator Attestation GUID
    pub aaguid: String,
    /// Supported transports
    pub transports: Vec<String>,
    /// User verification requirement level
    pub user_verification: String,
    /// Creation timestamp (ISO 8601)
    pub created_at: String,
    /// Last usage timestamp (ISO 8601)
    pub last_used: String,
    /// User-defined device name
    pub device_name: Option<String>,
    /// Credential active status
    pub is_active: bool,
}

impl Credential {
    /// Gets the DynamoDB primary key with app_id prefix.
    pub fn primary_key(&self) -> String {
        format!("{}#{}", self.app_id, self.credential_id)
    }

    /// Gets the DynamoDB sort key with app_id prefix.
    pub fn sort_key(&self) -> String {
        format!("{}#{}", self.app_id, self.user_id)
    }
}

/// Authentication session data with application isolation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Application identifier for data isolation
    pub app_id: String,
    /// Unique session identifier (UUID v4) within the application
    pub session_id: String,
    /// User UUID (set after registration completion)
    pub user_id: Option<String>,
    /// Base64 encoded WebAuthn challenge
    pub challenge: String,
    /// Session type ("registration" or "authentication")
    pub session_type: SessionType,
    /// WebAuthn RP ID (from application configuration)
    pub relying_party_id: String,
    /// Base64 encoded user handle
    pub user_handle: Option<String>,
    /// Email address for registration
    pub user_email: Option<String>,
    /// Display name for registration
    pub user_display_name: Option<String>,
    /// Client data JSON
    pub client_data_json: Option<String>,
    /// Registration options (JSON)
    pub public_key_credential_creation_options: Option<String>,
    /// Authentication options (JSON)
    pub public_key_credential_request_options: Option<String>,
    /// Creation timestamp (ISO 8601)
    pub created_at: String,
    /// Unix timestamp for TTL
    pub expires_at: i64,
    /// Client IP address
    pub ip_address: String,
    /// User-Agent header
    pub user_agent: String,
    /// Session status
    pub status: SessionStatus,
}

impl Session {
    /// Creates a new registration session with app-specific timeout.
    #[allow(clippy::too_many_arguments)]
    pub fn new_registration(
        app_id: String,
        challenge: String,
        relying_party_id: String,
        user_email: String,
        user_display_name: String,
        ip_address: String,
        user_agent: String,
        session_timeout_seconds: u64,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(session_timeout_seconds as i64);

        Self {
            app_id,
            session_id: Uuid::new_v4().to_string(),
            user_id: None,
            challenge,
            session_type: SessionType::Registration,
            relying_party_id,
            user_handle: None,
            user_email: Some(user_email),
            user_display_name: Some(user_display_name),
            client_data_json: None,
            public_key_credential_creation_options: None,
            public_key_credential_request_options: None,
            created_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            expires_at: expires_at.unix_timestamp(),
            ip_address,
            user_agent,
            status: SessionStatus::Active,
        }
    }

    /// Creates a new authentication session with app-specific timeout.
    pub fn new_authentication(
        app_id: String,
        challenge: String,
        relying_party_id: String,
        user_id: String,
        ip_address: String,
        user_agent: String,
        session_timeout_seconds: u64,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(session_timeout_seconds as i64);

        Self {
            app_id,
            session_id: Uuid::new_v4().to_string(),
            user_id: Some(user_id),
            challenge,
            session_type: SessionType::Authentication,
            relying_party_id,
            user_handle: None,
            user_email: None,
            user_display_name: None,
            client_data_json: None,
            public_key_credential_creation_options: None,
            public_key_credential_request_options: None,
            created_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            expires_at: expires_at.unix_timestamp(),
            ip_address,
            user_agent,
            status: SessionStatus::Active,
        }
    }

    /// Gets the DynamoDB primary key with app_id prefix.
    pub fn primary_key(&self) -> String {
        format!("{}#{}", self.app_id, self.session_id)
    }
}

/// Session type enumeration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    /// Registration session
    Registration,
    /// Authentication session
    Authentication,
}

/// Session status enumeration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    /// Session is active
    Active,
    /// Session completed successfully
    Completed,
    /// Session expired
    Expired,
    /// Session marked as invalid
    Invalid,
}

/// Application configuration for multi-app support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Unique application identifier
    pub app_id: String,
    /// Application display name
    pub name: String,
    /// WebAuthn Relying Party ID
    pub relying_party_id: String,
    /// WebAuthn Relying Party Name
    pub relying_party_name: String,
    /// Allowed origins for CORS
    pub allowed_origins: Vec<String>,
    /// JWT signing secret (unique per app)
    pub jwt_secret: String,
    /// JWT token expiration time in seconds
    pub jwt_expires_in: u64,
    /// Session timeout in seconds (WebAuthn challenge validity)
    pub session_timeout_seconds: u64,
    /// Application creation timestamp (ISO 8601)
    pub created_at: String,
    /// Application active status
    pub is_active: bool,
}

impl AppConfig {
    /// Creates a new application configuration.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app_id: String,
        name: String,
        relying_party_id: String,
        relying_party_name: String,
        allowed_origins: Vec<String>,
        jwt_secret: String,
        jwt_expires_in: u64,
        session_timeout_seconds: u64,
    ) -> Self {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();

        Self {
            app_id,
            name,
            relying_party_id,
            relying_party_name,
            allowed_origins,
            jwt_secret,
            jwt_expires_in,
            session_timeout_seconds,
            created_at: now,
            is_active: true,
        }
    }

    /// Gets the default configuration for development.
    pub fn default_dev(app_id: String) -> Self {
        Self::new(
            app_id.clone(),
            format!("{app_id} Development"),
            "localhost:3000".to_string(),
            format!("{app_id} Dev"),
            vec!["http://localhost:3000".to_string()],
            format!("dev-secret-{app_id}"),
            3600, // 1 hour JWT
            300,  // 5 minutes session
        )
    }
}
