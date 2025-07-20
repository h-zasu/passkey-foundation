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
    /// User's role within the application
    pub role: UserRole,
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
    /// Creates a new user with the given application ID, email, display name, and role.
    pub fn new(app_id: String, email: String, display_name: String, role: UserRole) -> Self {
        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        Self {
            app_id,
            user_id: Uuid::new_v4().to_string(),
            email,
            display_name,
            role,
            created_at: now.clone(),
            updated_at: now,
            is_active: true,
            last_login: None,
        }
    }

    /// Creates a new regular user (convenience method).
    pub fn new_user(app_id: String, email: String, display_name: String) -> Self {
        Self::new(app_id, email, display_name, UserRole::User)
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

/// User role enumeration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[derive(Default)]
pub enum UserRole {
    /// Regular user
    #[default]
    User,
    /// Application administrator
    Admin,
    /// Super administrator with cross-app access
    SuperAdmin,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::User => write!(f, "user"),
            UserRole::Admin => write!(f, "admin"),
            UserRole::SuperAdmin => write!(f, "super_admin"),
        }
    }
}

impl std::str::FromStr for UserRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "user" => Ok(UserRole::User),
            "admin" => Ok(UserRole::Admin),
            "super_admin" => Ok(UserRole::SuperAdmin),
            _ => Err(format!("Invalid user role: {s}")),
        }
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

impl std::fmt::Display for SessionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionType::Registration => write!(f, "registration"),
            SessionType::Authentication => write!(f, "authentication"),
        }
    }
}

impl std::str::FromStr for SessionType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "registration" => Ok(SessionType::Registration),
            "authentication" => Ok(SessionType::Authentication),
            _ => Err(format!("Invalid session type: {s}")),
        }
    }
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

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Active => write!(f, "active"),
            SessionStatus::Completed => write!(f, "completed"),
            SessionStatus::Expired => write!(f, "expired"),
            SessionStatus::Invalid => write!(f, "invalid"),
        }
    }
}

impl std::str::FromStr for SessionStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(SessionStatus::Active),
            "completed" => Ok(SessionStatus::Completed),
            "expired" => Ok(SessionStatus::Expired),
            "invalid" => Ok(SessionStatus::Invalid),
            _ => Err(format!("Invalid session status: {s}")),
        }
    }
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
    /// OTP expiration time in seconds
    pub otp_expires_in: u64,
    /// Application creation timestamp (ISO 8601)
    pub created_at: String,
    /// Last update timestamp (ISO 8601)
    pub updated_at: String,
    /// Application active status
    pub is_active: bool,
    /// Admin email addresses
    pub admin_emails: Vec<String>,
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
        otp_expires_in: u64,
        admin_emails: Vec<String>,
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
            otp_expires_in,
            created_at: now.clone(),
            updated_at: now,
            is_active: true,
            admin_emails,
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
            1800, // 30 minutes OTP
            vec![format!("admin@{app_id}.localhost")],
        )
    }

    /// Gets the DynamoDB primary key.
    pub fn primary_key(&self) -> String {
        self.app_id.clone()
    }
}

/// Pending user information for invitation-based registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingUser {
    /// Unique pending user identifier (UUID v4)
    pub pending_user_id: String,
    /// Application identifier for data isolation
    pub app_id: String,
    /// User's email address
    pub email: String,
    /// SHA-256 hash of the OTP
    pub otp_hash: String,
    /// Random salt for OTP hashing
    pub otp_salt: String,
    /// Number of OTP verification attempts
    pub otp_attempts: u32,
    /// Invitation timestamp (ISO 8601)
    pub invited_at: String,
    /// Unix timestamp for TTL expiration
    pub expires_at: i64,
    /// Admin user ID who sent the invitation
    pub invited_by: String,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

impl PendingUser {
    /// Creates a new pending user with OTP hash.
    pub fn new(
        app_id: String,
        email: String,
        otp_hash: String,
        otp_salt: String,
        invited_by: String,
        otp_expires_in: u64,
    ) -> Self {
        let now = OffsetDateTime::now_utc();
        let expires_at = now + time::Duration::seconds(otp_expires_in as i64);

        Self {
            pending_user_id: Uuid::new_v4().to_string(),
            app_id,
            email,
            otp_hash,
            otp_salt,
            otp_attempts: 0,
            invited_at: now
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
            expires_at: expires_at.unix_timestamp(),
            invited_by,
            metadata: None,
        }
    }

    /// Gets the DynamoDB primary key with app_id prefix.
    pub fn primary_key(&self) -> String {
        format!("{}#{}", self.app_id, self.email)
    }

    /// Increments the OTP attempt counter.
    pub fn increment_attempts(&mut self) {
        self.otp_attempts += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_new() {
        let user = User::new(
            "test_app".to_string(),
            "test@example.com".to_string(),
            "Test User".to_string(),
            UserRole::Admin,
        );

        assert_eq!(user.app_id, "test_app");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.display_name, "Test User");
        assert_eq!(user.role, UserRole::Admin);
        assert!(!user.user_id.is_empty());
        assert!(user.is_active);
        assert!(user.last_login.is_none());
        assert!(!user.created_at.is_empty());
        assert!(!user.updated_at.is_empty());
    }

    #[test]
    fn test_user_new_user_convenience() {
        let user = User::new_user(
            "test_app".to_string(),
            "user@example.com".to_string(),
            "Regular User".to_string(),
        );

        assert_eq!(user.role, UserRole::User);
        assert_eq!(user.email, "user@example.com");
    }

    #[test]
    fn test_user_primary_key() {
        let user = User {
            app_id: "test_app".to_string(),
            user_id: "user123".to_string(),
            email: "test@example.com".to_string(),
            display_name: "Test".to_string(),
            role: UserRole::User,
            created_at: "2023-01-01T00:00:00Z".to_string(),
            updated_at: "2023-01-01T00:00:00Z".to_string(),
            is_active: true,
            last_login: None,
        };

        assert_eq!(user.primary_key(), "test_app#user123");
    }

    #[test]
    fn test_user_role_display() {
        assert_eq!(UserRole::User.to_string(), "user");
        assert_eq!(UserRole::Admin.to_string(), "admin");
        assert_eq!(UserRole::SuperAdmin.to_string(), "super_admin");
    }

    #[test]
    fn test_user_role_from_str() {
        assert_eq!("user".parse::<UserRole>().unwrap(), UserRole::User);
        assert_eq!("admin".parse::<UserRole>().unwrap(), UserRole::Admin);
        assert_eq!(
            "super_admin".parse::<UserRole>().unwrap(),
            UserRole::SuperAdmin
        );
        assert!("invalid".parse::<UserRole>().is_err());
    }

    #[test]
    fn test_user_role_default() {
        assert_eq!(UserRole::default(), UserRole::User);
    }

    #[test]
    fn test_session_type_display() {
        assert_eq!(SessionType::Registration.to_string(), "registration");
        assert_eq!(SessionType::Authentication.to_string(), "authentication");
    }

    #[test]
    fn test_session_type_from_str() {
        assert_eq!(
            "registration".parse::<SessionType>().unwrap(),
            SessionType::Registration
        );
        assert_eq!(
            "authentication".parse::<SessionType>().unwrap(),
            SessionType::Authentication
        );
        assert!("invalid".parse::<SessionType>().is_err());
    }

    #[test]
    fn test_session_status_display() {
        assert_eq!(SessionStatus::Active.to_string(), "active");
        assert_eq!(SessionStatus::Completed.to_string(), "completed");
        assert_eq!(SessionStatus::Expired.to_string(), "expired");
        assert_eq!(SessionStatus::Invalid.to_string(), "invalid");
    }

    #[test]
    fn test_session_status_from_str() {
        assert_eq!(
            "active".parse::<SessionStatus>().unwrap(),
            SessionStatus::Active
        );
        assert_eq!(
            "completed".parse::<SessionStatus>().unwrap(),
            SessionStatus::Completed
        );
        assert_eq!(
            "expired".parse::<SessionStatus>().unwrap(),
            SessionStatus::Expired
        );
        assert_eq!(
            "invalid".parse::<SessionStatus>().unwrap(),
            SessionStatus::Invalid
        );
        assert!("unknown".parse::<SessionStatus>().is_err());
    }

    #[test]
    fn test_credential_primary_key() {
        let credential = Credential {
            app_id: "test_app".to_string(),
            credential_id: "cred123".to_string(),
            user_id: "user123".to_string(),
            public_key: "pk123".to_string(),
            counter: 1,
            aaguid: "guid".to_string(),
            transports: vec!["usb".to_string()],
            user_verification: "required".to_string(),
            created_at: "2023-01-01T00:00:00Z".to_string(),
            last_used: "2023-01-01T00:00:00Z".to_string(),
            device_name: Some("Device".to_string()),
            is_active: true,
        };

        assert_eq!(credential.primary_key(), "test_app#cred123");
    }

    #[test]
    fn test_session_new_registration() {
        let session = Session::new_registration(
            "test_app".to_string(),
            "challenge123".to_string(),
            "example.com".to_string(),
            "user@example.com".to_string(),
            "Test User".to_string(),
            "192.168.1.1".to_string(),
            "TestAgent/1.0".to_string(),
            300,
        );

        assert_eq!(session.app_id, "test_app");
        assert_eq!(session.challenge, "challenge123");
        assert_eq!(session.session_type, SessionType::Registration);
        assert_eq!(session.relying_party_id, "example.com");
        assert_eq!(session.user_email, Some("user@example.com".to_string()));
        assert_eq!(session.user_display_name, Some("Test User".to_string()));
        assert_eq!(session.ip_address, "192.168.1.1");
        assert_eq!(session.user_agent, "TestAgent/1.0");
        assert_eq!(session.status, SessionStatus::Active);
        assert!(session.user_id.is_none());
        assert!(!session.session_id.is_empty());
    }

    #[test]
    fn test_session_new_authentication() {
        let session = Session::new_authentication(
            "test_app".to_string(),
            "challenge456".to_string(),
            "example.com".to_string(),
            "user123".to_string(),
            "192.168.1.1".to_string(),
            "TestAgent/1.0".to_string(),
            300,
        );

        assert_eq!(session.app_id, "test_app");
        assert_eq!(session.challenge, "challenge456");
        assert_eq!(session.session_type, SessionType::Authentication);
        assert_eq!(session.user_id, Some("user123".to_string()));
        assert_eq!(session.status, SessionStatus::Active);
        assert!(session.user_email.is_none());
        assert!(session.user_display_name.is_none());
    }

    #[test]
    fn test_session_primary_key() {
        let session = Session {
            app_id: "test_app".to_string(),
            session_id: "session123".to_string(),
            user_id: None,
            challenge: "challenge".to_string(),
            session_type: SessionType::Registration,
            relying_party_id: "example.com".to_string(),
            user_handle: None,
            user_email: None,
            user_display_name: None,
            client_data_json: None,
            public_key_credential_creation_options: None,
            public_key_credential_request_options: None,
            created_at: "2023-01-01T00:00:00Z".to_string(),
            expires_at: 1672531200,
            ip_address: "192.168.1.1".to_string(),
            user_agent: "TestAgent/1.0".to_string(),
            status: SessionStatus::Active,
        };

        assert_eq!(session.primary_key(), "test_app#session123");
    }

    #[test]
    fn test_pending_user_new() {
        let pending_user = PendingUser::new(
            "test_app".to_string(),
            "pending@example.com".to_string(),
            "hash123".to_string(),
            "salt123".to_string(),
            "admin_user".to_string(),
            1800,
        );

        assert_eq!(pending_user.app_id, "test_app");
        assert_eq!(pending_user.email, "pending@example.com");
        assert_eq!(pending_user.otp_hash, "hash123");
        assert_eq!(pending_user.otp_salt, "salt123");
        assert_eq!(pending_user.invited_by, "admin_user");
        assert_eq!(pending_user.otp_attempts, 0);
        assert!(!pending_user.pending_user_id.is_empty());
        assert!(!pending_user.invited_at.is_empty());
        assert!(pending_user.expires_at > 0);
        assert!(pending_user.metadata.is_none());
    }

    #[test]
    fn test_pending_user_primary_key() {
        let pending_user = PendingUser {
            pending_user_id: "pending123".to_string(),
            app_id: "test_app".to_string(),
            email: "pending@example.com".to_string(),
            otp_hash: "hash".to_string(),
            otp_salt: "salt".to_string(),
            otp_attempts: 0,
            invited_at: "2023-01-01T00:00:00Z".to_string(),
            expires_at: 1672531200,
            invited_by: "admin".to_string(),
            metadata: None,
        };

        assert_eq!(pending_user.primary_key(), "test_app#pending@example.com");
    }

    #[test]
    fn test_pending_user_increment_attempts() {
        let mut pending_user = PendingUser::new(
            "test_app".to_string(),
            "test@example.com".to_string(),
            "hash".to_string(),
            "salt".to_string(),
            "admin".to_string(),
            1800,
        );

        assert_eq!(pending_user.otp_attempts, 0);
        pending_user.increment_attempts();
        assert_eq!(pending_user.otp_attempts, 1);
        pending_user.increment_attempts();
        assert_eq!(pending_user.otp_attempts, 2);
    }

    #[test]
    fn test_app_config_default_dev() {
        let config = AppConfig::default_dev("test_app".to_string());

        assert_eq!(config.app_id, "test_app");
        assert_eq!(config.name, "test_app Development");
        assert_eq!(config.relying_party_id, "localhost:3000");
        assert_eq!(config.relying_party_name, "test_app Dev");
        assert_eq!(config.allowed_origins, vec!["http://localhost:3000"]);
        assert_eq!(config.jwt_expires_in, 3600);
        assert_eq!(config.session_timeout_seconds, 300);
        assert_eq!(config.otp_expires_in, 1800);
        assert!(config.is_active);
        assert!(!config.jwt_secret.is_empty());
        assert!(!config.created_at.is_empty());
        assert!(!config.updated_at.is_empty());
    }
}
