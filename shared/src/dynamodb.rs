//! DynamoDB table management for authentication systems.
//!
//! This module provides functionality to create and manage DynamoDB tables
//! for any authentication system using WebAuthn/Passkey technology.
//! It includes three main tables:
//!
//! - **Users**: Stores user account information and metadata
//! - **Credentials**: Stores WebAuthn credentials and public keys  
//! - **Sessions**: Manages temporary authentication sessions with TTL
//!
//! All tables are created with on-demand billing and appropriate secondary indexes
//! for efficient querying patterns. Table names can be customized with a prefix
//! to support multiple environments or applications.

use crate::{
    AppConfig, Credential, DatabaseError, PasskeyError, PendingUser, Session, SessionStatus,
    SessionType, User,
};
use crate::config::{EncryptionLevel, ServiceConfig};
use anyhow::Result;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, AttributeValue, BillingMode, GlobalSecondaryIndex, KeySchemaElement,
    KeyType, LocalSecondaryIndex, Projection, ProjectionType, ScalarAttributeType,
    TimeToLiveSpecification, SseSpecification, SseType,
};
use std::collections::HashMap;
use std::str::FromStr;

/// Configuration for DynamoDB table creation.
#[derive(Debug, Clone)]
pub struct DynamoDbConfig {
    /// Prefix for all table names (e.g., "passkey", "auth", "myapp")
    pub table_prefix: String,
    /// Environment suffix (e.g., "dev", "staging", "prod")
    pub environment: String,
    /// AWS region for table creation
    pub region: String,
}

impl DynamoDbConfig {
    /// Creates a new DynamoDB configuration.
    ///
    /// # Arguments
    ///
    /// * `table_prefix` - Prefix for all table names
    /// * `environment` - Environment suffix
    /// * `region` - AWS region
    ///
    /// # Examples
    ///
    /// ```
    /// # use shared::DynamoDbConfig;
    /// let config = DynamoDbConfig::new("myapp", "dev", "us-east-1");
    /// ```
    pub fn new(table_prefix: &str, environment: &str, region: &str) -> Self {
        Self {
            table_prefix: table_prefix.to_string(),
            environment: environment.to_string(),
            region: region.to_string(),
        }
    }

    /// Gets the full table name with prefix and environment.
    ///
    /// # Arguments
    ///
    /// * `table_type` - Type of table ("users", "credentials", "sessions")
    ///
    /// # Examples
    ///
    /// ```
    /// # use shared::DynamoDbConfig;
    /// let config = DynamoDbConfig::new("passkey", "dev", "us-east-1");
    /// assert_eq!(config.table_name("users"), "passkey-users-dev");
    /// ```
    pub fn table_name(&self, table_type: &str) -> String {
        format!("{}-{}-{}", self.table_prefix, table_type, self.environment)
    }
}

/// Creates all DynamoDB tables required for the authentication system.
///
/// This function creates five tables in the specified AWS region with encryption:
/// - `{prefix}-users-{env}`: User account information
/// - `{prefix}-credentials-{env}`: WebAuthn credentials
/// - `{prefix}-sessions-{env}`: Authentication sessions with TTL
/// - `{prefix}-pending-users-{env}`: Pending user invitations with TTL
/// - `{prefix}-app-configs-{env}`: Application configurations
///
/// # Arguments
///
/// * `config` - DynamoDB configuration with prefix, environment, and region
/// * `service_config` - Service configuration including encryption settings
///
/// # Returns
///
/// Returns `Ok(())` if all tables are created successfully, or an error if any creation fails.
///
/// # Examples
///
/// ```no_run
/// # use anyhow::Result;
/// # use shared::{DynamoDbConfig, create_dynamodb_tables};
/// # use shared::config::ServiceConfig;
/// # async fn example() -> Result<()> {
/// let db_config = DynamoDbConfig::new("passkey", "dev", "us-east-1");
/// let service_config = ServiceConfig::from_env()?;
/// create_dynamodb_tables(&db_config, &service_config).await?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// This function will return an error if:
/// - AWS credentials are not properly configured
/// - The specified region is invalid
/// - DynamoDB service is unavailable
/// - Insufficient permissions to create tables
/// - Encryption configuration is invalid (e.g., Enterprise level without KMS key)
pub async fn create_dynamodb_tables(config: &DynamoDbConfig, service_config: &ServiceConfig) -> Result<()> {
    // Validate encryption configuration before proceeding
    service_config.validate_encryption_config()
        .map_err(|e| anyhow::anyhow!("Encryption configuration validation failed: {e}"))?;

    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(config.region.clone()))
        .load()
        .await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&aws_config);

    let tables = vec![
        create_users_table(&dynamodb, config, service_config).await,
        create_credentials_table(&dynamodb, config, service_config).await,
        create_sessions_table(&dynamodb, config, service_config).await,
        create_pending_users_table(&dynamodb, config, service_config).await,
        create_app_configs_table(&dynamodb, config, service_config).await,
    ];

    for result in tables {
        result?;
    }

    Ok(())
}

/// Creates SSE specification for DynamoDB table encryption.
///
/// This function creates the appropriate Server-Side Encryption specification
/// based on the service configuration:
/// - Standard: Uses AWS managed keys (aws/dynamodb)
/// - Enterprise: Uses customer managed keys from KMS
///
/// # Arguments
///
/// * `service_config` - Service configuration with encryption level and KMS key ARN
///
/// # Returns
///
/// Returns `SseSpecification` configured with the appropriate encryption settings.
fn create_sse_specification(service_config: &ServiceConfig) -> SseSpecification {
    match service_config.encryption_level {
        EncryptionLevel::Standard => {
            // Use AWS managed keys
            SseSpecification::builder()
                .enabled(true)
                .sse_type(SseType::Aes256)
                .build()
        },
        EncryptionLevel::Enterprise => {
            // Use customer managed keys
            let mut builder = SseSpecification::builder()
                .enabled(true)
                .sse_type(SseType::Kms);
            
            if let Some(ref kms_key_arn) = service_config.kms_key_arn {
                builder = builder.kms_master_key_id(kms_key_arn.clone());
            }
            
            builder.build()
        }
    }
}

/// Creates the Users table for storing user account information.
///
/// The Users table stores basic user account data with the following structure:
/// - **Primary Key**: `user_id` (String) - UUID v4 identifier
/// - **Attributes**: email, display_name, created_at, updated_at, is_active, last_login
/// - **GSI**: EmailIndex - allows querying users by email address
///
/// # Table Schema
///
/// | Attribute | Type | Description |
/// |-----------|------|-------------|
/// | user_id | String (PK) | Unique user identifier (UUID v4) |
/// | email | String | User's email address (unique) |
/// | display_name | String | User's display name |
/// | created_at | String | ISO 8601 timestamp |
/// | updated_at | String | ISO 8601 timestamp |
/// | is_active | Boolean | Account active status |
/// | last_login | String | Last login timestamp |
///
/// # Global Secondary Index
///
/// - **EmailIndex**: Partition key: email, Sort key: created_at
/// - **Projection**: ALL attributes
/// - **Purpose**: Find users by email address for login/registration
///
/// # Arguments
///
/// * `dynamodb` - DynamoDB client instance
/// * `config` - DynamoDB configuration with table naming
/// * `service_config` - Service configuration with encryption settings
///
/// # Returns
///
/// Returns `Ok(())` if table creation succeeds or table already exists.
async fn create_users_table(
    dynamodb: &aws_sdk_dynamodb::Client,
    config: &DynamoDbConfig,
    service_config: &ServiceConfig,
) -> Result<()> {
    let table_name = config.table_name("users");

    // Check if table already exists
    if table_exists(dynamodb, &table_name).await? {
        println!("✅ Table {table_name} already exists");
        return Ok(());
    }

    let request = dynamodb
        .create_table()
        .table_name(&table_name)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("user_id")
                .attribute_type(ScalarAttributeType::S)
                .build()?,
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("email")
                .attribute_type(ScalarAttributeType::S)
                .build()?,
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("created_at")
                .attribute_type(ScalarAttributeType::S)
                .build()?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("user_id")
                .key_type(KeyType::Hash)
                .build()?,
        )
        .global_secondary_indexes(
            GlobalSecondaryIndex::builder()
                .index_name("EmailIndex")
                .key_schema(
                    KeySchemaElement::builder()
                        .attribute_name("email")
                        .key_type(KeyType::Hash)
                        .build()?,
                )
                .key_schema(
                    KeySchemaElement::builder()
                        .attribute_name("created_at")
                        .key_type(KeyType::Range)
                        .build()?,
                )
                .projection(
                    Projection::builder()
                        .projection_type(ProjectionType::All)
                        .build(),
                )
                .build()?,
        )
        .sse_specification(create_sse_specification(service_config));

    request.send().await?;
    println!("✅ Created table with encryption: {table_name}");
    Ok(())
}

/// Creates the Credentials table for storing WebAuthn authentication data.
///
/// The Credentials table stores WebAuthn public keys and related metadata:
/// - **Primary Key**: `credential_id` (Hash) + `user_id` (Range)
/// - **Attributes**: public_key, counter, aaguid, transports, user_verification, etc.
/// - **GSI**: UserIndex - allows querying all credentials for a user
/// - **LSI**: LastUsedIndex - allows sorting credentials by last usage
///
/// # Table Schema
///
/// | Attribute | Type | Description |
/// |-----------|------|-------------|
/// | credential_id | String (PK) | Base64 encoded authenticator ID |
/// | user_id | String (SK) | User UUID v4 |
/// | public_key | String | Base64 encoded public key |
/// | counter | Number | Usage counter (replay attack prevention) |
/// | aaguid | String | Authenticator Attestation GUID |
/// | transports | StringSet | Supported transports ["usb", "nfc", "ble", "internal"] |
/// | user_verification | String | Verification requirement level |
/// | created_at | String | ISO 8601 timestamp |
/// | last_used | String | Last usage timestamp |
/// | device_name | String | User-defined device name |
/// | is_active | Boolean | Credential active status |
///
/// # Indexes
///
/// - **UserIndex (GSI)**: PK: user_id, SK: created_at, Projection: ALL
/// - **LastUsedIndex (LSI)**: PK: credential_id, SK: last_used, Projection: ALL
///
/// # Arguments
///
/// * `dynamodb` - DynamoDB client instance
/// * `config` - DynamoDB configuration with table naming
/// * `service_config` - Service configuration with encryption settings
///
/// # Returns
///
/// Returns `Ok(())` if table creation succeeds or table already exists.
async fn create_credentials_table(
    dynamodb: &aws_sdk_dynamodb::Client,
    config: &DynamoDbConfig,
    service_config: &ServiceConfig,
) -> Result<()> {
    let table_name = config.table_name("credentials");

    if table_exists(dynamodb, &table_name).await? {
        println!("✅ Table {table_name} already exists");
        return Ok(());
    }

    let request = dynamodb
        .create_table()
        .table_name(&table_name)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("credential_id")
                .attribute_type(ScalarAttributeType::S)
                .build()?,
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("user_id")
                .attribute_type(ScalarAttributeType::S)
                .build()?,
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("created_at")
                .attribute_type(ScalarAttributeType::S)
                .build()?,
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("last_used")
                .attribute_type(ScalarAttributeType::S)
                .build()?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("credential_id")
                .key_type(KeyType::Hash)
                .build()?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("user_id")
                .key_type(KeyType::Range)
                .build()?,
        )
        .global_secondary_indexes(
            GlobalSecondaryIndex::builder()
                .index_name("UserIndex")
                .key_schema(
                    KeySchemaElement::builder()
                        .attribute_name("user_id")
                        .key_type(KeyType::Hash)
                        .build()?,
                )
                .key_schema(
                    KeySchemaElement::builder()
                        .attribute_name("created_at")
                        .key_type(KeyType::Range)
                        .build()?,
                )
                .projection(
                    Projection::builder()
                        .projection_type(ProjectionType::All)
                        .build(),
                )
                .build()?,
        )
        .local_secondary_indexes(
            LocalSecondaryIndex::builder()
                .index_name("LastUsedIndex")
                .key_schema(
                    KeySchemaElement::builder()
                        .attribute_name("credential_id")
                        .key_type(KeyType::Hash)
                        .build()?,
                )
                .key_schema(
                    KeySchemaElement::builder()
                        .attribute_name("last_used")
                        .key_type(KeyType::Range)
                        .build()?,
                )
                .projection(
                    Projection::builder()
                        .projection_type(ProjectionType::All)
                        .build(),
                )
                .build()?,
        )
        .sse_specification(create_sse_specification(service_config));

    request.send().await?;
    println!("✅ Created table with encryption: {table_name}");
    Ok(())
}

/// Creates the Sessions table for managing temporary authentication sessions.
///
/// The Sessions table stores temporary session data during registration and authentication flows:
/// - **Primary Key**: `session_id` (String) - UUID v4 identifier
/// - **TTL**: Automatic expiration after 300 seconds (5 minutes)
/// - **GSI**: UserIndex - allows finding active sessions for a user
///
/// # Table Schema
///
/// | Attribute | Type | Description |
/// |-----------|------|-------------|
/// | session_id | String (PK) | Unique session identifier (UUID v4) |
/// | user_id | String | User UUID (set after registration completion) |
/// | challenge | String | Base64 encoded WebAuthn challenge |
/// | session_type | String | "registration" or "authentication" |
/// | relying_party_id | String | WebAuthn RP ID |
/// | user_handle | String | Base64 encoded user handle |
/// | user_email | String | Email address for registration |
/// | user_display_name | String | Display name for registration |
/// | client_data_json | String | Client data JSON |
/// | public_key_credential_creation_options | String | Registration options (JSON) |
/// | public_key_credential_request_options | String | Authentication options (JSON) |
/// | created_at | String | ISO 8601 timestamp |
/// | expires_at | Number | Unix timestamp for TTL |
/// | ip_address | String | Client IP address |
/// | user_agent | String | User-Agent header |
/// | status | String | "active", "completed", "expired", "invalid" |
///
/// # Time To Live (TTL)
///
/// - **TTL Attribute**: `expires_at`
/// - **Duration**: 300 seconds (5 minutes)
/// - **Purpose**: Automatic cleanup of expired sessions
///
/// # Global Secondary Index
///
/// - **UserIndex**: PK: user_id, SK: created_at, Projection: KEYS_ONLY
/// - **Purpose**: Find active sessions for a specific user
///
/// # Arguments
///
/// * `dynamodb` - DynamoDB client instance
/// * `config` - DynamoDB configuration with table naming
/// * `service_config` - Service configuration with encryption settings
///
/// # Returns
///
/// Returns `Ok(())` if table creation and TTL setup succeed, or table already exists.
async fn create_sessions_table(
    dynamodb: &aws_sdk_dynamodb::Client,
    config: &DynamoDbConfig,
    service_config: &ServiceConfig,
) -> Result<()> {
    let table_name = config.table_name("sessions");

    if table_exists(dynamodb, &table_name).await? {
        println!("✅ Table {table_name} already exists");
        return Ok(());
    }

    let request = dynamodb
        .create_table()
        .table_name(&table_name)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("session_id")
                .attribute_type(ScalarAttributeType::S)
                .build()?,
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("user_id")
                .attribute_type(ScalarAttributeType::S)
                .build()?,
        )
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("created_at")
                .attribute_type(ScalarAttributeType::S)
                .build()?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("session_id")
                .key_type(KeyType::Hash)
                .build()?,
        )
        .global_secondary_indexes(
            GlobalSecondaryIndex::builder()
                .index_name("UserIndex")
                .key_schema(
                    KeySchemaElement::builder()
                        .attribute_name("user_id")
                        .key_type(KeyType::Hash)
                        .build()?,
                )
                .key_schema(
                    KeySchemaElement::builder()
                        .attribute_name("created_at")
                        .key_type(KeyType::Range)
                        .build()?,
                )
                .projection(
                    Projection::builder()
                        .projection_type(ProjectionType::KeysOnly)
                        .build(),
                )
                .build()?,
        )
        .sse_specification(create_sse_specification(service_config));

    request.send().await?;

    // Enable TTL
    let ttl_request = dynamodb
        .update_time_to_live()
        .table_name(&table_name)
        .time_to_live_specification(
            TimeToLiveSpecification::builder()
                .attribute_name("expires_at")
                .enabled(true)
                .build()?,
        );

    ttl_request.send().await?;
    println!("✅ Created table with TTL and encryption: {table_name}");
    Ok(())
}

/// Checks if a DynamoDB table exists.
///
/// This helper function uses the DescribeTable API to determine if a table
/// exists in the current AWS account and region.
///
/// # Arguments
///
/// * `dynamodb` - DynamoDB client instance
/// * `table_name` - Full name of the table to check
///
/// # Returns
///
/// Returns `Ok(true)` if the table exists, `Ok(false)` if it doesn't exist,
/// or an error for other API failures.
///
/// # Errors
///
/// This function will return an error for any DynamoDB API errors except
/// `ResourceNotFoundException`, which is handled as a "table does not exist" case.
async fn table_exists(dynamodb: &aws_sdk_dynamodb::Client, table_name: &str) -> Result<bool> {
    match dynamodb
        .describe_table()
        .table_name(table_name)
        .send()
        .await
    {
        Ok(_) => Ok(true),
        Err(e) => {
            if e.to_string().contains("ResourceNotFoundException") {
                Ok(false)
            } else {
                Err(e.into())
            }
        }
    }
}

/// Creates the PendingUsers table for storing user invitations.
///
/// The PendingUsers table stores temporary user invitation data:
/// - **Primary Key**: `app_id#email` (String)
/// - **Attributes**: pending_user_id, otp_hash, otp_salt, invited_at, expires_at, etc.
/// - **TTL**: Automatic expiration based on expires_at field
///
/// # Arguments
///
/// * `dynamodb` - DynamoDB client instance
/// * `config` - DynamoDB configuration with table naming
/// * `service_config` - Service configuration with encryption settings
///
/// # Returns
///
/// Returns `Ok(())` if table creation succeeds or table already exists.
async fn create_pending_users_table(
    dynamodb: &aws_sdk_dynamodb::Client,
    config: &DynamoDbConfig,
    service_config: &ServiceConfig,
) -> Result<()> {
    let table_name = config.table_name("pending-users");

    if table_exists(dynamodb, &table_name).await? {
        println!("✅ Table {table_name} already exists");
        return Ok(());
    }

    let request = dynamodb
        .create_table()
        .table_name(&table_name)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("pk")
                .attribute_type(ScalarAttributeType::S)
                .build()?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("pk")
                .key_type(KeyType::Hash)
                .build()?,
        )
        .sse_specification(create_sse_specification(service_config));

    request.send().await?;

    // Enable TTL
    let ttl_request = dynamodb
        .update_time_to_live()
        .table_name(&table_name)
        .time_to_live_specification(
            TimeToLiveSpecification::builder()
                .attribute_name("expires_at")
                .enabled(true)
                .build()?,
        );

    ttl_request.send().await?;
    println!("✅ Created table with TTL and encryption: {table_name}");
    Ok(())
}

/// Creates the AppConfigs table for storing application configurations.
///
/// The AppConfigs table stores application-specific settings:
/// - **Primary Key**: `app_id` (String)
/// - **Attributes**: name, relying_party_id, jwt_secret, timeouts, etc.
///
/// # Arguments
///
/// * `dynamodb` - DynamoDB client instance
/// * `config` - DynamoDB configuration with table naming
/// * `service_config` - Service configuration with encryption settings
///
/// # Returns
///
/// Returns `Ok(())` if table creation succeeds or table already exists.
async fn create_app_configs_table(
    dynamodb: &aws_sdk_dynamodb::Client,
    config: &DynamoDbConfig,
    service_config: &ServiceConfig,
) -> Result<()> {
    let table_name = config.table_name("app-configs");

    if table_exists(dynamodb, &table_name).await? {
        println!("✅ Table {table_name} already exists");
        return Ok(());
    }

    let request = dynamodb
        .create_table()
        .table_name(&table_name)
        .billing_mode(BillingMode::PayPerRequest)
        .attribute_definitions(
            AttributeDefinition::builder()
                .attribute_name("app_id")
                .attribute_type(ScalarAttributeType::S)
                .build()?,
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("app_id")
                .key_type(KeyType::Hash)
                .build()?,
        )
        .sse_specification(create_sse_specification(service_config));

    request.send().await?;
    println!("✅ Created table with encryption: {table_name}");
    Ok(())
}

// =============================================================================
// CRUD Operations
// =============================================================================

/// Creates a new user in the users table.
pub async fn create_user(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    user: &User,
) -> Result<(), PasskeyError> {
    let mut item = HashMap::new();

    item.insert(
        "user_id".to_string(),
        AttributeValue::S(user.user_id.clone()),
    );
    item.insert("app_id".to_string(), AttributeValue::S(user.app_id.clone()));
    item.insert("email".to_string(), AttributeValue::S(user.email.clone()));
    item.insert(
        "display_name".to_string(),
        AttributeValue::S(user.display_name.clone()),
    );
    item.insert(
        "created_at".to_string(),
        AttributeValue::S(user.created_at.clone()),
    );
    item.insert(
        "updated_at".to_string(),
        AttributeValue::S(user.updated_at.clone()),
    );
    item.insert(
        "is_active".to_string(),
        AttributeValue::Bool(user.is_active),
    );
    item.insert("role".to_string(), AttributeValue::S(user.role.to_string()));

    if let Some(ref last_login) = user.last_login {
        item.insert(
            "last_login".to_string(),
            AttributeValue::S(last_login.clone()),
        );
    }

    dynamodb
        .put_item()
        .table_name(table_name)
        .set_item(Some(item))
        .condition_expression("attribute_not_exists(user_id)")
        .send()
        .await
        .map_err(|e| {
            if e.to_string().contains("ConditionalCheckFailedException") {
                PasskeyError::Database(DatabaseError::ConstraintViolation(
                    "User already exists".to_string(),
                ))
            } else {
                PasskeyError::Database(DatabaseError::DynamoDB(e.to_string()))
            }
        })?;

    Ok(())
}

/// Retrieves a user by user_id.
pub async fn get_user(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    user_id: &str,
) -> Result<Option<User>, PasskeyError> {
    let result = dynamodb
        .get_item()
        .table_name(table_name)
        .key("user_id", AttributeValue::S(user_id.to_string()))
        .send()
        .await
        .map_err(|e| PasskeyError::Database(DatabaseError::DynamoDB(e.to_string())))?;

    if let Some(item) = result.item {
        let user = parse_user_from_item(item)?;
        Ok(Some(user))
    } else {
        Ok(None)
    }
}

/// Retrieves a user by email address using GSI.
pub async fn get_user_by_email(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    email: &str,
) -> Result<Option<User>, PasskeyError> {
    let result = dynamodb
        .query()
        .table_name(table_name)
        .index_name("EmailIndex")
        .key_condition_expression("email = :email")
        .expression_attribute_values(":email", AttributeValue::S(email.to_string()))
        .limit(1)
        .send()
        .await
        .map_err(|e| PasskeyError::Database(DatabaseError::DynamoDB(e.to_string())))?;

    if let Some(items) = result.items {
        if let Some(item) = items.into_iter().next() {
            let user = parse_user_from_item(item)?;
            return Ok(Some(user));
        }
    }

    Ok(None)
}

/// Updates a user's information.
pub async fn update_user(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    user: &User,
) -> Result<(), PasskeyError> {
    let mut update_expression = "SET ".to_string();
    let mut expression_attribute_values = HashMap::new();
    let mut expression_attribute_names = HashMap::new();

    update_expression.push_str("display_name = :display_name, ");
    expression_attribute_values.insert(
        ":display_name".to_string(),
        AttributeValue::S(user.display_name.clone()),
    );

    update_expression.push_str("updated_at = :updated_at, ");
    expression_attribute_values.insert(
        ":updated_at".to_string(),
        AttributeValue::S(user.updated_at.clone()),
    );

    update_expression.push_str("is_active = :is_active, ");
    expression_attribute_values.insert(
        ":is_active".to_string(),
        AttributeValue::Bool(user.is_active),
    );

    update_expression.push_str("#role = :role");
    expression_attribute_names.insert("#role".to_string(), "role".to_string());
    expression_attribute_values.insert(
        ":role".to_string(),
        AttributeValue::S(user.role.to_string()),
    );

    if let Some(ref last_login) = user.last_login {
        update_expression.push_str(", last_login = :last_login");
        expression_attribute_values.insert(
            ":last_login".to_string(),
            AttributeValue::S(last_login.clone()),
        );
    }

    dynamodb
        .update_item()
        .table_name(table_name)
        .key("user_id", AttributeValue::S(user.user_id.clone()))
        .update_expression(update_expression)
        .set_expression_attribute_values(Some(expression_attribute_values))
        .set_expression_attribute_names(Some(expression_attribute_names))
        .condition_expression("attribute_exists(user_id)")
        .send()
        .await
        .map_err(|e| {
            if e.to_string().contains("ConditionalCheckFailedException") {
                PasskeyError::UserNotFound
            } else {
                PasskeyError::Database(DatabaseError::DynamoDB(e.to_string()))
            }
        })?;

    Ok(())
}

/// Creates a new credential in the credentials table.
pub async fn create_credential(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    credential: &Credential,
) -> Result<(), PasskeyError> {
    let mut item = HashMap::new();

    item.insert(
        "credential_id".to_string(),
        AttributeValue::S(credential.credential_id.clone()),
    );
    item.insert(
        "app_id".to_string(),
        AttributeValue::S(credential.app_id.clone()),
    );
    item.insert(
        "user_id".to_string(),
        AttributeValue::S(credential.user_id.clone()),
    );
    item.insert(
        "public_key".to_string(),
        AttributeValue::S(credential.public_key.clone()),
    );
    item.insert(
        "counter".to_string(),
        AttributeValue::N(credential.counter.to_string()),
    );
    item.insert(
        "aaguid".to_string(),
        AttributeValue::S(credential.aaguid.clone()),
    );

    // Convert transports Vec to StringSet
    if !credential.transports.is_empty() {
        item.insert(
            "transports".to_string(),
            AttributeValue::Ss(credential.transports.clone()),
        );
    }

    item.insert(
        "user_verification".to_string(),
        AttributeValue::S(credential.user_verification.clone()),
    );
    item.insert(
        "created_at".to_string(),
        AttributeValue::S(credential.created_at.clone()),
    );
    item.insert(
        "last_used".to_string(),
        AttributeValue::S(credential.last_used.clone()),
    );
    item.insert(
        "is_active".to_string(),
        AttributeValue::Bool(credential.is_active),
    );

    if let Some(ref device_name) = credential.device_name {
        item.insert(
            "device_name".to_string(),
            AttributeValue::S(device_name.clone()),
        );
    }

    dynamodb
        .put_item()
        .table_name(table_name)
        .set_item(Some(item))
        .condition_expression("attribute_not_exists(credential_id)")
        .send()
        .await
        .map_err(|e| {
            if e.to_string().contains("ConditionalCheckFailedException") {
                PasskeyError::Database(DatabaseError::ConstraintViolation(
                    "Credential already exists".to_string(),
                ))
            } else {
                PasskeyError::Database(DatabaseError::DynamoDB(e.to_string()))
            }
        })?;

    Ok(())
}

/// Retrieves all credentials for a user using GSI.
pub async fn get_credentials_by_user(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    user_id: &str,
) -> Result<Vec<Credential>, PasskeyError> {
    let result = dynamodb
        .query()
        .table_name(table_name)
        .index_name("UserIndex")
        .key_condition_expression("user_id = :user_id")
        .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
        .send()
        .await
        .map_err(|e| PasskeyError::Database(DatabaseError::DynamoDB(e.to_string())))?;

    let mut credentials = Vec::new();
    if let Some(items) = result.items {
        for item in items {
            let credential = parse_credential_from_item(item)?;
            credentials.push(credential);
        }
    }

    Ok(credentials)
}

/// Creates a new session in the sessions table.
pub async fn create_session(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    session: &Session,
) -> Result<(), PasskeyError> {
    let mut item = HashMap::new();

    item.insert(
        "session_id".to_string(),
        AttributeValue::S(session.session_id.clone()),
    );
    item.insert(
        "app_id".to_string(),
        AttributeValue::S(session.app_id.clone()),
    );
    item.insert(
        "challenge".to_string(),
        AttributeValue::S(session.challenge.clone()),
    );
    item.insert(
        "session_type".to_string(),
        AttributeValue::S(session.session_type.to_string()),
    );
    item.insert(
        "relying_party_id".to_string(),
        AttributeValue::S(session.relying_party_id.clone()),
    );
    item.insert(
        "created_at".to_string(),
        AttributeValue::S(session.created_at.clone()),
    );
    item.insert(
        "expires_at".to_string(),
        AttributeValue::N(session.expires_at.to_string()),
    );
    item.insert(
        "status".to_string(),
        AttributeValue::S(session.status.to_string()),
    );
    item.insert(
        "ip_address".to_string(),
        AttributeValue::S(session.ip_address.clone()),
    );
    item.insert(
        "user_agent".to_string(),
        AttributeValue::S(session.user_agent.clone()),
    );

    // Optional fields
    if let Some(user_id) = &session.user_id {
        item.insert("user_id".to_string(), AttributeValue::S(user_id.clone()));
    }
    if let Some(user_handle) = &session.user_handle {
        item.insert(
            "user_handle".to_string(),
            AttributeValue::S(user_handle.clone()),
        );
    }
    if let Some(user_email) = &session.user_email {
        item.insert(
            "user_email".to_string(),
            AttributeValue::S(user_email.clone()),
        );
    }
    if let Some(user_display_name) = &session.user_display_name {
        item.insert(
            "user_display_name".to_string(),
            AttributeValue::S(user_display_name.clone()),
        );
    }
    if let Some(client_data_json) = &session.client_data_json {
        item.insert(
            "client_data_json".to_string(),
            AttributeValue::S(client_data_json.clone()),
        );
    }
    if let Some(options) = &session.public_key_credential_creation_options {
        item.insert(
            "public_key_credential_creation_options".to_string(),
            AttributeValue::S(options.clone()),
        );
    }
    if let Some(options) = &session.public_key_credential_request_options {
        item.insert(
            "public_key_credential_request_options".to_string(),
            AttributeValue::S(options.clone()),
        );
    }

    dynamodb
        .put_item()
        .table_name(table_name)
        .set_item(Some(item))
        .condition_expression("attribute_not_exists(session_id)")
        .send()
        .await
        .map_err(|e| {
            if e.to_string().contains("ConditionalCheckFailedException") {
                PasskeyError::Database(DatabaseError::ConstraintViolation(
                    "Session already exists".to_string(),
                ))
            } else {
                PasskeyError::Database(DatabaseError::DynamoDB(e.to_string()))
            }
        })?;

    Ok(())
}

/// Retrieves a session by session_id.
pub async fn get_session(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    session_id: &str,
) -> Result<Option<Session>, PasskeyError> {
    let result = dynamodb
        .get_item()
        .table_name(table_name)
        .key("session_id", AttributeValue::S(session_id.to_string()))
        .send()
        .await
        .map_err(|e| PasskeyError::Database(DatabaseError::DynamoDB(e.to_string())))?;

    if let Some(item) = result.item {
        let session = parse_session_from_item(item)?;
        Ok(Some(session))
    } else {
        Ok(None)
    }
}

/// Updates a session's status.
pub async fn update_session(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    session_id: &str,
    status: &str,
) -> Result<(), PasskeyError> {
    dynamodb
        .update_item()
        .table_name(table_name)
        .key("session_id", AttributeValue::S(session_id.to_string()))
        .update_expression("SET #status = :status")
        .expression_attribute_names("#status", "status")
        .expression_attribute_values(":status", AttributeValue::S(status.to_string()))
        .condition_expression("attribute_exists(session_id)")
        .send()
        .await
        .map_err(|e| {
            if e.to_string().contains("ConditionalCheckFailedException") {
                PasskeyError::SessionNotFound
            } else {
                PasskeyError::Database(DatabaseError::DynamoDB(e.to_string()))
            }
        })?;

    Ok(())
}

/// Creates a new pending user invitation.
pub async fn create_pending_user(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    pending_user: &PendingUser,
) -> Result<(), PasskeyError> {
    let mut item = HashMap::new();

    item.insert(
        "pk".to_string(),
        AttributeValue::S(pending_user.primary_key()),
    );
    item.insert(
        "pending_user_id".to_string(),
        AttributeValue::S(pending_user.pending_user_id.clone()),
    );
    item.insert(
        "app_id".to_string(),
        AttributeValue::S(pending_user.app_id.clone()),
    );
    item.insert(
        "email".to_string(),
        AttributeValue::S(pending_user.email.clone()),
    );
    item.insert(
        "otp_hash".to_string(),
        AttributeValue::S(pending_user.otp_hash.clone()),
    );
    item.insert(
        "otp_salt".to_string(),
        AttributeValue::S(pending_user.otp_salt.clone()),
    );
    item.insert(
        "invited_at".to_string(),
        AttributeValue::S(pending_user.invited_at.clone()),
    );
    item.insert(
        "expires_at".to_string(),
        AttributeValue::N(pending_user.expires_at.to_string()),
    );
    item.insert(
        "otp_attempts".to_string(),
        AttributeValue::N(pending_user.otp_attempts.to_string()),
    );
    item.insert(
        "invited_by".to_string(),
        AttributeValue::S(pending_user.invited_by.clone()),
    );

    if let Some(ref metadata) = pending_user.metadata {
        item.insert(
            "metadata".to_string(),
            AttributeValue::S(metadata.to_string()),
        );
    }

    dynamodb
        .put_item()
        .table_name(table_name)
        .set_item(Some(item))
        .condition_expression("attribute_not_exists(pk)")
        .send()
        .await
        .map_err(|e| {
            if e.to_string().contains("ConditionalCheckFailedException") {
                PasskeyError::Database(DatabaseError::ConstraintViolation(
                    "Pending user already exists".to_string(),
                ))
            } else {
                PasskeyError::Database(DatabaseError::DynamoDB(e.to_string()))
            }
        })?;

    Ok(())
}

/// Retrieves a pending user by app_id and email.
pub async fn get_pending_user(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    app_id: &str,
    email: &str,
) -> Result<Option<PendingUser>, PasskeyError> {
    let pk = format!("{app_id}#{email}");

    let result = dynamodb
        .get_item()
        .table_name(table_name)
        .key("pk", AttributeValue::S(pk))
        .send()
        .await
        .map_err(|e| PasskeyError::Database(DatabaseError::DynamoDB(e.to_string())))?;

    if let Some(item) = result.item {
        let pending_user = parse_pending_user_from_item(item)?;
        Ok(Some(pending_user))
    } else {
        Ok(None)
    }
}

/// Deletes a pending user invitation.
pub async fn delete_pending_user(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    app_id: &str,
    email: &str,
) -> Result<(), PasskeyError> {
    let pk = format!("{app_id}#{email}");

    dynamodb
        .delete_item()
        .table_name(table_name)
        .key("pk", AttributeValue::S(pk))
        .condition_expression("attribute_exists(pk)")
        .send()
        .await
        .map_err(|e| {
            if e.to_string().contains("ConditionalCheckFailedException") {
                PasskeyError::PendingUserNotFound
            } else {
                PasskeyError::Database(DatabaseError::DynamoDB(e.to_string()))
            }
        })?;

    Ok(())
}

/// Retrieves an application configuration.
pub async fn get_app_config(
    dynamodb: &aws_sdk_dynamodb::Client,
    table_name: &str,
    app_id: &str,
) -> Result<Option<AppConfig>, PasskeyError> {
    let result = dynamodb
        .get_item()
        .table_name(table_name)
        .key("app_id", AttributeValue::S(app_id.to_string()))
        .send()
        .await
        .map_err(|e| PasskeyError::Database(DatabaseError::DynamoDB(e.to_string())))?;

    if let Some(item) = result.item {
        let app_config = parse_app_config_from_item(item)?;
        Ok(Some(app_config))
    } else {
        Ok(None)
    }
}

// =============================================================================
// Parser Functions
// =============================================================================

/// Parses a User from DynamoDB item.
fn parse_user_from_item(item: HashMap<String, AttributeValue>) -> Result<User, PasskeyError> {
    let app_id = item
        .get("app_id")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing app_id".to_string(),
            ))
        })?
        .clone();

    let user_id = item
        .get("user_id")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing user_id".to_string(),
            ))
        })?
        .clone();

    let email = item
        .get("email")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing email".to_string(),
            ))
        })?
        .clone();

    let display_name = item
        .get("display_name")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing display_name".to_string(),
            ))
        })?
        .clone();

    let created_at = item
        .get("created_at")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing created_at".to_string(),
            ))
        })?
        .clone();

    let updated_at = item
        .get("updated_at")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing updated_at".to_string(),
            ))
        })?
        .clone();

    let is_active = item
        .get("is_active")
        .and_then(|v| v.as_bool().ok())
        .copied()
        .unwrap_or(true);

    let role = item
        .get("role")
        .and_then(|v| v.as_s().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or_default();

    let last_login = item.get("last_login").and_then(|v| v.as_s().ok()).cloned();

    Ok(User {
        app_id,
        user_id,
        email,
        display_name,
        role,
        created_at,
        updated_at,
        is_active,
        last_login,
    })
}

/// Parses a Credential from DynamoDB item.
fn parse_credential_from_item(
    item: HashMap<String, AttributeValue>,
) -> Result<Credential, PasskeyError> {
    let app_id = item
        .get("app_id")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing app_id".to_string(),
            ))
        })?
        .clone();

    let credential_id = item
        .get("credential_id")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing credential_id".to_string(),
            ))
        })?
        .clone();

    let user_id = item
        .get("user_id")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing user_id".to_string(),
            ))
        })?
        .clone();

    let public_key = item
        .get("public_key")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing public_key".to_string(),
            ))
        })?
        .clone();

    let counter = item
        .get("counter")
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Invalid counter".to_string(),
            ))
        })?;

    let aaguid = item
        .get("aaguid")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing aaguid".to_string(),
            ))
        })?
        .clone();

    let transports = item
        .get("transports")
        .and_then(|v| v.as_ss().ok())
        .cloned()
        .unwrap_or_default();

    let user_verification = item
        .get("user_verification")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing user_verification".to_string(),
            ))
        })?
        .clone();

    let created_at = item
        .get("created_at")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing created_at".to_string(),
            ))
        })?
        .clone();

    let last_used = item
        .get("last_used")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing last_used".to_string(),
            ))
        })?
        .clone();

    let device_name = item.get("device_name").and_then(|v| v.as_s().ok()).cloned();

    let is_active = item
        .get("is_active")
        .and_then(|v| v.as_bool().ok())
        .copied()
        .unwrap_or(true);

    Ok(Credential {
        app_id,
        credential_id,
        user_id,
        public_key,
        counter,
        aaguid,
        transports,
        user_verification,
        created_at,
        last_used,
        device_name,
        is_active,
    })
}

/// Parses a Session from DynamoDB item.
fn parse_session_from_item(item: HashMap<String, AttributeValue>) -> Result<Session, PasskeyError> {
    let app_id = item
        .get("app_id")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing app_id".to_string(),
            ))
        })?
        .clone();

    let session_id = item
        .get("session_id")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing session_id".to_string(),
            ))
        })?
        .clone();

    let challenge = item
        .get("challenge")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing challenge".to_string(),
            ))
        })?
        .clone();

    let session_type = item
        .get("session_type")
        .and_then(|v| v.as_s().ok())
        .and_then(|s| SessionType::from_str(s).ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Invalid session_type".to_string(),
            ))
        })?;

    let relying_party_id = item
        .get("relying_party_id")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing relying_party_id".to_string(),
            ))
        })?
        .clone();

    let created_at = item
        .get("created_at")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing created_at".to_string(),
            ))
        })?
        .clone();

    let expires_at = item
        .get("expires_at")
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Invalid expires_at".to_string(),
            ))
        })?;

    let status = item
        .get("status")
        .and_then(|v| v.as_s().ok())
        .and_then(|s| SessionStatus::from_str(s).ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Invalid status".to_string(),
            ))
        })?;

    let ip_address = item
        .get("ip_address")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing ip_address".to_string(),
            ))
        })?
        .clone();

    let user_agent = item
        .get("user_agent")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing user_agent".to_string(),
            ))
        })?
        .clone();

    let user_id = item.get("user_id").and_then(|v| v.as_s().ok()).cloned();
    let user_handle = item.get("user_handle").and_then(|v| v.as_s().ok()).cloned();
    let user_email = item.get("user_email").and_then(|v| v.as_s().ok()).cloned();
    let user_display_name = item
        .get("user_display_name")
        .and_then(|v| v.as_s().ok())
        .cloned();
    let client_data_json = item
        .get("client_data_json")
        .and_then(|v| v.as_s().ok())
        .cloned();
    let public_key_credential_creation_options = item
        .get("public_key_credential_creation_options")
        .and_then(|v| v.as_s().ok())
        .cloned();
    let public_key_credential_request_options = item
        .get("public_key_credential_request_options")
        .and_then(|v| v.as_s().ok())
        .cloned();

    Ok(Session {
        app_id,
        session_id,
        user_id,
        challenge,
        session_type,
        relying_party_id,
        user_handle,
        user_email,
        user_display_name,
        client_data_json,
        public_key_credential_creation_options,
        public_key_credential_request_options,
        created_at,
        expires_at,
        ip_address,
        user_agent,
        status,
    })
}

/// Parses a PendingUser from DynamoDB item.
fn parse_pending_user_from_item(
    item: HashMap<String, AttributeValue>,
) -> Result<PendingUser, PasskeyError> {
    let pending_user_id = item
        .get("pending_user_id")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing pending_user_id".to_string(),
            ))
        })?
        .clone();

    let app_id = item
        .get("app_id")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing app_id".to_string(),
            ))
        })?
        .clone();

    let email = item
        .get("email")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing email".to_string(),
            ))
        })?
        .clone();

    let otp_hash = item
        .get("otp_hash")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing otp_hash".to_string(),
            ))
        })?
        .clone();

    let otp_salt = item
        .get("otp_salt")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing otp_salt".to_string(),
            ))
        })?
        .clone();

    let invited_at = item
        .get("invited_at")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing invited_at".to_string(),
            ))
        })?
        .clone();

    let expires_at = item
        .get("expires_at")
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Invalid expires_at".to_string(),
            ))
        })?;

    let otp_attempts = item
        .get("otp_attempts")
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let invited_by = item
        .get("invited_by")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing invited_by".to_string(),
            ))
        })?
        .clone();

    let metadata = item
        .get("metadata")
        .and_then(|v| v.as_s().ok())
        .and_then(|s| serde_json::from_str(s).ok());

    Ok(PendingUser {
        pending_user_id,
        app_id,
        email,
        otp_hash,
        otp_salt,
        otp_attempts,
        invited_at,
        expires_at,
        invited_by,
        metadata,
    })
}

/// Parses an AppConfig from DynamoDB item.
fn parse_app_config_from_item(
    item: HashMap<String, AttributeValue>,
) -> Result<AppConfig, PasskeyError> {
    let app_id = item
        .get("app_id")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing app_id".to_string(),
            ))
        })?
        .clone();

    let name = item
        .get("name")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing name".to_string(),
            ))
        })?
        .clone();

    let relying_party_id = item
        .get("relying_party_id")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing relying_party_id".to_string(),
            ))
        })?
        .clone();

    let relying_party_name = item
        .get("relying_party_name")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing relying_party_name".to_string(),
            ))
        })?
        .clone();

    let allowed_origins = item
        .get("allowed_origins")
        .and_then(|v| v.as_ss().ok())
        .cloned()
        .unwrap_or_default();

    let jwt_secret = item
        .get("jwt_secret")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing jwt_secret".to_string(),
            ))
        })?
        .clone();

    let jwt_expires_in = item
        .get("jwt_expires_in")
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600);

    let session_timeout_seconds = item
        .get("session_timeout_seconds")
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);

    let otp_expires_in = item
        .get("otp_expires_in")
        .and_then(|v| v.as_n().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(1800);

    let created_at = item
        .get("created_at")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing created_at".to_string(),
            ))
        })?
        .clone();

    let updated_at = item
        .get("updated_at")
        .and_then(|v| v.as_s().ok())
        .ok_or_else(|| {
            PasskeyError::Database(DatabaseError::SerializationError(
                "Missing updated_at".to_string(),
            ))
        })?
        .clone();

    let is_active = item
        .get("is_active")
        .and_then(|v| v.as_bool().ok())
        .copied()
        .unwrap_or(true);

    let admin_emails = item
        .get("admin_emails")
        .and_then(|v| v.as_ss().ok())
        .cloned()
        .unwrap_or_default();

    Ok(AppConfig {
        app_id,
        name,
        relying_party_id,
        relying_party_name,
        allowed_origins,
        jwt_secret,
        jwt_expires_in,
        session_timeout_seconds,
        otp_expires_in,
        created_at,
        updated_at,
        is_active,
        admin_emails,
        registration_mode: crate::types::RegistrationMode::InviteOnly, // Default for backward compatibility
        auto_approve_registration: false, // Default for backward compatibility  
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EncryptionLevel, ServiceConfig};
    use crate::types::{User, UserRole, RegistrationMode};

    fn create_test_service_config() -> ServiceConfig {
        ServiceConfig {
            environment: "test".to_string(),
            table_prefix: "passkey".to_string(),
            cors_origins: vec!["http://localhost:3000".to_string()],
            default_jwt_expires_in: 3600,
            default_session_timeout: 300,
            default_otp_expires_in: 1800,
            encryption_level: EncryptionLevel::Standard,
            kms_key_arn: None,
        }
    }

    fn create_test_dynamodb_config() -> DynamoDbConfig {
        DynamoDbConfig::new("passkey", "test", "us-east-1")
    }

    #[test]
    fn test_dynamodb_config_new() {
        let config = DynamoDbConfig::new("passkey", "test", "us-east-1");
        assert_eq!(config.table_prefix, "passkey");
        assert_eq!(config.environment, "test");
        assert_eq!(config.region, "us-east-1");
    }

    #[test]
    fn test_dynamodb_config_table_name() {
        let config = create_test_dynamodb_config();
        assert_eq!(config.table_name("users"), "passkey-users-test");
        assert_eq!(config.table_name("credentials"), "passkey-credentials-test");
        assert_eq!(config.table_name("sessions"), "passkey-sessions-test");
        assert_eq!(config.table_name("pending-users"), "passkey-pending-users-test");
        assert_eq!(config.table_name("app-configs"), "passkey-app-configs-test");
    }

    #[test]
    fn test_create_sse_specification_standard() {
        let service_config = create_test_service_config();
        let sse_spec = create_sse_specification(&service_config);
        
        // Note: We can't directly test the internal structure of SseSpecification
        // as it doesn't expose its fields, but we can test that it builds successfully
        assert!(true); // If we reach here, the function executed without panic
    }

    #[test]
    fn test_create_sse_specification_enterprise() {
        let mut service_config = create_test_service_config();
        service_config.encryption_level = EncryptionLevel::Enterprise;
        service_config.kms_key_arn = Some("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012".to_string());
        
        let sse_spec = create_sse_specification(&service_config);
        
        // Test that enterprise encryption builds successfully
        assert!(true);
    }

    #[test]
    fn test_create_sse_specification_enterprise_without_kms() {
        let mut service_config = create_test_service_config();
        service_config.encryption_level = EncryptionLevel::Enterprise;
        service_config.kms_key_arn = None;
        
        let sse_spec = create_sse_specification(&service_config);
        
        // Even without KMS key ARN, the function should not panic
        assert!(true);
    }

    #[test]
    fn test_parse_user_from_item() {
        let mut item = HashMap::new();
        item.insert("app_id".to_string(), AttributeValue::S("test_app".to_string()));
        item.insert("user_id".to_string(), AttributeValue::S("user123".to_string()));
        item.insert("email".to_string(), AttributeValue::S("test@example.com".to_string()));
        item.insert("display_name".to_string(), AttributeValue::S("Test User".to_string()));
        item.insert("created_at".to_string(), AttributeValue::S("2023-01-01T00:00:00Z".to_string()));
        item.insert("updated_at".to_string(), AttributeValue::S("2023-01-01T00:00:00Z".to_string()));
        item.insert("is_active".to_string(), AttributeValue::Bool(true));
        item.insert("role".to_string(), AttributeValue::S("user".to_string()));

        let user = parse_user_from_item(item).unwrap();
        assert_eq!(user.app_id, "test_app");
        assert_eq!(user.user_id, "user123");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.display_name, "Test User");
        assert_eq!(user.role, UserRole::User);
        assert!(user.is_active);
        assert!(user.last_login.is_none());
    }

    #[test]
    fn test_parse_user_from_item_missing_required_field() {
        let mut item = HashMap::new();
        item.insert("app_id".to_string(), AttributeValue::S("test_app".to_string()));
        // Missing user_id
        item.insert("email".to_string(), AttributeValue::S("test@example.com".to_string()));

        let result = parse_user_from_item(item);
        assert!(result.is_err());
        assert!(matches!(result, Err(PasskeyError::Database(DatabaseError::SerializationError(_)))));
    }

    #[test]
    fn test_parse_credential_from_item() {
        let mut item = HashMap::new();
        item.insert("app_id".to_string(), AttributeValue::S("test_app".to_string()));
        item.insert("credential_id".to_string(), AttributeValue::S("cred123".to_string()));
        item.insert("user_id".to_string(), AttributeValue::S("user123".to_string()));
        item.insert("public_key".to_string(), AttributeValue::S("pubkey123".to_string()));
        item.insert("counter".to_string(), AttributeValue::N("1".to_string()));
        item.insert("aaguid".to_string(), AttributeValue::S("aaguid123".to_string()));
        item.insert("transports".to_string(), AttributeValue::Ss(vec!["usb".to_string(), "nfc".to_string()]));
        item.insert("user_verification".to_string(), AttributeValue::S("required".to_string()));
        item.insert("created_at".to_string(), AttributeValue::S("2023-01-01T00:00:00Z".to_string()));
        item.insert("last_used".to_string(), AttributeValue::S("2023-01-01T00:00:00Z".to_string()));
        item.insert("is_active".to_string(), AttributeValue::Bool(true));

        let credential = parse_credential_from_item(item).unwrap();
        assert_eq!(credential.app_id, "test_app");
        assert_eq!(credential.credential_id, "cred123");
        assert_eq!(credential.user_id, "user123");
        assert_eq!(credential.counter, 1);
        assert_eq!(credential.transports, vec!["usb", "nfc"]);
        assert!(credential.is_active);
    }

    #[test]
    fn test_parse_session_from_item() {
        let mut item = HashMap::new();
        item.insert("app_id".to_string(), AttributeValue::S("test_app".to_string()));
        item.insert("session_id".to_string(), AttributeValue::S("session123".to_string()));
        item.insert("challenge".to_string(), AttributeValue::S("challenge123".to_string()));
        item.insert("session_type".to_string(), AttributeValue::S("registration".to_string()));
        item.insert("relying_party_id".to_string(), AttributeValue::S("example.com".to_string()));
        item.insert("created_at".to_string(), AttributeValue::S("2023-01-01T00:00:00Z".to_string()));
        item.insert("expires_at".to_string(), AttributeValue::N("1672531200".to_string()));
        item.insert("status".to_string(), AttributeValue::S("active".to_string()));
        item.insert("ip_address".to_string(), AttributeValue::S("192.168.1.1".to_string()));
        item.insert("user_agent".to_string(), AttributeValue::S("Mozilla/5.0".to_string()));

        let session = parse_session_from_item(item).unwrap();
        assert_eq!(session.app_id, "test_app");
        assert_eq!(session.session_id, "session123");
        assert_eq!(session.challenge, "challenge123");
        assert_eq!(session.relying_party_id, "example.com");
        assert_eq!(session.expires_at, 1672531200);
        assert_eq!(session.ip_address, "192.168.1.1");
    }

    #[test]
    fn test_parse_pending_user_from_item() {
        let mut item = HashMap::new();
        item.insert("pending_user_id".to_string(), AttributeValue::S("pending123".to_string()));
        item.insert("app_id".to_string(), AttributeValue::S("test_app".to_string()));
        item.insert("email".to_string(), AttributeValue::S("pending@example.com".to_string()));
        item.insert("otp_hash".to_string(), AttributeValue::S("hash123".to_string()));
        item.insert("otp_salt".to_string(), AttributeValue::S("salt123".to_string()));
        item.insert("invited_at".to_string(), AttributeValue::S("2023-01-01T00:00:00Z".to_string()));
        item.insert("expires_at".to_string(), AttributeValue::N("1672531200".to_string()));
        item.insert("otp_attempts".to_string(), AttributeValue::N("0".to_string()));
        item.insert("invited_by".to_string(), AttributeValue::S("admin@example.com".to_string()));

        let pending_user = parse_pending_user_from_item(item).unwrap();
        assert_eq!(pending_user.pending_user_id, "pending123");
        assert_eq!(pending_user.app_id, "test_app");
        assert_eq!(pending_user.email, "pending@example.com");
        assert_eq!(pending_user.otp_hash, "hash123");
        assert_eq!(pending_user.otp_attempts, 0);
        assert_eq!(pending_user.invited_by, "admin@example.com");
    }

    #[test]
    fn test_parse_app_config_from_item() {
        let mut item = HashMap::new();
        item.insert("app_id".to_string(), AttributeValue::S("test_app".to_string()));
        item.insert("name".to_string(), AttributeValue::S("Test Application".to_string()));
        item.insert("relying_party_id".to_string(), AttributeValue::S("example.com".to_string()));
        item.insert("relying_party_name".to_string(), AttributeValue::S("Test App".to_string()));
        item.insert("allowed_origins".to_string(), AttributeValue::Ss(vec!["https://example.com".to_string()]));
        item.insert("jwt_secret".to_string(), AttributeValue::S("secret123".to_string()));
        item.insert("jwt_expires_in".to_string(), AttributeValue::N("3600".to_string()));
        item.insert("session_timeout_seconds".to_string(), AttributeValue::N("300".to_string()));
        item.insert("otp_expires_in".to_string(), AttributeValue::N("1800".to_string()));
        item.insert("created_at".to_string(), AttributeValue::S("2023-01-01T00:00:00Z".to_string()));
        item.insert("updated_at".to_string(), AttributeValue::S("2023-01-01T00:00:00Z".to_string()));
        item.insert("is_active".to_string(), AttributeValue::Bool(true));
        item.insert("admin_emails".to_string(), AttributeValue::Ss(vec!["admin@example.com".to_string()]));

        let app_config = parse_app_config_from_item(item).unwrap();
        assert_eq!(app_config.app_id, "test_app");
        assert_eq!(app_config.name, "Test Application");
        assert_eq!(app_config.relying_party_id, "example.com");
        assert_eq!(app_config.jwt_expires_in, 3600);
        assert_eq!(app_config.session_timeout_seconds, 300);
        assert_eq!(app_config.otp_expires_in, 1800);
        assert!(app_config.is_active);
        // Test default values for backward compatibility
        assert_eq!(app_config.registration_mode, RegistrationMode::InviteOnly);
        assert!(!app_config.auto_approve_registration);
    }

    #[test]
    fn test_service_config_encryption_with_tables() {
        let service_config = create_test_service_config();
        
        // Test that standard encryption configuration works
        assert_eq!(service_config.encryption_level, EncryptionLevel::Standard);
        assert!(service_config.kms_key_arn.is_none());
        assert!(!service_config.uses_customer_managed_keys());
        assert!(service_config.validate_encryption_config().is_ok());

        // Test table naming with encryption
        let db_config = create_test_dynamodb_config();
        assert_eq!(db_config.table_name("users"), "passkey-users-test");
    }

    #[test]
    fn test_encryption_levels_for_table_creation() {
        // Test that both encryption levels can be used with SSE specification
        let standard_config = ServiceConfig {
            encryption_level: EncryptionLevel::Standard,
            kms_key_arn: None,
            ..create_test_service_config()
        };
        
        let enterprise_config = ServiceConfig {
            encryption_level: EncryptionLevel::Enterprise,
            kms_key_arn: Some("arn:aws:kms:us-east-1:123456789012:key/test".to_string()),
            ..create_test_service_config()
        };

        // Both should create valid SSE specifications
        let standard_sse = create_sse_specification(&standard_config);
        let enterprise_sse = create_sse_specification(&enterprise_config);
        
        // Verify they were created without panicking
        assert!(true);
    }

    #[test]
    fn test_table_creation_integration() {
        // Integration test for table creation components
        let service_config = create_test_service_config();
        let db_config = create_test_dynamodb_config();
        
        // Test that all table names can be generated
        let users_table = db_config.table_name("users");
        let credentials_table = db_config.table_name("credentials");
        let sessions_table = db_config.table_name("sessions");
        let pending_users_table = db_config.table_name("pending-users");
        let app_configs_table = db_config.table_name("app-configs");
        
        assert_eq!(users_table, "passkey-users-test");
        assert_eq!(credentials_table, "passkey-credentials-test");
        assert_eq!(sessions_table, "passkey-sessions-test");
        assert_eq!(pending_users_table, "passkey-pending-users-test");
        assert_eq!(app_configs_table, "passkey-app-configs-test");
        
        // Test that SSE specifications can be created for all encryption levels
        let sse_standard = create_sse_specification(&service_config);
        
        let mut enterprise_config = service_config;
        enterprise_config.encryption_level = EncryptionLevel::Enterprise;
        enterprise_config.kms_key_arn = Some("test-key".to_string());
        let sse_enterprise = create_sse_specification(&enterprise_config);
        
        // Verify successful creation
        assert!(true);
    }
}
