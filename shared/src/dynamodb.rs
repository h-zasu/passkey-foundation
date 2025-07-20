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

use anyhow::Result;
use aws_sdk_dynamodb::types::{
    AttributeDefinition, BillingMode, GlobalSecondaryIndex, KeySchemaElement, KeyType,
    LocalSecondaryIndex, Projection, ProjectionType, ScalarAttributeType, TimeToLiveSpecification,
};

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
    /// let config = DynamoDbConfig::new("myapp", "dev", "us-west-2");
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
    /// let config = DynamoDbConfig::new("passkey", "dev", "us-west-2");
    /// assert_eq!(config.table_name("users"), "passkey-users-dev");
    /// ```
    pub fn table_name(&self, table_type: &str) -> String {
        format!("{}-{}-{}", self.table_prefix, table_type, self.environment)
    }
}

/// Creates all DynamoDB tables required for the authentication system.
///
/// This function creates three tables in the specified AWS region:
/// - `{prefix}-users-{env}`: User account information
/// - `{prefix}-credentials-{env}`: WebAuthn credentials
/// - `{prefix}-sessions-{env}`: Authentication sessions with TTL
///
/// # Arguments
///
/// * `config` - DynamoDB configuration with prefix, environment, and region
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
/// # async fn example() -> Result<()> {
/// let config = DynamoDbConfig::new("passkey", "dev", "us-west-2");
/// create_dynamodb_tables(&config).await?;
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
pub async fn create_dynamodb_tables(config: &DynamoDbConfig) -> Result<()> {
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(config.region.clone()))
        .load()
        .await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&aws_config);

    let tables = vec![
        create_users_table(&dynamodb, config).await,
        create_credentials_table(&dynamodb, config).await,
        create_sessions_table(&dynamodb, config).await,
    ];

    for result in tables {
        result?;
    }

    Ok(())
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
///
/// # Returns
///
/// Returns `Ok(())` if table creation succeeds or table already exists.
async fn create_users_table(
    dynamodb: &aws_sdk_dynamodb::Client,
    config: &DynamoDbConfig,
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
        );

    request.send().await?;
    println!("✅ Created table: {table_name}");
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
///
/// # Returns
///
/// Returns `Ok(())` if table creation succeeds or table already exists.
async fn create_credentials_table(
    dynamodb: &aws_sdk_dynamodb::Client,
    config: &DynamoDbConfig,
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
        );

    request.send().await?;
    println!("✅ Created table: {table_name}");
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
///
/// # Returns
///
/// Returns `Ok(())` if table creation and TTL setup succeed, or table already exists.
async fn create_sessions_table(
    dynamodb: &aws_sdk_dynamodb::Client,
    config: &DynamoDbConfig,
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
        );

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
    println!("✅ Created table with TTL: {table_name}");
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
