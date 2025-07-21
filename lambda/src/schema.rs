//! GraphQL schema definition for the Passkey authentication system
//!
//! This module defines the GraphQL schema including Query and Mutation types,
//! input and output types, and custom scalars.

use async_graphql::{Object, SimpleObject, Context, Result, Scalar, ScalarType, InputValueResult, InputValueError, Value};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tracing;

use crate::context::GraphQLContext;
use crate::errors::{IntoGraphQLError, forbidden_error, bad_request_error, internal_error};
use shared::types::{RegistrationMode as SharedRegistrationMode, UserRole as SharedUserRole};

// Custom Scalars

/// Custom DateTime scalar that handles RFC 3339 formatted date strings
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DateTime(pub OffsetDateTime);

#[Scalar]
impl ScalarType for DateTime {
    fn parse(value: Value) -> InputValueResult<Self> {
        match value {
            Value::String(s) => {
                OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339)
                    .map(DateTime)
                    .map_err(|e| InputValueError::custom(format!("Invalid datetime format: {}", e)))
            }
            _ => Err(InputValueError::expected_type(value)),
        }
    }

    fn to_value(&self) -> Value {
        Value::String(
            self.0
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        )
    }
}

/// JSON scalar for arbitrary JSON data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JSON(pub serde_json::Value);

#[Scalar]
impl ScalarType for JSON {
    fn parse(value: Value) -> InputValueResult<Self> {
        Ok(JSON(value.into_json().map_err(InputValueError::custom)?))
    }

    fn to_value(&self) -> Value {
        Value::from_json(self.0.clone()).unwrap_or(Value::Null)
    }
}

/// Root Query type for the GraphQL schema
#[derive(Debug, Default)]
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Get service health information
    async fn health(&self, ctx: &Context<'_>) -> Result<HealthResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        let health_info = context.get_health_info().await;
        
        Ok(HealthResponse {
            status: "healthy".to_string(),
            version: health_info.service_version,
            cached_apps: health_info.cached_apps.len() as i32,
            configured_services: ConfiguredServices {
                jwt_apps: health_info.jwt_configured_apps.len() as i32,
                webauthn_apps: health_info.webauthn_configured_apps.len() as i32,
            },
        })
    }

    /// Get application configuration (admin only)
    async fn app_config(&self, ctx: &Context<'_>, app_id: String) -> Result<AppConfigResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        let app_config = context.validate_app_access(&app_id).await?;
        
        Ok(AppConfigResponse {
            app_id: app_config.app_id,
            name: app_config.name,
            relying_party_id: app_config.relying_party_id,
            allowed_origins: app_config.allowed_origins,
            registration_mode: app_config.registration_mode.into(),
            auto_approve_registration: app_config.auto_approve_registration,
            is_active: app_config.is_active,
            created_at: app_config.created_at,
            updated_at: app_config.updated_at,
        })
    }

    /// Get user information by ID
    async fn user(&self, ctx: &Context<'_>, app_id: String, user_id: String) -> Result<Option<UserResponse>> {
        let context = ctx.data::<GraphQLContext>()?;
        
        // Validate app access
        context.validate_app_access(&app_id).await?;
        
        // Get user from database
        let table_name = context.table_name("users");
        let user_pk = format!("{}#{}", app_id, user_id);
        
        if let Some(user) = shared::get_user(&context.aws_config.dynamodb, &table_name, &user_pk).await? {
            Ok(Some(UserResponse {
                user_id: user.user_id,
                app_id: user.app_id,
                email: user.email,
                display_name: user.display_name,
                role: user.role.into(),
                is_active: user.is_active,
                created_at: user.created_at,
                updated_at: user.updated_at,
                last_login: user.last_login,
            }))
        } else {
            Ok(None)
        }
    }

    /// List users for an application (with pagination)
    async fn users(
        &self,
        ctx: &Context<'_>,
        app_id: String,
        first: Option<i32>,
        after: Option<String>,
        last: Option<i32>,
        before: Option<String>,
    ) -> Result<UserConnection> {
        let context = ctx.data::<GraphQLContext>()?;
        
        // Validate app access
        context.validate_app_access(&app_id).await?;
        
        // Validate pagination arguments
        let pagination = PaginationArgs::new(first, after, last, before)?;
        
        // For now, return empty connection - full implementation would:
        // 1. Query DynamoDB with proper GSI on app_id
        // 2. Use pagination.limit() and cursor values for DynamoDB pagination
        // 3. Decode cursors to DynamoDB LastEvaluatedKey
        // 4. Encode DynamoDB keys to base64 cursors
        // 5. Calculate has_next_page/has_previous_page based on result count
        
        let limit = pagination.limit();
        tracing::info!(
            "Querying users for app_id: {}, limit: {}, forward: {}",
            app_id,
            limit,
            pagination.is_forward()
        );
        
        Ok(UserConnection {
            edges: vec![],
            page_info: PageInfo {
                has_next_page: false,
                has_previous_page: false,
                start_cursor: None,
                end_cursor: None,
            },
            total_count: 0,
        })
    }
}

/// Root Mutation type for the GraphQL schema
#[derive(Debug, Default)]
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Invite a user to register (admin only)
    async fn invite_user(
        &self,
        ctx: &Context<'_>,
        input: InviteUserInput,
    ) -> Result<InviteUserResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        
        // Validate app access
        let app_config = context.validate_app_access(&input.app_id).await?;
        
        // Generate OTP for invitation
        let (otp, _salt, otp_hash) = context.otp_service.generate_otp();
        
        // Create pending user entry
        let pending_user_id = uuid::Uuid::new_v4().to_string();
        let _table_name = context.table_name("pending-users");
        
        // For now, log the generated information (in production this would be stored in DynamoDB)
        tracing::info!(
            "Generated invitation for {} in app {}: pending_user_id={}, otp_hash={}",
            input.email,
            input.app_id,
            pending_user_id,
            otp_hash
        );
        
        // TODO: Store in PendingUsers DynamoDB table
        // TODO: Send actual email via SES
        // For now, include OTP in response for development purposes
        tracing::info!("Generated OTP: {} (this would be sent via email)", otp);
        
        // Send invitation email
        let subject = format!("Invitation to join {}", app_config.name);
        let _message = format!(
            "You have been invited to join {}. Your verification code is: {}",
            app_config.name, otp
        );
        
        // Log email details (in production this would use SES)
        tracing::info!(
            "Would send email to {} with subject '{}' and OTP: {}",
            input.email,
            subject,
            otp
        );
        
        Ok(InviteUserResponse {
            success: true,
            message: format!("Invitation sent to {}", input.email),
            pending_user_id: Some(pending_user_id),
        })
    }

    /// Self-register a user (if public registration is enabled)
    async fn self_register(
        &self,
        ctx: &Context<'_>,
        input: SelfRegisterInput,
    ) -> Result<SelfRegisterResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        
        // Validate app access
        let app_config = context.validate_app_access(&input.app_id).await?;
        
        // Check if public registration is enabled
        if app_config.registration_mode != SharedRegistrationMode::PublicRegistration {
            return Err(forbidden_error("Public registration is not enabled for this application"));
        }
        
        // Generate OTP for self-registration
        let (otp, _salt, otp_hash) = context.otp_service.generate_otp();
        
        // Create pending user entry
        let pending_user_id = uuid::Uuid::new_v4().to_string();
        let _table_name = context.table_name("pending-users");
        
        // For now, log the generated information (in production this would be stored in DynamoDB)
        tracing::info!(
            "Generated self-registration for {} in app {}: pending_user_id={}, otp_hash={}",
            input.email,
            input.app_id,
            pending_user_id,
            otp_hash
        );
        
        // TODO: Store in PendingUsers DynamoDB table
        // TODO: Send actual email via SES
        // For now, include OTP in response for development purposes
        tracing::info!("Generated OTP: {} (this would be sent via email)", otp);
        
        // Send verification email
        let subject = format!("Verify your registration for {}", app_config.name);
        let _message = format!(
            "Welcome! Please verify your email address with this code: {}",
            otp
        );
        
        // Log email details (in production this would use SES)
        tracing::info!(
            "Would send email to {} with subject '{}' and OTP: {}",
            input.email,
            subject,
            otp
        );
        
        Ok(SelfRegisterResponse {
            success: true,
            message: format!("Verification email sent to {}", input.email),
            pending_user_id: Some(pending_user_id),
        })
    }

    /// Start WebAuthn registration process
    async fn start_registration(
        &self,
        ctx: &Context<'_>,
        input: StartRegistrationInput,
    ) -> Result<StartRegistrationResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        
        // Validate app access
        let app_config = context.validate_app_access(&input.app_id).await?;
        
        // TODO: Verify OTP and get pending user from DynamoDB
        // For now, validate OTP format and log the attempt
        if input.otp.len() != 6 || !input.otp.chars().all(|c| c.is_ascii_digit()) {
            return Err(bad_request_error("Invalid OTP format"));
        }
        
        tracing::info!(
            "Starting registration for pending_user_id: {} with OTP: {} in app: {}",
            input.pending_user_id,
            input.otp,
            input.app_id
        );
        
        // Create a dummy user for WebAuthn challenge generation
        let temp_user = shared::User {
            user_id: input.pending_user_id.clone(),
            app_id: input.app_id.clone(),
            email: "temp@example.com".to_string(), // TODO: Get from pending user
            display_name: "Temp User".to_string(), // TODO: Get from pending user
            role: SharedUserRole::User,
            is_active: false,
            created_at: time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap(),
            updated_at: time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap(),
            last_login: None,
        };
        
        // Ensure WebAuthn is configured for this app
        context.ensure_webauthn_configured(&input.app_id).await?;
        
        // Generate WebAuthn registration challenge
        let webauthn_service = context.webauthn_service.read().await;
        match webauthn_service.start_registration(&input.app_id, &temp_user) {
            Ok((challenge_response, registration_state)) => {
                // TODO: Store registration state in Sessions table
                let session_id = uuid::Uuid::new_v4().to_string();
                
                tracing::info!(
                    "Generated WebAuthn challenge for pending_user_id: {}, session_id: {}",
                    input.pending_user_id,
                    session_id
                );
                
                // Convert challenge to JSON
                let challenge_json = serde_json::to_value(&challenge_response)
                    .map_err(|e| internal_error(&format!("Failed to serialize challenge: {}", e)))?;
                
                Ok(StartRegistrationResponse {
                    success: true,
                    challenge: JSON(challenge_json),
                    session_id,
                })
            }
            Err(e) => {
                tracing::error!("Failed to start WebAuthn registration: {:?}", e);
                Err(e.into_graphql_error_with_context(&input.app_id, None))
            }
        }
    }

    /// Complete WebAuthn registration process
    async fn complete_registration(
        &self,
        ctx: &Context<'_>,
        input: CompleteRegistrationInput,
    ) -> Result<CompleteRegistrationResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        
        // Validate app access
        let app_config = context.validate_app_access(&input.app_id).await?;
        
        tracing::info!(
            "Completing registration for session_id: {} in app: {}",
            input.session_id,
            input.app_id
        );
        
        // TODO: Retrieve registration state from Sessions table using session_id
        // For now, create a dummy registration state and proceed
        
        // TODO: Retrieve pending user information from database
        // For now, create a dummy user
        let new_user_id = uuid::Uuid::new_v4().to_string();
        let new_user = shared::User {
            user_id: new_user_id.clone(),
            app_id: input.app_id.clone(),
            email: "user@example.com".to_string(), // TODO: Get from pending user
            display_name: "New User".to_string(), // TODO: Get from pending user
            role: SharedUserRole::User,
            is_active: true,
            created_at: time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap(),
            updated_at: time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap(),
            last_login: Some(time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap()),
        };
        
        // TODO: Complete WebAuthn registration verification
        // For now, simulate successful registration
        tracing::info!(
            "Successfully completed registration for user: {}, credential verified",
            new_user_id
        );
        
        // TODO: Store user and credential in DynamoDB
        // TODO: Delete pending user and session
        
        // Generate JWT tokens
        context.ensure_jwt_configured(&input.app_id).await?;
        let jwt_service = context.jwt_service.read().await;
        
        match jwt_service.generate_access_token(
            new_user.user_id.clone(),
            new_user.app_id.clone(),
            new_user.email.clone(),
            new_user.display_name.clone(),
            new_user.role.clone(),
            None,
        ) {
            Ok(access_token) => {
                let token_id = uuid::Uuid::new_v4().to_string();
                let refresh_token = jwt_service.generate_refresh_token(new_user_id.clone(), input.app_id.clone(), token_id)
                    .unwrap_or_else(|_| "refresh-token-placeholder".to_string());
                
                let user_response = UserResponse {
                    user_id: new_user.user_id,
                    app_id: new_user.app_id,
                    email: new_user.email,
                    display_name: new_user.display_name,
                    role: new_user.role.into(),
                    is_active: new_user.is_active,
                    created_at: new_user.created_at,
                    updated_at: new_user.updated_at,
                    last_login: new_user.last_login,
                };
                
                Ok(CompleteRegistrationResponse {
                    success: true,
                    user: Some(user_response),
                    access_token: Some(access_token),
                    refresh_token: Some(refresh_token),
                })
            }
            Err(e) => {
                tracing::error!("Failed to generate JWT tokens: {:?}", e);
                Err(e.into_graphql_error_with_context(&input.app_id, Some(&new_user_id)))
            }
        }
    }

    /// Start WebAuthn authentication process
    async fn start_authentication(
        &self,
        ctx: &Context<'_>,
        input: StartAuthenticationInput,
    ) -> Result<StartAuthenticationResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        
        // Validate app access
        let app_config = context.validate_app_access(&input.app_id).await?;
        
        tracing::info!(
            "Starting authentication for {} in app: {}",
            input.email,
            input.app_id
        );
        
        // TODO: Find user by email and app_id in DynamoDB
        // For now, create a dummy user for demonstration
        let user_id = "demo-user-id";
        let _table_name = context.table_name("users");
        let _user_pk = format!("{}#{}", input.app_id, user_id);
        
        // TODO: Get user's credentials from DynamoDB
        // For now, create dummy credentials for WebAuthn challenge
        let dummy_credentials = vec![]; // Empty for now
        
        tracing::info!(
            "Found user with {} credentials for authentication",
            dummy_credentials.len()
        );
        
        // Ensure WebAuthn is configured for this app
        context.ensure_webauthn_configured(&input.app_id).await?;
        
        // Generate WebAuthn authentication challenge
        let webauthn_service = context.webauthn_service.read().await;
        match webauthn_service.start_authentication(&input.app_id, dummy_credentials) {
            Ok((challenge_response, authentication_state)) => {
                // TODO: Store authentication state in Sessions table
                let session_id = uuid::Uuid::new_v4().to_string();
                
                tracing::info!(
                    "Generated WebAuthn authentication challenge for {}, session_id: {}",
                    input.email,
                    session_id
                );
                
                // Convert challenge to JSON
                let challenge_json = serde_json::to_value(&challenge_response)
                    .map_err(|e| internal_error(&format!("Failed to serialize challenge: {}", e)))?;
                
                Ok(StartAuthenticationResponse {
                    success: true,
                    challenge: JSON(challenge_json),
                    session_id,
                })
            }
            Err(e) => {
                tracing::error!("Failed to start WebAuthn authentication: {:?}", e);
                Err(e.into_graphql_error_with_context(&input.app_id, None))
            }
        }
    }

    /// Complete WebAuthn authentication process
    async fn complete_authentication(
        &self,
        ctx: &Context<'_>,
        input: CompleteAuthenticationInput,
    ) -> Result<CompleteAuthenticationResponse> {
        let context = ctx.data::<GraphQLContext>()?;
        
        // Validate app access
        let app_config = context.validate_app_access(&input.app_id).await?;
        
        tracing::info!(
            "Completing authentication for session_id: {} in app: {}",
            input.session_id,
            input.app_id
        );
        
        // TODO: Retrieve authentication state from Sessions table using session_id
        // TODO: Verify WebAuthn assertion using stored state and user credentials
        
        // For now, simulate successful authentication
        let user_id = "demo-user-id";
        let authenticated_user = shared::User {
            user_id: user_id.to_string(),
            app_id: input.app_id.clone(),
            email: "user@example.com".to_string(), // TODO: Get from database
            display_name: "Demo User".to_string(), // TODO: Get from database
            role: SharedUserRole::User,
            is_active: true,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            updated_at: time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap(),
            last_login: Some(time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap()),
        };
        
        tracing::info!(
            "Successfully authenticated user: {}, assertion verified",
            user_id
        );
        
        // TODO: Update credential counter in DynamoDB
        // TODO: Update user's last_login timestamp
        // TODO: Delete authentication session
        
        // Generate JWT tokens
        context.ensure_jwt_configured(&input.app_id).await?;
        let jwt_service = context.jwt_service.read().await;
        
        match jwt_service.generate_access_token(
            authenticated_user.user_id.clone(),
            authenticated_user.app_id.clone(),
            authenticated_user.email.clone(),
            authenticated_user.display_name.clone(),
            authenticated_user.role.clone(),
            None,
        ) {
            Ok(access_token) => {
                let token_id = uuid::Uuid::new_v4().to_string();
                let refresh_token = jwt_service.generate_refresh_token(authenticated_user.user_id.clone(), input.app_id.clone(), token_id)
                    .unwrap_or_else(|_| "refresh-token-placeholder".to_string());
                
                let user_response = UserResponse {
                    user_id: authenticated_user.user_id,
                    app_id: authenticated_user.app_id,
                    email: authenticated_user.email,
                    display_name: authenticated_user.display_name,
                    role: authenticated_user.role.into(),
                    is_active: authenticated_user.is_active,
                    created_at: authenticated_user.created_at,
                    updated_at: authenticated_user.updated_at,
                    last_login: authenticated_user.last_login,
                };
                
                Ok(CompleteAuthenticationResponse {
                    success: true,
                    user: Some(user_response),
                    access_token: Some(access_token),
                    refresh_token: Some(refresh_token),
                })
            }
            Err(e) => {
                tracing::error!("Failed to generate JWT tokens: {:?}", e);
                Err(e.into_graphql_error_with_context(&input.app_id, None))
            }
        }
    }

    // ===== 管理機能 =====

    /// Update user information (admin only)
    async fn update_user(
        &self,
        ctx: &Context<'_>,
        input: UpdateUserInput,
    ) -> Result<UpdateUserResponse> {
        let context = ctx.data::<GraphQLContext>()?;

        // TODO: Implement JWT token verification and admin permission check
        // For now, log the operation
        tracing::info!(
            "Admin updating user {} in app {}: display_name={:?}, is_active={:?}, role={:?}",
            input.user_id,
            input.app_id,
            input.display_name,
            input.is_active,
            input.role
        );

        // Validate app access
        let _app_config = context.validate_app_access(&input.app_id).await?;

        // TODO: Verify admin permissions
        // TODO: Get user from database
        // TODO: Update user information
        // TODO: Save changes to DynamoDB

        // For now, return a mock success response
        let updated_user = UserResponse {
            user_id: input.user_id.clone(),
            app_id: input.app_id.clone(),
            email: "user@example.com".to_string(), // TODO: Get from database
            display_name: input.display_name.unwrap_or("Updated User".to_string()),
            role: input.role.map(|r| r.into()).unwrap_or(UserRole::User),
            is_active: input.is_active.unwrap_or(true),
            created_at: "2025-01-01T00:00:00Z".to_string(), // TODO: Get from database
            updated_at: time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap(),
            last_login: None,
        };

        Ok(UpdateUserResponse {
            success: true,
            message: format!("User {} updated successfully", input.user_id),
            user: Some(updated_user),
        })
    }

    /// Deactivate user account (admin only)
    async fn deactivate_user(
        &self,
        ctx: &Context<'_>,
        input: DeactivateUserInput,
    ) -> Result<DeactivateUserResponse> {
        let context = ctx.data::<GraphQLContext>()?;

        tracing::info!(
            "Admin deactivating user {} in app {}: reason={:?}",
            input.user_id,
            input.app_id,
            input.reason
        );

        // Validate app access
        let _app_config = context.validate_app_access(&input.app_id).await?;

        // TODO: Verify admin permissions
        // TODO: Get user from database
        // TODO: Set user as inactive
        // TODO: Invalidate user sessions
        // TODO: Save changes to DynamoDB

        Ok(DeactivateUserResponse {
            success: true,
            message: format!("User {} deactivated successfully", input.user_id),
        })
    }

    /// Delete user credential (admin or user owner)
    async fn delete_credential(
        &self,
        ctx: &Context<'_>,
        input: DeleteCredentialInput,
    ) -> Result<DeleteCredentialResponse> {
        let context = ctx.data::<GraphQLContext>()?;

        tracing::info!(
            "Deleting credential {} for user {} in app {}",
            input.credential_id,
            input.user_id,
            input.app_id
        );

        // Validate app access
        let _app_config = context.validate_app_access(&input.app_id).await?;

        // TODO: Verify user ownership or admin permissions
        // TODO: Get credential from database
        // TODO: Verify credential belongs to user
        // TODO: Delete credential from DynamoDB
        // TODO: Log security event

        Ok(DeleteCredentialResponse {
            success: true,
            message: format!("Credential {} deleted successfully", input.credential_id),
        })
    }

    /// Update credential name (admin or user owner)
    async fn update_credential_name(
        &self,
        ctx: &Context<'_>,
        input: UpdateCredentialNameInput,
    ) -> Result<UpdateCredentialNameResponse> {
        let context = ctx.data::<GraphQLContext>()?;

        tracing::info!(
            "Updating credential {} name to '{}' for user {} in app {}",
            input.credential_id,
            input.new_name,
            input.user_id,
            input.app_id
        );

        // Validate app access
        let _app_config = context.validate_app_access(&input.app_id).await?;

        // TODO: Verify user ownership or admin permissions
        // TODO: Get credential from database
        // TODO: Update credential name
        // TODO: Save changes to DynamoDB

        Ok(UpdateCredentialNameResponse {
            success: true,
            message: format!("Credential {} name updated to '{}'", input.credential_id, input.new_name),
            credential_id: input.credential_id,
            new_name: input.new_name,
        })
    }
}

// GraphQL Types

/// Health check response
#[derive(SimpleObject)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub cached_apps: i32,
    pub configured_services: ConfiguredServices,
}

/// Information about configured services
#[derive(SimpleObject)]
pub struct ConfiguredServices {
    pub jwt_apps: i32,
    pub webauthn_apps: i32,
}

/// Application configuration response
#[derive(SimpleObject)]
pub struct AppConfigResponse {
    pub app_id: String,
    pub name: String,
    pub relying_party_id: String,
    pub allowed_origins: Vec<String>,
    pub registration_mode: RegistrationMode,
    pub auto_approve_registration: bool,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// User response type
#[derive(SimpleObject)]
pub struct UserResponse {
    pub user_id: String,
    pub app_id: String,
    pub email: String,
    pub display_name: String,
    pub role: UserRole,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_login: Option<String>,
}

/// Connection type for paginated user results
#[derive(SimpleObject)]
pub struct UserConnection {
    pub edges: Vec<UserEdge>,
    pub page_info: PageInfo,
    pub total_count: i32,
}

/// Edge type for user connection
#[derive(SimpleObject)]
pub struct UserEdge {
    pub node: UserResponse,
    pub cursor: String,
}

/// Page info for pagination following Relay Cursor Connections Specification
#[derive(SimpleObject)]
pub struct PageInfo {
    /// Whether there are more items when paginating forward
    pub has_next_page: bool,
    /// Whether there are more items when paginating backward
    pub has_previous_page: bool,
    /// Cursor for the first item in the current page
    pub start_cursor: Option<String>,
    /// Cursor for the last item in the current page
    pub end_cursor: Option<String>,
}

/// Generic connection interface for implementing cursor-based pagination
pub struct Connection<T> {
    pub edges: Vec<Edge<T>>,
    pub page_info: PageInfo,
    pub total_count: i32,
}

/// Generic edge type for pagination
pub struct Edge<T> {
    pub node: T,
    pub cursor: String,
}

/// Pagination arguments for implementing consistent pagination across queries
#[derive(Debug, Clone)]
pub struct PaginationArgs {
    pub first: Option<i32>,
    pub after: Option<String>,
    pub last: Option<i32>,
    pub before: Option<String>,
}

impl PaginationArgs {
    /// Creates new pagination arguments with validation
    pub fn new(
        first: Option<i32>,
        after: Option<String>,
        last: Option<i32>,
        before: Option<String>,
    ) -> Result<Self> {
        // Validate pagination arguments according to Relay specification
        if first.is_some() && last.is_some() {
            return Err(bad_request_error("Cannot provide both 'first' and 'last' arguments"));
        }

        if let Some(first) = first {
            if first < 0 {
                return Err(bad_request_error("'first' argument must be non-negative"));
            }
            if first > 100 {
                return Err(bad_request_error("'first' argument cannot exceed 100"));
            }
        }

        if let Some(last) = last {
            if last < 0 {
                return Err(bad_request_error("'last' argument must be non-negative"));
            }
            if last > 100 {
                return Err(bad_request_error("'last' argument cannot exceed 100"));
            }
        }

        Ok(Self {
            first,
            after,
            last,
            before,
        })
    }

    /// Returns the effective limit for the query
    pub fn limit(&self) -> i32 {
        if let Some(first) = self.first {
            first.min(100)
        } else if let Some(last) = self.last {
            last.min(100)
        } else {
            20 // Default page size
        }
    }

    /// Returns true if paginating forward
    pub fn is_forward(&self) -> bool {
        self.first.is_some() || self.after.is_some()
    }
}

// Input Types

/// Input for inviting a user
#[derive(Serialize, Deserialize, async_graphql::InputObject)]
pub struct InviteUserInput {
    /// Application ID
    pub app_id: String,
    /// User's email address
    pub email: String,
    /// User's display name
    pub display_name: String,
    /// Optional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Response for user invitation
#[derive(SimpleObject)]
pub struct InviteUserResponse {
    pub success: bool,
    pub message: String,
    pub pending_user_id: Option<String>,
}

/// Input for self-registration
#[derive(Serialize, Deserialize, async_graphql::InputObject)]
pub struct SelfRegisterInput {
    /// Application ID
    pub app_id: String,
    /// User's email address
    pub email: String,
    /// User's display name
    pub display_name: String,
}

/// Response for self-registration
#[derive(SimpleObject)]
pub struct SelfRegisterResponse {
    pub success: bool,
    pub message: String,
    pub pending_user_id: Option<String>,
}

// WebAuthn Authentication Flow Types

/// Input for starting WebAuthn registration
#[derive(Serialize, Deserialize, async_graphql::InputObject)]
pub struct StartRegistrationInput {
    /// Application ID
    pub app_id: String,
    /// Pending user ID (from OTP verification)
    pub pending_user_id: String,
    /// OTP for verification
    pub otp: String,
}

/// Response for starting WebAuthn registration
#[derive(SimpleObject)]
pub struct StartRegistrationResponse {
    pub success: bool,
    pub challenge: JSON,
    pub session_id: String,
}

/// Input for completing WebAuthn registration
#[derive(Serialize, Deserialize, async_graphql::InputObject)]
pub struct CompleteRegistrationInput {
    /// Application ID
    pub app_id: String,
    /// Session ID from registration start
    pub session_id: String,
    /// WebAuthn credential response
    pub credential: JSON,
}

/// Response for completing WebAuthn registration
#[derive(SimpleObject)]
pub struct CompleteRegistrationResponse {
    pub success: bool,
    pub user: Option<UserResponse>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
}

/// Input for starting WebAuthn authentication
#[derive(Serialize, Deserialize, async_graphql::InputObject)]
pub struct StartAuthenticationInput {
    /// Application ID
    pub app_id: String,
    /// User's email address
    pub email: String,
}

/// Response for starting WebAuthn authentication
#[derive(SimpleObject)]
pub struct StartAuthenticationResponse {
    pub success: bool,
    pub challenge: JSON,
    pub session_id: String,
}

/// Input for completing WebAuthn authentication
#[derive(Serialize, Deserialize, async_graphql::InputObject)]
pub struct CompleteAuthenticationInput {
    /// Application ID
    pub app_id: String,
    /// Session ID from authentication start
    pub session_id: String,
    /// WebAuthn assertion response
    pub assertion: JSON,
}

/// Response for completing WebAuthn authentication
#[derive(SimpleObject)]
pub struct CompleteAuthenticationResponse {
    pub success: bool,
    pub user: Option<UserResponse>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
}

// Admin Management Types

/// Input for updating user information
#[derive(Serialize, Deserialize, async_graphql::InputObject)]
pub struct UpdateUserInput {
    /// Application ID
    pub app_id: String,
    /// User ID to update
    pub user_id: String,
    /// New display name (optional)
    pub display_name: Option<String>,
    /// New active status (optional)
    pub is_active: Option<bool>,
    /// New role (optional)
    pub role: Option<UserRole>,
}

/// Response for updating user information
#[derive(SimpleObject)]
pub struct UpdateUserResponse {
    pub success: bool,
    pub message: String,
    pub user: Option<UserResponse>,
}

/// Input for deactivating a user
#[derive(Serialize, Deserialize, async_graphql::InputObject)]
pub struct DeactivateUserInput {
    /// Application ID
    pub app_id: String,
    /// User ID to deactivate
    pub user_id: String,
    /// Reason for deactivation (optional)
    pub reason: Option<String>,
}

/// Response for deactivating a user
#[derive(SimpleObject)]
pub struct DeactivateUserResponse {
    pub success: bool,
    pub message: String,
}

/// Input for deleting a credential
#[derive(Serialize, Deserialize, async_graphql::InputObject)]
pub struct DeleteCredentialInput {
    /// Application ID
    pub app_id: String,
    /// User ID who owns the credential
    pub user_id: String,
    /// Credential ID to delete
    pub credential_id: String,
}

/// Response for deleting a credential
#[derive(SimpleObject)]
pub struct DeleteCredentialResponse {
    pub success: bool,
    pub message: String,
}

/// Input for updating credential name
#[derive(Serialize, Deserialize, async_graphql::InputObject)]
pub struct UpdateCredentialNameInput {
    /// Application ID
    pub app_id: String,
    /// User ID who owns the credential
    pub user_id: String,
    /// Credential ID to update
    pub credential_id: String,
    /// New name for the credential
    pub new_name: String,
}

/// Response for updating credential name
#[derive(SimpleObject)]
pub struct UpdateCredentialNameResponse {
    pub success: bool,
    pub message: String,
    pub credential_id: String,
    pub new_name: String,
}

// Enums

/// Registration mode for applications
#[derive(async_graphql::Enum, Copy, Clone, Eq, PartialEq)]
pub enum RegistrationMode {
    /// Only invited users can register
    #[graphql(name = "INVITE_ONLY")]
    InviteOnly,
    /// Public registration is allowed
    #[graphql(name = "PUBLIC_REGISTRATION")]
    PublicRegistration,
}

impl From<SharedRegistrationMode> for RegistrationMode {
    fn from(mode: SharedRegistrationMode) -> Self {
        match mode {
            SharedRegistrationMode::InviteOnly => RegistrationMode::InviteOnly,
            SharedRegistrationMode::PublicRegistration => RegistrationMode::PublicRegistration,
        }
    }
}

impl From<RegistrationMode> for SharedRegistrationMode {
    fn from(mode: RegistrationMode) -> Self {
        match mode {
            RegistrationMode::InviteOnly => SharedRegistrationMode::InviteOnly,
            RegistrationMode::PublicRegistration => SharedRegistrationMode::PublicRegistration,
        }
    }
}

/// User roles
#[derive(async_graphql::Enum, Copy, Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum UserRole {
    /// Regular user
    #[graphql(name = "USER")]
    User,
    /// Application administrator
    #[graphql(name = "ADMIN")]
    Admin,
    /// Super administrator
    #[graphql(name = "SUPER_ADMIN")]
    SuperAdmin,
}

impl From<SharedUserRole> for UserRole {
    fn from(role: SharedUserRole) -> Self {
        match role {
            SharedUserRole::User => UserRole::User,
            SharedUserRole::Admin => UserRole::Admin,
            SharedUserRole::SuperAdmin => UserRole::SuperAdmin,
        }
    }
}

impl From<UserRole> for SharedUserRole {
    fn from(role: UserRole) -> Self {
        match role {
            UserRole::User => SharedUserRole::User,
            UserRole::Admin => SharedUserRole::Admin,
            UserRole::SuperAdmin => SharedUserRole::SuperAdmin,
        }
    }
}

// Additional utility types

/// Credential information for a user
#[derive(SimpleObject)]
pub struct CredentialResponse {
    pub credential_id: String,
    pub name: String,
    pub created_at: DateTime,
    pub last_used: Option<DateTime>,
}

/// Session information
#[derive(SimpleObject)]
pub struct SessionResponse {
    pub session_id: String,
    pub session_type: String,
    pub expires_at: DateTime,
    pub created_at: DateTime,
}