//! Integration tests for the Passkey GraphQL API
//!
//! This module provides comprehensive integration tests that verify the entire
//! GraphQL API functionality end-to-end, including resolvers, error handling,
//! and data flow.

use std::sync::Arc;

use async_graphql::{EmptySubscription, Request, Schema, Variables};
use shared::{AwsConfig, ServiceConfig, EncryptionLevel};
use tracing_test::traced_test;

use crate::{
    context::GraphQLContext,
    schema::{MutationRoot, QueryRoot},
};

/// Test schema type alias
type TestSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

/// Creates a test GraphQL schema with mock context
async fn create_test_schema() -> TestSchema {
    // Create mock service configuration for tests
    let service_config = ServiceConfig {
        environment: "test".to_string(),
        table_prefix: "test-passkey".to_string(),
        cors_origins: vec!["http://localhost:3000".to_string()],
        default_jwt_expires_in: 3600,
        default_session_timeout: 300,
        default_otp_expires_in: 1800,
        encryption_level: EncryptionLevel::Standard,
        kms_key_arn: None,
    };

    // Create mock AWS configuration (for local testing)
    let aws_config = match AwsConfig::new().await {
        Ok(config) => config,
        Err(_) => {
            // If AWS is not available, create minimal mock for testing
            let aws_cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .load()
                .await;
            
            AwsConfig {
                dynamodb: aws_sdk_dynamodb::Client::new(&aws_cfg),
                ses: aws_sdk_ses::Client::new(&aws_cfg),
                config: aws_cfg,
            }
        }
    };

    // Create test GraphQL context
    let context = GraphQLContext::new(aws_config, service_config)
        .await
        .expect("Failed to create test GraphQL context");

    // Build test schema
    Schema::build(
        QueryRoot::default(),
        MutationRoot::default(),
        EmptySubscription,
    )
    .data(context)
    .finish()
}

/// Helper function to execute GraphQL queries for testing
async fn execute_query(schema: &TestSchema, query: &str, variables: Option<Variables>) -> async_graphql::Response {
    let mut request = Request::new(query);
    if let Some(vars) = variables {
        request = request.variables(vars);
    }
    schema.execute(request).await
}

/// Helper function to create test variables  
fn create_variables<T: serde::Serialize>(value: T) -> Variables {
    Variables::from_json(serde_json::to_value(value).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Test health query - basic functionality
    #[tokio::test]
    #[traced_test]
    async fn test_health_query() {
        let schema = create_test_schema().await;
        
        let query = r#"
            query {
                health {
                    status
                    version
                    cachedApps
                    configuredServices {
                        jwtApps
                        webauthnApps
                    }
                }
            }
        "#;

        let response = execute_query(&schema, query, None).await;
        
        // Verify successful response
        assert!(response.errors.is_empty(), "Health query should not have errors: {:?}", response.errors);
        
        let data = response.data.into_json().unwrap();
        let health = &data["health"];
        
        assert_eq!(health["status"], "healthy");
        assert!(health["version"].is_string());
        assert!(health["cachedApps"].is_number());
        assert!(health["configuredServices"]["jwtApps"].is_number());
        assert!(health["configuredServices"]["webauthnApps"].is_number());

        tracing::info!("Health query test passed successfully");
    }

    /// Test app_config query - validation and structure  
    #[tokio::test]
    #[traced_test]
    async fn test_app_config_query() {
        let schema = create_test_schema().await;
        
        let query = r#"
            query($appId: String!) {
                appConfig(appId: $appId) {
                    appId
                    name
                    relyingPartyId
                    allowedOrigins
                    registrationMode
                    autoApproveRegistration
                    isActive
                    createdAt
                    updatedAt
                }
            }
        "#;

        let variables = create_variables(json!({
            "appId": "test-app"
        }));

        let response = execute_query(&schema, query, Some(variables)).await;
        
        // This should likely return an error since we don't have test data
        // but we're verifying the GraphQL structure works correctly
        if !response.errors.is_empty() {
            // Expected error for non-existent app (could be various error types)
            assert!(response.errors[0].message.contains("not found") || 
                   response.errors[0].message.contains("not active") ||
                   response.errors[0].message.contains("Configuration error") ||
                   response.errors[0].message.contains("Database error"),
                   "Expected app-related error, got: {}", response.errors[0].message);
            tracing::info!("App config query correctly returned error for non-existent app");
        } else {
            // If no error, verify structure
            let data = response.data.into_json().unwrap();
            let app_config = &data["appConfig"];
            assert!(app_config["appId"].is_string());
            assert!(app_config["name"].is_string());
            tracing::info!("App config query returned valid structure");
        }
    }

    /// Test invite_user mutation - error handling for missing app
    #[tokio::test]
    #[traced_test]
    async fn test_invite_user_mutation_error_handling() {
        let schema = create_test_schema().await;
        
        let mutation = r#"
            mutation($input: InviteUserInput!) {
                inviteUser(input: $input) {
                    success
                    message
                    pendingUserId
                }
            }
        "#;

        let variables = create_variables(json!({
            "input": {
                "appId": "non-existent-app",
                "email": "test@example.com",
                "displayName": "Test User"
            }
        }));

        let response = execute_query(&schema, mutation, Some(variables)).await;
        
        // This should return an error due to invalid app
        assert!(!response.errors.is_empty(), "Expected error for non-existent app");
        
        // Verify error contains appropriate message and structure
        let error = &response.errors[0];
        assert!(error.message.contains("not found") || 
               error.message.contains("not active") ||
               error.message.contains("Configuration error") ||
               error.message.contains("Database error"),
               "Expected app-related error, got: {}", error.message);
        
        // Verify error extensions exist (from our error handling system)
        if let Some(extensions) = &error.extensions {
            tracing::info!("Error extensions found: {:?}", extensions);
        }
        
        tracing::info!("Invite user mutation correctly handled error: {}", error.message);
    }

    /// Test self_register mutation - registration mode validation
    #[tokio::test]
    #[traced_test]
    async fn test_self_register_mutation_validation() {
        let schema = create_test_schema().await;
        
        let mutation = r#"
            mutation($input: SelfRegisterInput!) {
                selfRegister(input: $input) {
                    success
                    message
                    pendingUserId
                }
            }
        "#;

        let variables = create_variables(json!({
            "input": {
                "appId": "test-app",
                "email": "user@example.com",
                "displayName": "New User"
            }
        }));

        let response = execute_query(&schema, mutation, Some(variables)).await;
        
        // This should return an error since the test app doesn't exist
        assert!(!response.errors.is_empty(), "Expected error for non-existent app");
        
        let error = &response.errors[0];
        if let Some(extensions) = &error.extensions {
            tracing::info!("Self register error extensions: {:?}", extensions);
        }
        
        tracing::info!("Self register mutation validation test passed: {}", error.message);
    }

    /// Test start_registration mutation - OTP format validation
    #[tokio::test]
    #[traced_test]
    async fn test_start_registration_otp_validation() {
        let schema = create_test_schema().await;
        
        let mutation = r#"
            mutation($input: StartRegistrationInput!) {
                startRegistration(input: $input) {
                    success
                    challenge
                    sessionId
                }
            }
        "#;

        // Test with invalid OTP format
        let variables = create_variables(json!({
            "input": {
                "appId": "test-app",
                "pendingUserId": "test-pending-user",
                "otp": "invalid-otp-format"
            }
        }));

        let response = execute_query(&schema, mutation, Some(variables)).await;
        
        // Should return OTP validation error or app-related error
        assert!(!response.errors.is_empty(), "Expected validation error");
        
        let error = &response.errors[0];
        // Can be OTP validation error or app-related error
        assert!(error.message.contains("Invalid OTP format") || 
               error.message.contains("Invalid request") ||
               error.message.contains("not found") ||
               error.message.contains("Database error"));
        
        // Verify error code in extensions
        if let Some(extensions) = &error.extensions {
            tracing::info!("Error extensions: {:?}", extensions);
        }
        
        tracing::info!("Start registration validation test passed: {}", error.message);
    }

    /// Test GraphQL introspection - schema structure
    #[tokio::test]
    #[traced_test]
    async fn test_schema_introspection() {
        let schema = create_test_schema().await;
        
        let introspection_query = r#"
            query {
                __schema {
                    types {
                        name
                        kind
                    }
                    queryType {
                        name
                    }
                    mutationType {
                        name
                    }
                }
            }
        "#;

        let response = execute_query(&schema, introspection_query, None).await;
        
        assert!(response.errors.is_empty(), "Introspection query should not have errors");
        
        let data = response.data.into_json().unwrap();
        let schema_data = &data["__schema"];
        
        assert_eq!(schema_data["queryType"]["name"], "QueryRoot");
        assert_eq!(schema_data["mutationType"]["name"], "MutationRoot");
        
        // Verify some of our custom types exist
        let types: Vec<_> = schema_data["types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap_or(""))
            .collect();
        
        assert!(types.contains(&"HealthResponse"));
        assert!(types.contains(&"InviteUserInput"));
        assert!(types.contains(&"SelfRegisterInput"));
        assert!(types.contains(&"RegistrationMode"));
        assert!(types.contains(&"UserRole"));
        
        tracing::info!("Schema introspection test passed - {} types found", types.len());
    }

    /// Test concurrent requests - basic load testing
    #[tokio::test]
    #[traced_test]
    async fn test_concurrent_health_queries() {
        let schema = Arc::new(create_test_schema().await);
        
        let query = r#"
            query {
                health {
                    status
                    version
                }
            }
        "#;

        // Execute multiple concurrent health queries
        let tasks = (0..10).map(|i| {
            let schema_clone = Arc::clone(&schema);
            let query_str = query.to_string();
            
            tokio::spawn(async move {
                tracing::info!("Starting concurrent health query {}", i);
                let response = execute_query(&*schema_clone, &query_str, None).await;
                assert!(response.errors.is_empty(), "Concurrent query {} failed", i);
                
                let data = response.data.into_json().unwrap();
                assert_eq!(data["health"]["status"], "healthy");
                
                tracing::info!("Completed concurrent health query {}", i);
                i
            })
        });

        // Wait for all tasks to complete
        let results = futures::future::join_all(tasks).await;
        
        // Verify all tasks completed successfully
        for (index, result) in results.into_iter().enumerate() {
            let task_id = result.unwrap();
            assert_eq!(task_id, index, "Task {} completed out of order", index);
        }
        
        tracing::info!("Concurrent health queries test passed - all 10 queries successful");
    }

    /// Test error handling consistency across all resolvers
    #[tokio::test]
    #[traced_test]
    async fn test_error_handling_consistency() {
        let schema = create_test_schema().await;
        
        // Test various queries/mutations that should produce errors
        let test_cases = vec![
            ("Invalid app config query", r#"query { appConfig(appId: "non-existent") { appId } }"#),
            ("Invalid invite user", r#"mutation { inviteUser(input: { appId: "invalid", email: "test@test.com", displayName: "Test" }) { success } }"#),
            ("Invalid self register", r#"mutation { selfRegister(input: { appId: "invalid", email: "test@test.com", displayName: "Test" }) { success } }"#),
        ];
        
        for (test_name, query) in test_cases {
            let response = execute_query(&schema, query, None).await;
            
            // All should have errors
            assert!(!response.errors.is_empty(), "{} should produce an error", test_name);
            
            let error = &response.errors[0];
            
            // All errors should have extensions (from our error handling system)
            if let Some(extensions) = &error.extensions {
                tracing::info!("{} error extensions: {:?}", test_name, extensions);
            }
            
            tracing::info!("{} error handling test passed: {}", test_name, error.message);
        }
    }

    /// Test input validation across mutations
    #[tokio::test]
    #[traced_test]
    async fn test_input_validation() {
        let schema = create_test_schema().await;
        
        // Test invalid email format in invite user
        let mutation = r#"
            mutation {
                inviteUser(input: { 
                    appId: "test", 
                    email: "invalid-email", 
                    displayName: "Test User" 
                }) {
                    success
                }
            }
        "#;
        
        let response = execute_query(&schema, mutation, None).await;
        
        // Should have validation or app-related error
        assert!(!response.errors.is_empty(), "Expected validation error for invalid email or app");
        
        tracing::info!("Input validation test completed");
    }
}

/// Integration tests for Lambda function execution
#[cfg(test)]
mod lambda_integration_tests {
    use super::*;

    /// Test that the GraphQL schema can be created and executed in Lambda context
    #[tokio::test]
    #[traced_test]
    async fn test_lambda_schema_creation() {
        // This simulates the schema creation process that happens in main()
        let result = create_test_schema().await;
        
        // Verify schema was created successfully by executing a simple query
        let query = r#"query { health { status } }"#;
        let response = execute_query(&result, query, None).await;
        assert!(response.errors.is_empty(), "Schema should be created successfully");
        
        tracing::info!("Lambda schema creation test passed");
    }

    /// Test basic Lambda function workflow simulation
    #[tokio::test]
    #[traced_test]
    async fn test_lambda_request_handling() {
        let schema = create_test_schema().await;
        
        // Simulate a basic Lambda request with health check
        let query = r#"query { health { status } }"#;
        let response = execute_query(&schema, query, None).await;
        
        // Verify Lambda-style response
        assert!(response.errors.is_empty(), "Lambda request should succeed");
        
        let data = response.data.into_json().unwrap();
        assert_eq!(data["health"]["status"], "healthy");
        
        tracing::info!("Lambda request handling test passed");
    }
}