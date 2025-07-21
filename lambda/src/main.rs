//! AWS Lambda function for Passkey GraphQL API
//!
//! This Lambda function provides a GraphQL API for the Passkey authentication system.
//! It uses Axum web framework with async-graphql for GraphQL support.

use anyhow::Error;
use async_graphql::{EmptySubscription, Schema};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::Extension,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use lambda_runtime::{service_fn, Error as LambdaError, LambdaEvent};
use shared::{AwsConfig, ServiceConfig};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::info;

mod context;
mod schema;
mod errors;

#[cfg(test)]
mod integration_tests;

use context::GraphQLContext;
use schema::{MutationRoot, QueryRoot};

/// GraphQL schema type alias
type PasskeySchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Initialize tracing for structured logging
    tracing_subscriber::fmt()
        .with_target(false)
        .without_time()
        .init();

    info!("Starting Passkey GraphQL Lambda function");

    // Load service configuration from environment variables
    let service_config = ServiceConfig::from_env()
        .map_err(|e| anyhow::anyhow!("Failed to load service configuration: {e}"))?;

    // Initialize AWS clients
    let aws_config = AwsConfig::new()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to initialize AWS configuration: {e}"))?;

    // Create GraphQL context with AWS clients and configuration
    let context = GraphQLContext::new(aws_config, service_config)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create GraphQL context: {e}"))?;

    // Build GraphQL schema
    let schema = Schema::build(
        QueryRoot::default(),
        MutationRoot::default(),
        EmptySubscription,
    )
    .data(context)
    .finish();

    if std::env::var("AWS_LAMBDA_RUNTIME_API").is_ok() {
        // Run on AWS Lambda
        info!("Running on AWS Lambda");
        lambda_runtime::run(service_fn(|_event: LambdaEvent<serde_json::Value>| async {
            Ok::<serde_json::Value, LambdaError>(serde_json::json!({
                "statusCode": 200,
                "body": "GraphQL Lambda is running. Use POST /graphql for GraphQL queries."
            }))
        }))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to run on Lambda: {e}"))?;
    } else {
        // Run locally for development
        info!("Running locally on http://localhost:3000");
        let app = create_app(schema);
        let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
        let listener = TcpListener::bind(addr).await?;
        axum::serve(listener, app.into_make_service()).await?;
    }

    Ok(())
}

/// Creates the Axum router with GraphQL and health endpoints
fn create_app(schema: PasskeySchema) -> Router {
    Router::new()
        .route("/", get(graphql_playground))
        .route("/graphql", post(graphql_handler))
        .route("/health", get(health_handler))
        .layer(Extension(schema))
}

/// GraphQL Playground for development and testing
async fn graphql_playground() -> impl IntoResponse {
    Html(async_graphql::http::playground_source(
        async_graphql::http::GraphQLPlaygroundConfig::new("/graphql"),
    ))
}

/// GraphQL endpoint handler
async fn graphql_handler(
    Extension(schema): Extension<PasskeySchema>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
}

/// Health check endpoint
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}