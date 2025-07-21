//! Shared library for Passkey authentication system.
//!
//! This crate provides common functionality shared across different components
//! of the Passkey system, including DynamoDB table management, data types,
//! configuration management, and error handling.

pub mod config;
pub mod dynamodb;
pub mod errors;
pub mod types;

pub use config::*;
pub use dynamodb::*;
pub use errors::*;
pub use types::*;
