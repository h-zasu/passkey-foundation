//! Shared library for Passkey authentication system.
//!
//! This crate provides common functionality shared across different components
//! of the Passkey system, including DynamoDB table management, data types,
//! and utility functions.

pub mod dynamodb;
pub mod types;

pub use dynamodb::*;
pub use types::*;
