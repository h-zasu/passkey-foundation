//! Shared library for Passkey authentication system.
//!
//! This crate provides common functionality shared across different components
//! of the Passkey system, including DynamoDB table management, data types,
//! configuration management, and error handling.

pub mod config;
pub mod dynamodb;
pub mod email;
pub mod errors;
pub mod jwt;
pub mod otp;
pub mod types;
pub mod webauthn;

pub use config::*;
pub use dynamodb::*;
pub use email::*;
pub use errors::*;
pub use jwt::*;
pub use otp::*;
pub use types::*;
pub use webauthn::*;
