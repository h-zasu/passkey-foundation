//! One-Time Password (OTP) functionality for secure user verification.
//!
//! This module provides secure OTP generation and verification for user authentication
//! during registration and login processes. It implements industry-standard security
//! practices including:
//!
//! - Cryptographically secure random OTP generation
//! - Salted SHA-256 hashing for secure storage
//! - Time-based expiration
//! - Attempt limiting to prevent brute force attacks
//! - Constant-time comparison to prevent timing attacks

use crate::PasskeyError;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// OTP configuration constants
pub const OTP_LENGTH: usize = 6;
pub const OTP_DEFAULT_EXPIRY_SECONDS: u64 = 1800; // 30 minutes
pub const OTP_MAX_ATTEMPTS: u32 = 5;
pub const SALT_LENGTH: usize = 32;

/// OTP service for generating and verifying one-time passwords.
#[derive(Debug, Clone)]
pub struct OtpService {
    /// Default expiry time in seconds
    pub default_expiry_seconds: u64,
    /// Maximum allowed verification attempts
    pub max_attempts: u32,
}

impl OtpService {
    /// Creates a new OTP service with default configuration.
    pub fn new() -> Self {
        Self {
            default_expiry_seconds: OTP_DEFAULT_EXPIRY_SECONDS,
            max_attempts: OTP_MAX_ATTEMPTS,
        }
    }

    /// Creates a new OTP service with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `expiry_seconds` - How long OTPs remain valid (in seconds)
    /// * `max_attempts` - Maximum number of verification attempts allowed
    ///
    /// # Examples
    ///
    /// ```
    /// # use shared::otp::OtpService;
    /// let service = OtpService::with_config(900, 3); // 15 minutes, 3 attempts
    /// ```
    pub fn with_config(expiry_seconds: u64, max_attempts: u32) -> Self {
        Self {
            default_expiry_seconds: expiry_seconds,
            max_attempts,
        }
    }

    /// Generates a new 6-digit OTP and its associated salt and hash.
    ///
    /// This function generates a cryptographically secure random 6-digit number,
    /// a random salt, and returns both the plaintext OTP (for sending to user)
    /// and the salted hash (for secure storage).
    ///
    /// # Returns
    ///
    /// Returns a tuple containing:
    /// - `otp` - The plaintext 6-digit OTP string
    /// - `salt` - Base64-encoded random salt
    /// - `hash` - Hex-encoded SHA-256 hash of OTP + salt
    ///
    /// # Examples
    ///
    /// ```
    /// # use shared::otp::OtpService;
    /// let service = OtpService::new();
    /// let (otp, salt, hash) = service.generate_otp();
    /// assert_eq!(otp.len(), 6);
    /// assert!(otp.chars().all(|c| c.is_ascii_digit()));
    /// ```
    pub fn generate_otp(&self) -> (String, String, String) {
        // Generate 6-digit OTP (000000 to 999999)
        let otp = self.generate_random_otp();
        
        // Generate random salt
        let salt = self.generate_salt();
        
        // Create hash from OTP and salt
        let hash = self.hash_otp(&otp, &salt);
        
        (otp, salt, hash)
    }

    /// Verifies an OTP against the stored hash and salt.
    ///
    /// This function performs secure OTP verification with the following checks:
    /// - OTP format validation
    /// - Expiration time check
    /// - Attempt count limiting
    /// - Constant-time hash comparison
    ///
    /// # Arguments
    ///
    /// * `provided_otp` - The OTP provided by the user
    /// * `stored_hash` - The stored hash from the database
    /// * `stored_salt` - The stored salt from the database
    /// * `created_timestamp` - When the OTP was created (Unix timestamp)
    /// * `current_attempts` - How many attempts have been made
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if OTP is valid, `Ok(false)` if invalid,
    /// or `Err(PasskeyError)` for various error conditions.
    ///
    /// # Errors
    ///
    /// This function returns an error if:
    /// - OTP format is invalid
    /// - OTP has expired
    /// - Maximum attempts exceeded
    /// - Hash comparison fails due to encoding issues
    ///
    /// # Examples
    ///
    /// ```
    /// # use shared::otp::OtpService;
    /// # use std::time::{SystemTime, UNIX_EPOCH};
    /// let service = OtpService::new();
    /// let (otp, salt, hash) = service.generate_otp();
    /// let timestamp = SystemTime::now()
    ///     .duration_since(UNIX_EPOCH)
    ///     .unwrap()
    ///     .as_secs() as i64;
    /// 
    /// let result = service.verify_otp(&otp, &hash, &salt, timestamp, 0);
    /// assert!(result.is_ok());
    /// assert!(result.unwrap());
    /// ```
    pub fn verify_otp(
        &self,
        provided_otp: &str,
        stored_hash: &str,
        stored_salt: &str,
        created_timestamp: i64,
        current_attempts: u32,
    ) -> Result<bool, PasskeyError> {
        // Validate OTP format
        if !self.is_valid_otp_format(provided_otp) {
            return Err(PasskeyError::InvalidOtp("Invalid OTP format".to_string()));
        }

        // Check if OTP has expired
        if self.is_expired(created_timestamp)? {
            return Err(PasskeyError::OtpExpired);
        }

        // Check attempt limits
        if current_attempts >= self.max_attempts {
            return Err(PasskeyError::OtpMaxAttemptsExceeded);
        }

        // Hash the provided OTP with stored salt
        let computed_hash = self.hash_otp(provided_otp, stored_salt);

        // Constant-time comparison to prevent timing attacks
        Ok(self.constant_time_compare(&computed_hash, stored_hash))
    }

    /// Checks if an OTP has expired based on its creation timestamp.
    ///
    /// # Arguments
    ///
    /// * `created_timestamp` - Unix timestamp when OTP was created
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if expired, `Ok(false)` if still valid,
    /// or `Err(PasskeyError)` if timestamp validation fails.
    pub fn is_expired(&self, created_timestamp: i64) -> Result<bool, PasskeyError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| PasskeyError::SystemTime(format!("System time error: {e}")))?
            .as_secs() as i64;

        let expiry_timestamp = created_timestamp + self.default_expiry_seconds as i64;
        Ok(now > expiry_timestamp)
    }

    /// Generates a cryptographically secure 6-digit OTP.
    fn generate_random_otp(&self) -> String {
        let mut rng = rand::rng();
        let otp: u32 = rng.random_range(0..1_000_000);
        format!("{:06}", otp)
    }

    /// Generates a cryptographically secure random salt.
    ///
    /// # Returns
    ///
    /// Returns a base64-encoded salt string.
    fn generate_salt(&self) -> String {
        let mut salt = [0u8; SALT_LENGTH];
        rand::rng().fill_bytes(&mut salt);
        STANDARD.encode(&salt)
    }

    /// Creates a SHA-256 hash of OTP combined with salt.
    ///
    /// # Arguments
    ///
    /// * `otp` - The OTP to hash
    /// * `salt` - The salt to combine with OTP
    ///
    /// # Returns
    ///
    /// Returns a hex-encoded SHA-256 hash string.
    fn hash_otp(&self, otp: &str, salt: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(otp.as_bytes());
        hasher.update(salt.as_bytes());
        let result = hasher.finalize();
        hex_encode(&result)
    }

    /// Validates OTP format (must be exactly 6 digits).
    ///
    /// # Arguments
    ///
    /// * `otp` - The OTP string to validate
    ///
    /// # Returns
    ///
    /// Returns `true` if OTP format is valid, `false` otherwise.
    fn is_valid_otp_format(&self, otp: &str) -> bool {
        otp.len() == OTP_LENGTH && otp.chars().all(|c| c.is_ascii_digit())
    }

    /// Performs constant-time string comparison to prevent timing attacks.
    ///
    /// # Arguments
    ///
    /// * `a` - First string to compare
    /// * `b` - Second string to compare
    ///
    /// # Returns
    ///
    /// Returns `true` if strings are equal, `false` otherwise.
    fn constant_time_compare(&self, a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (byte_a, byte_b) in a.bytes().zip(b.bytes()) {
            result |= byte_a ^ byte_b;
        }
        result == 0
    }
}

impl Default for OtpService {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility function to convert hex string to bytes
fn hex_decode(hex_str: &str) -> Result<Vec<u8>, PasskeyError> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|e| PasskeyError::InvalidOtp(format!("Invalid hex format: {e}")))
        })
        .collect()
}

/// Utility function to encode bytes to hex string  
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_otp_service_new() {
        let service = OtpService::new();
        assert_eq!(service.default_expiry_seconds, OTP_DEFAULT_EXPIRY_SECONDS);
        assert_eq!(service.max_attempts, OTP_MAX_ATTEMPTS);
    }

    #[test]
    fn test_otp_service_with_config() {
        let service = OtpService::with_config(900, 3);
        assert_eq!(service.default_expiry_seconds, 900);
        assert_eq!(service.max_attempts, 3);
    }

    #[test]
    fn test_generate_otp() {
        let service = OtpService::new();
        let (otp, salt, hash) = service.generate_otp();
        
        // Verify OTP format
        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));
        
        // Verify salt is base64
        assert!(STANDARD.decode(&salt).is_ok());
        
        // Verify hash is hex
        assert!(hex_decode(&hash).is_ok());
    }

    #[test]
    fn test_generate_random_otp() {
        let service = OtpService::new();
        let otp = service.generate_random_otp();
        
        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));
        
        // Test that it can generate leading zeros
        let otp_num: u32 = otp.parse().unwrap();
        assert!(otp_num < 1_000_000);
    }

    #[test]
    fn test_generate_salt() {
        let service = OtpService::new();
        let salt1 = service.generate_salt();
        let salt2 = service.generate_salt();
        
        // Salts should be different
        assert_ne!(salt1, salt2);
        
        // Should be valid base64
        assert!(STANDARD.decode(&salt1).is_ok());
        assert!(STANDARD.decode(&salt2).is_ok());
    }

    #[test]
    fn test_hash_otp() {
        let service = OtpService::new();
        let otp = "123456";
        let salt = "test_salt";
        
        let hash1 = service.hash_otp(otp, salt);
        let hash2 = service.hash_otp(otp, salt);
        
        // Same input should produce same hash
        assert_eq!(hash1, hash2);
        
        // Different salt should produce different hash
        let hash3 = service.hash_otp(otp, "different_salt");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_is_valid_otp_format() {
        let service = OtpService::new();
        
        assert!(service.is_valid_otp_format("123456"));
        assert!(service.is_valid_otp_format("000000"));
        assert!(service.is_valid_otp_format("999999"));
        
        assert!(!service.is_valid_otp_format("12345"));  // Too short
        assert!(!service.is_valid_otp_format("1234567")); // Too long
        assert!(!service.is_valid_otp_format("12345a"));   // Contains letter
        assert!(!service.is_valid_otp_format(""));         // Empty
        assert!(!service.is_valid_otp_format("12 456"));   // Contains space
    }

    #[test]
    fn test_verify_otp_success() {
        let service = OtpService::new();
        let (otp, salt, hash) = service.generate_otp();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let result = service.verify_otp(&otp, &hash, &salt, timestamp, 0);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_otp_invalid_format() {
        let service = OtpService::new();
        let (_, salt, hash) = service.generate_otp();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let result = service.verify_otp("12345", &hash, &salt, timestamp, 0);
        assert!(result.is_err());
        assert!(matches!(result, Err(PasskeyError::InvalidOtp(_))));
    }

    #[test]
    fn test_verify_otp_expired() {
        let service = OtpService::with_config(1, 5); // 1 second expiry
        let (otp, salt, hash) = service.generate_otp();
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64 - 10; // 10 seconds ago

        let result = service.verify_otp(&otp, &hash, &salt, old_timestamp, 0);
        assert!(result.is_err());
        assert!(matches!(result, Err(PasskeyError::OtpExpired)));
    }

    #[test]
    fn test_verify_otp_max_attempts() {
        let service = OtpService::new();
        let (otp, salt, hash) = service.generate_otp();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let result = service.verify_otp(&otp, &hash, &salt, timestamp, OTP_MAX_ATTEMPTS);
        assert!(result.is_err());
        assert!(matches!(result, Err(PasskeyError::OtpMaxAttemptsExceeded)));
    }

    #[test]
    fn test_verify_otp_wrong_otp() {
        let service = OtpService::new();
        let (_, salt, hash) = service.generate_otp();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let result = service.verify_otp("000000", &hash, &salt, timestamp, 0);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_is_expired() {
        let service = OtpService::with_config(60, 5); // 1 minute expiry
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        // Not expired
        assert!(!service.is_expired(now - 30).unwrap()); // 30 seconds ago
        
        // Expired
        assert!(service.is_expired(now - 120).unwrap()); // 2 minutes ago
    }

    #[test]
    fn test_constant_time_compare() {
        let service = OtpService::new();
        
        assert!(service.constant_time_compare("hello", "hello"));
        assert!(!service.constant_time_compare("hello", "world"));
        assert!(!service.constant_time_compare("hello", "hello!")); // Different lengths
        assert!(!service.constant_time_compare("", "hello"));
    }

    #[test]
    fn test_hex_encode_decode() {
        let data = vec![0x12, 0x34, 0xAB, 0xCD];
        let encoded = hex_encode(&data);
        assert_eq!(encoded, "1234abcd");
        
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_otp_service_default() {
        let service = OtpService::default();
        assert_eq!(service.default_expiry_seconds, OTP_DEFAULT_EXPIRY_SECONDS);
        assert_eq!(service.max_attempts, OTP_MAX_ATTEMPTS);
    }
}