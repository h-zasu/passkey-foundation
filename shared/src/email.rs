//! Email service for sending user notifications and invitations.
//!
//! This module provides email functionality for the Passkey authentication system,
//! including user invitations, authentication notifications, and other system emails.
//! It uses AWS SES for reliable email delivery with proper error handling and retry logic.

use crate::{EmailError, PasskeyError};
use aws_sdk_ses::types::{Body, Content, Destination, Message};
use aws_sdk_ses::Client as SesClient;
use time::OffsetDateTime;
use tracing::{error, info, warn};

/// Email service configuration
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// Sender email address (must be verified in SES)
    pub from_email: String,
    /// Reply-to email address
    pub reply_to: Option<String>,
    /// Maximum retry attempts for failed sends
    pub max_retries: u32,
    /// Base retry delay in milliseconds
    pub retry_delay_ms: u64,
    /// Whether to use exponential backoff for retries
    pub exponential_backoff: bool,
}

impl EmailConfig {
    /// Creates a new email configuration.
    pub fn new(from_email: String) -> Self {
        Self {
            from_email,
            reply_to: None,
            max_retries: 3,
            retry_delay_ms: 1000,
            exponential_backoff: true,
        }
    }

    /// Sets the reply-to email address.
    pub fn with_reply_to(mut self, reply_to: String) -> Self {
        self.reply_to = Some(reply_to);
        self
    }

    /// Sets retry configuration.
    pub fn with_retry_config(mut self, max_retries: u32, delay_ms: u64, exponential: bool) -> Self {
        self.max_retries = max_retries;
        self.retry_delay_ms = delay_ms;
        self.exponential_backoff = exponential;
        self
    }
}

/// Email service for sending notifications via AWS SES.
#[derive(Debug, Clone)]
pub struct EmailService {
    /// AWS SES client
    ses_client: SesClient,
    /// Email configuration
    config: EmailConfig,
}

impl EmailService {
    /// Creates a new email service.
    pub fn new(ses_client: SesClient, config: EmailConfig) -> Self {
        Self { ses_client, config }
    }

    /// Sends a user invitation email.
    ///
    /// # Arguments
    ///
    /// * `to_email` - Recipient's email address
    /// * `app_name` - Application name
    /// * `otp` - One-time password for verification
    /// * `expiry_minutes` - How many minutes until OTP expires
    /// * `invited_by` - Email of the person who sent the invitation (optional)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if email was sent successfully, or error details.
    pub async fn send_invitation_email(
        &self,
        to_email: &str,
        app_name: &str,
        otp: &str,
        expiry_minutes: u32,
        invited_by: Option<&str>,
    ) -> Result<(), PasskeyError> {
        let subject = format!("You're invited to {}", app_name);
        
        let html_body = self.build_invitation_html(app_name, otp, expiry_minutes, invited_by);
        let text_body = self.build_invitation_text(app_name, otp, expiry_minutes, invited_by);

        self.send_email_with_retry(to_email, &subject, &text_body, Some(&html_body))
            .await
    }

    /// Sends an authentication completion notification email.
    ///
    /// # Arguments
    ///
    /// * `to_email` - Recipient's email address
    /// * `app_name` - Application name
    /// * `user_display_name` - User's display name
    /// * `ip_address` - IP address from which authentication occurred
    /// * `user_agent` - User agent string from the browser
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if email was sent successfully, or error details.
    pub async fn send_authentication_success_email(
        &self,
        to_email: &str,
        app_name: &str,
        user_display_name: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<(), PasskeyError> {
        let subject = format!("Successful sign-in to {}", app_name);
        
        let html_body = self.build_auth_success_html(
            app_name,
            user_display_name,
            ip_address,
            user_agent,
        );
        let text_body = self.build_auth_success_text(
            app_name,
            user_display_name,
            ip_address,
            user_agent,
        );

        self.send_email_with_retry(to_email, &subject, &text_body, Some(&html_body))
            .await
    }

    /// Sends a security alert email for suspicious activity.
    ///
    /// # Arguments
    ///
    /// * `to_email` - Recipient's email address
    /// * `app_name` - Application name
    /// * `alert_type` - Type of security alert
    /// * `details` - Additional details about the alert
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if email was sent successfully, or error details.
    pub async fn send_security_alert_email(
        &self,
        to_email: &str,
        app_name: &str,
        alert_type: &str,
        details: &str,
    ) -> Result<(), PasskeyError> {
        let subject = format!("Security Alert - {}", app_name);
        
        let html_body = self.build_security_alert_html(app_name, alert_type, details);
        let text_body = self.build_security_alert_text(app_name, alert_type, details);

        self.send_email_with_retry(to_email, &subject, &text_body, Some(&html_body))
            .await
    }

    /// Sends an email with retry logic.
    async fn send_email_with_retry(
        &self,
        to_email: &str,
        subject: &str,
        text_body: &str,
        html_body: Option<&str>,
    ) -> Result<(), PasskeyError> {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match self
                .send_email_once(to_email, subject, text_body, html_body)
                .await
            {
                Ok(()) => {
                    if attempt > 0 {
                        info!(
                            "Email sent successfully on attempt {} to {}",
                            attempt + 1,
                            to_email
                        );
                    }
                    return Ok(());
                }
                Err(error) => {
                    last_error = Some(error);
                    
                    if attempt < self.config.max_retries {
                        let delay = if self.config.exponential_backoff {
                            self.config.retry_delay_ms * 2_u64.pow(attempt)
                        } else {
                            self.config.retry_delay_ms
                        };

                        warn!(
                            "Email send attempt {} failed for {}, retrying in {}ms: {:?}",
                            attempt + 1,
                            to_email,
                            delay,
                            last_error
                        );

                        tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                    } else {
                        error!(
                            "Email send failed after {} attempts for {}: {:?}",
                            self.config.max_retries + 1,
                            to_email,
                            last_error
                        );
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            PasskeyError::EmailService(EmailError::SendFailed)
        }))
    }

    /// Sends an email once (no retry).
    async fn send_email_once(
        &self,
        to_email: &str,
        subject: &str,
        text_body: &str,
        html_body: Option<&str>,
    ) -> Result<(), PasskeyError> {
        // Validate email address format
        if !is_valid_email(to_email) {
            return Err(PasskeyError::EmailService(EmailError::InvalidAddress(
                to_email.to_string(),
            )));
        }

        let destination = Destination::builder()
            .to_addresses(to_email)
            .build();

        let subject_content = Content::builder()
            .data(subject)
            .charset("UTF-8")
            .build()
            .map_err(|e| {
                PasskeyError::EmailService(EmailError::SESError(format!(
                    "Failed to build subject: {e}"
                )))
            })?;

        let text_content = Content::builder()
            .data(text_body)
            .charset("UTF-8")
            .build()
            .map_err(|e| {
                PasskeyError::EmailService(EmailError::SESError(format!(
                    "Failed to build text body: {e}"
                )))
            })?;

        let mut body_builder = Body::builder().text(text_content);

        if let Some(html) = html_body {
            let html_content = Content::builder()
                .data(html)
                .charset("UTF-8")
                .build()
                .map_err(|e| {
                    PasskeyError::EmailService(EmailError::SESError(format!(
                        "Failed to build HTML body: {e}"
                    )))
                })?;
            body_builder = body_builder.html(html_content);
        }

        let body = body_builder.build();

        let message = Message::builder()
            .subject(subject_content)
            .body(body)
            .build();

        let mut send_email_builder = self
            .ses_client
            .send_email()
            .source(&self.config.from_email)
            .destination(destination)
            .message(message);

        if let Some(ref reply_to) = self.config.reply_to {
            send_email_builder = send_email_builder.reply_to_addresses(reply_to);
        }

        send_email_builder.send().await.map_err(|e| {
            PasskeyError::EmailService(EmailError::SESError(format!("SES send error: {e}")))
        })?;

        info!("Email sent successfully to {}", to_email);
        Ok(())
    }

    /// Builds HTML content for invitation email.
    fn build_invitation_html(
        &self,
        app_name: &str,
        otp: &str,
        expiry_minutes: u32,
        invited_by: Option<&str>,
    ) -> String {
        let invited_by_text = if let Some(inviter) = invited_by {
            format!("You have been invited by <strong>{}</strong> to join <strong>{}</strong>.", html_escape(inviter), html_escape(app_name))
        } else {
            format!("You have been invited to join <strong>{}</strong>.", html_escape(app_name))
        };

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Invitation to {app_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .otp {{ font-size: 32px; font-weight: bold; color: #2563eb; text-align: center; margin: 30px 0; padding: 20px; background-color: #f0f9ff; border-radius: 8px; letter-spacing: 4px; }}
        .warning {{ background-color: #fef3c7; padding: 15px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #f59e0b; }}
        .footer {{ margin-top: 30px; font-size: 14px; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 You're Invited!</h1>
        </div>
        
        <p>{invited_by_text}</p>
        
        <p>To complete your registration, please use the following verification code:</p>
        
        <div class="otp">{otp}</div>
        
        <div class="warning">
            <strong>⚠️ Important:</strong> This verification code will expire in {expiry_minutes} minutes. 
            If you didn't expect this invitation, please ignore this email.
        </div>
        
        <p>If you have any questions about this invitation, please contact your administrator.</p>
        
        <div class="footer">
            <p>This is an automated message from {app_name}.</p>
        </div>
    </div>
</body>
</html>"#,
            app_name = html_escape(app_name),
            invited_by_text = invited_by_text,
            otp = html_escape(otp),
            expiry_minutes = expiry_minutes,
        )
    }

    /// Builds text content for invitation email.
    fn build_invitation_text(
        &self,
        app_name: &str,
        otp: &str,
        expiry_minutes: u32,
        invited_by: Option<&str>,
    ) -> String {
        let invited_by_text = if let Some(inviter) = invited_by {
            format!("You have been invited by {} to join {}.", inviter, app_name)
        } else {
            format!("You have been invited to join {}.", app_name)
        };

        format!(
            r#"🔐 You're Invited!

{invited_by_text}

To complete your registration, please use the following verification code:

{otp}

⚠️ IMPORTANT: This verification code will expire in {expiry_minutes} minutes. 
If you didn't expect this invitation, please ignore this email.

If you have any questions about this invitation, please contact your administrator.

---
This is an automated message from {app_name}."#,
            invited_by_text = invited_by_text,
            otp = otp,
            expiry_minutes = expiry_minutes,
            app_name = app_name,
        )
    }

    /// Builds HTML content for authentication success email.
    fn build_auth_success_html(
        &self,
        app_name: &str,
        user_display_name: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> String {
        let now = OffsetDateTime::now_utc();
        let timestamp = format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            now.year(), now.month() as u8, now.day(),
            now.hour(), now.minute(), now.second());

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Successful Sign-in to {app_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .success {{ background-color: #d1fae5; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #10b981; }}
        .details {{ background-color: #f9fafb; padding: 15px; border-radius: 6px; margin: 20px 0; }}
        .footer {{ margin-top: 30px; font-size: 14px; color: #666; text-align: center; }}
        .warning {{ background-color: #fee2e2; padding: 15px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #ef4444; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>✅ Successful Sign-in</h1>
        </div>
        
        <div class="success">
            <h3>Hello {user_display_name}!</h3>
            <p>You have successfully signed in to <strong>{app_name}</strong>.</p>
        </div>
        
        <div class="details">
            <h4>Sign-in Details:</h4>
            <ul>
                <li><strong>Time:</strong> {timestamp}</li>
                <li><strong>IP Address:</strong> {ip_address}</li>
                <li><strong>Browser/Device:</strong> {user_agent}</li>
            </ul>
        </div>
        
        <div class="warning">
            <strong>⚠️ Didn't sign in?</strong> If this wasn't you, please contact your administrator immediately 
            and consider changing your passkey credentials.
        </div>
        
        <div class="footer">
            <p>This is an automated security notification from {app_name}.</p>
        </div>
    </div>
</body>
</html>"#,
            app_name = html_escape(app_name),
            user_display_name = html_escape(user_display_name),
            timestamp = timestamp,
            ip_address = html_escape(ip_address),
            user_agent = html_escape(user_agent),
        )
    }

    /// Builds text content for authentication success email.
    fn build_auth_success_text(
        &self,
        app_name: &str,
        user_display_name: &str,
        ip_address: &str,
        user_agent: &str,
    ) -> String {
        let now = OffsetDateTime::now_utc();
        let timestamp = format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            now.year(), now.month() as u8, now.day(),
            now.hour(), now.minute(), now.second());

        format!(
            r#"✅ Successful Sign-in

Hello {user_display_name}!

You have successfully signed in to {app_name}.

Sign-in Details:
- Time: {timestamp}
- IP Address: {ip_address}
- Browser/Device: {user_agent}

⚠️ DIDN'T SIGN IN? If this wasn't you, please contact your administrator immediately 
and consider changing your passkey credentials.

---
This is an automated security notification from {app_name}."#,
            user_display_name = user_display_name,
            app_name = app_name,
            timestamp = timestamp,
            ip_address = ip_address,
            user_agent = user_agent,
        )
    }

    /// Builds HTML content for security alert email.
    fn build_security_alert_html(
        &self,
        app_name: &str,
        alert_type: &str,
        details: &str,
    ) -> String {
        let now = OffsetDateTime::now_utc();
        let timestamp = format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            now.year(), now.month() as u8, now.day(),
            now.hour(), now.minute(), now.second());

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Alert - {app_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .alert {{ background-color: #fee2e2; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #ef4444; }}
        .details {{ background-color: #f9fafb; padding: 15px; border-radius: 6px; margin: 20px 0; }}
        .footer {{ margin-top: 30px; font-size: 14px; color: #666; text-align: center; }}
        .action {{ background-color: #fef3c7; padding: 15px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #f59e0b; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 Security Alert</h1>
        </div>
        
        <div class="alert">
            <h3>Security Event Detected</h3>
            <p>We detected a security-related event on your <strong>{app_name}</strong> account.</p>
        </div>
        
        <div class="details">
            <h4>Alert Details:</h4>
            <ul>
                <li><strong>Alert Type:</strong> {alert_type}</li>
                <li><strong>Time:</strong> {timestamp}</li>
                <li><strong>Details:</strong> {details}</li>
            </ul>
        </div>
        
        <div class="action">
            <strong>⚠️ Action Required:</strong> Please review this activity and contact your administrator 
            if you believe this may indicate unauthorized access to your account.
        </div>
        
        <div class="footer">
            <p>This is an automated security alert from {app_name}.</p>
        </div>
    </div>
</body>
</html>"#,
            app_name = html_escape(app_name),
            alert_type = html_escape(alert_type),
            timestamp = timestamp,
            details = html_escape(details),
        )
    }

    /// Builds text content for security alert email.
    fn build_security_alert_text(
        &self,
        app_name: &str,
        alert_type: &str,
        details: &str,
    ) -> String {
        let now = OffsetDateTime::now_utc();
        let timestamp = format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
            now.year(), now.month() as u8, now.day(),
            now.hour(), now.minute(), now.second());

        format!(
            r#"🚨 Security Alert

Security Event Detected

We detected a security-related event on your {app_name} account.

Alert Details:
- Alert Type: {alert_type}
- Time: {timestamp}
- Details: {details}

⚠️ ACTION REQUIRED: Please review this activity and contact your administrator 
if you believe this may indicate unauthorized access to your account.

---
This is an automated security alert from {app_name}."#,
            app_name = app_name,
            alert_type = alert_type,
            timestamp = timestamp,
            details = details,
        )
    }
}

/// Validates email address format.
fn is_valid_email(email: &str) -> bool {
    // Basic email validation - in production, consider using a more robust validator
    email.contains('@') && email.contains('.') && email.len() > 5 && !email.starts_with('@') && !email.ends_with('@')
}

/// Escapes HTML characters to prevent injection.
fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_config_new() {
        let config = EmailConfig::new("test@example.com".to_string());
        assert_eq!(config.from_email, "test@example.com");
        assert_eq!(config.reply_to, None);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.retry_delay_ms, 1000);
        assert!(config.exponential_backoff);
    }

    #[test]
    fn test_email_config_with_reply_to() {
        let config = EmailConfig::new("from@example.com".to_string())
            .with_reply_to("reply@example.com".to_string());
        assert_eq!(config.reply_to, Some("reply@example.com".to_string()));
    }

    #[test]
    fn test_email_config_with_retry_config() {
        let config = EmailConfig::new("test@example.com".to_string())
            .with_retry_config(5, 2000, false);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.retry_delay_ms, 2000);
        assert!(!config.exponential_backoff);
    }

    #[test]
    fn test_is_valid_email() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("test.email+tag@domain.co.uk"));
        
        assert!(!is_valid_email("invalid"));
        assert!(!is_valid_email("@example.com"));
        assert!(!is_valid_email("user@"));
        assert!(!is_valid_email("user"));
        assert!(!is_valid_email(""));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("Hello World"), "Hello World");
        assert_eq!(html_escape("Hello & World"), "Hello &amp; World");
        assert_eq!(html_escape("<script>alert('xss')</script>"), "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;");
        assert_eq!(html_escape("Quote: \"Hello\""), "Quote: &quot;Hello&quot;");
        assert_eq!(html_escape("Mixed: <>&\"'"), "Mixed: &lt;&gt;&amp;&quot;&#39;");
    }

    #[tokio::test]
    async fn test_invitation_email_templates() {
        let config = EmailConfig::new("test@example.com".to_string());
        let ses_client = create_mock_ses_client().await;
        let service = EmailService::new(ses_client, config);

        let html = service.build_invitation_html("Test App", "123456", 30, Some("admin@test.com"));
        assert!(html.contains("123456"));
        assert!(html.contains("Test App"));
        assert!(html.contains("30 minutes"));
        assert!(html.contains("admin@test.com"));

        let text = service.build_invitation_text("Test App", "123456", 30, None);
        assert!(text.contains("123456"));
        assert!(text.contains("Test App"));
        assert!(text.contains("30 minutes"));
        assert!(!text.contains("admin@test.com"));
    }

    #[tokio::test]
    async fn test_auth_success_email_templates() {
        let config = EmailConfig::new("test@example.com".to_string());
        let ses_client = create_mock_ses_client().await;
        let service = EmailService::new(ses_client, config);

        let html = service.build_auth_success_html(
            "Test App", 
            "John Doe", 
            "192.168.1.1", 
            "Mozilla/5.0"
        );
        assert!(html.contains("Test App"));
        assert!(html.contains("John Doe"));
        assert!(html.contains("192.168.1.1"));
        assert!(html.contains("Mozilla/5.0"));

        let text = service.build_auth_success_text(
            "Test App", 
            "John Doe", 
            "192.168.1.1", 
            "Mozilla/5.0"
        );
        assert!(text.contains("Test App"));
        assert!(text.contains("John Doe"));
        assert!(text.contains("192.168.1.1"));
        assert!(text.contains("Mozilla/5.0"));
    }

    #[tokio::test]
    async fn test_security_alert_email_templates() {
        let config = EmailConfig::new("test@example.com".to_string());
        let ses_client = create_mock_ses_client().await;
        let service = EmailService::new(ses_client, config);

        let html = service.build_security_alert_html(
            "Test App", 
            "Multiple Failed Login Attempts", 
            "5 failed attempts from IP 10.0.0.1"
        );
        assert!(html.contains("Test App"));
        assert!(html.contains("Multiple Failed Login Attempts"));
        assert!(html.contains("5 failed attempts from IP 10.0.0.1"));

        let text = service.build_security_alert_text(
            "Test App", 
            "Multiple Failed Login Attempts", 
            "5 failed attempts from IP 10.0.0.1"
        );
        assert!(text.contains("Test App"));
        assert!(text.contains("Multiple Failed Login Attempts"));
        assert!(text.contains("5 failed attempts from IP 10.0.0.1"));
    }

    // Helper function to create a mock SES client for testing
    async fn create_mock_ses_client() -> SesClient {
        // In a real test environment, you would use a mock SES client
        // For now, we'll create a client that won't actually send emails
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new("us-east-1"))
            .load()
            .await;
        SesClient::new(&config)
    }
}