use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use scripty::*;
use shared::{DynamoDbConfig, create_dynamodb_tables};
use std::path::Path;

/// Passkey project automation tool
#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "A task runner for the Passkey project")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize AWS resources and development environment
    Init {
        /// AWS region to deploy to
        #[arg(short, long, default_value = "us-east-1")]
        region: String,
        /// Environment name (dev, staging, prod)
        #[arg(short, long, default_value = "dev")]
        env: String,
    },
    /// Build and deploy Lambda functions
    Deploy {
        /// AWS region to deploy to
        #[arg(short, long, default_value = "us-east-1")]
        region: String,
        /// Environment name (dev, staging, prod)
        #[arg(short, long, default_value = "dev")]
        env: String,
        /// Deploy specific function (authorizer, register, authenticate)
        #[arg(short, long)]
        function: Option<String>,
    },
    /// Run tests
    Test {
        /// Run integration tests
        #[arg(short, long)]
        integration: bool,
        /// Run specific test pattern
        #[arg(short, long)]
        pattern: Option<String>,
    },
    /// Clean build artifacts and temporary files
    Clean {
        /// Also clean AWS resources (dangerous!)
        #[arg(long)]
        aws_resources: bool,
        /// Environment to clean
        #[arg(short, long, default_value = "dev")]
        env: String,
    },
    /// Run pre-commit checks (fmt, check, clippy, test)
    Precommit {
        /// Skip cargo fmt
        #[arg(long)]
        skip_fmt: bool,
        /// Skip cargo clippy
        #[arg(long)]
        skip_clippy: bool,
        /// Skip cargo test
        #[arg(long)]
        skip_test: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Ensure we're in the project root
    if !Path::new("Cargo.toml").exists() {
        anyhow::bail!("Must be run from the project root directory");
    }

    match args.command {
        Command::Init { region, env } => {
            println!("{}", "🚀 Initializing Passkey project...".green().bold());
            init_command(&region, &env).await?;
        }
        Command::Deploy {
            region,
            env,
            function,
        } => {
            println!("{}", "📦 Deploying Lambda functions...".blue().bold());
            deploy_command(&region, &env, function.as_deref()).await?;
        }
        Command::Test {
            integration,
            pattern,
        } => {
            println!("{}", "🧪 Running tests...".yellow().bold());
            test_command(integration, pattern.as_deref())?;
        }
        Command::Clean { aws_resources, env } => {
            println!("{}", "🧹 Cleaning up...".red().bold());
            clean_command(aws_resources, &env).await?;
        }
        Command::Precommit {
            skip_fmt,
            skip_clippy,
            skip_test,
        } => {
            println!("{}", "🔍 Running pre-commit checks...".magenta().bold());
            precommit_command(skip_fmt, skip_clippy, skip_test)?;
        }
    }

    println!("{}", "✅ Task completed successfully!".green().bold());
    Ok(())
}

async fn init_command(region: &str, env: &str) -> Result<()> {
    println!("📋 Checking AWS credentials...");
    check_aws_credentials().await?;

    println!("📋 Checking required tools...");
    check_required_tools()?;

    println!("🏗️  Creating DynamoDB tables...");
    let db_config = DynamoDbConfig::new("passkey", env, region);
    create_dynamodb_tables(&db_config).await?;

    println!("🔑 Creating IAM roles...");
    create_iam_roles(region, env).await?;

    println!("📄 Generating environment configuration...");
    generate_env_config(region, env)?;

    println!("{}", "✨ Initialization complete!".green());
    println!("Next steps:");
    println!("1. Review and update .env.{env}");
    println!("2. Run 'cargo xtask deploy' to deploy Lambda functions");

    Ok(())
}

async fn deploy_command(region: &str, env: &str, function: Option<&str>) -> Result<()> {
    // Check if cargo-lambda is installed
    if cmd!("cargo", "lambda", "--version").run().is_err() {
        println!("{}", "❌ cargo-lambda not found. Installing...".yellow());
        cmd!("cargo", "install", "cargo-lambda")
            .run()
            .context("Failed to install cargo-lambda")?;
    }

    let functions = match function {
        Some(f) => vec![f.to_string()],
        None => vec!["lambda".to_string()],
    };

    for func in &functions {
        println!("🔨 Building {func}...");
        build_lambda_function(func)?;

        println!("🚀 Deploying {func}...");
        deploy_lambda_function(func, region, env).await?;
    }

    println!("🌐 Updating API Gateway...");
    update_api_gateway(region, env).await?;

    Ok(())
}

fn test_command(integration: bool, pattern: Option<&str>) -> Result<()> {
    let mut test_args = vec!["test"];

    if let Some(p) = pattern {
        test_args.push(p);
    }

    if integration {
        test_args.push("--features");
        test_args.push("integration-tests");
    }

    println!("🧪 Running unit tests...");
    let mut test_cmd = cmd!("cargo", "test");
    for arg in &test_args[1..] {
        // Skip the first "test" argument
        test_cmd = test_cmd.arg(arg);
    }
    test_cmd.run().context("Unit tests failed")?;

    if integration {
        println!("🔄 Running integration tests...");
        run_integration_tests()?;
    }

    Ok(())
}

async fn clean_command(aws_resources: bool, env: &str) -> Result<()> {
    println!("🧹 Cleaning build artifacts...");
    cmd!("cargo", "clean")
        .run()
        .context("Failed to clean cargo artifacts")?;

    // Clean lambda build artifacts
    let target_dir = "lambda/target";
    if Path::new(target_dir).exists() {
        std::fs::remove_dir_all(target_dir)
            .with_context(|| format!("Failed to remove {target_dir}"))?;
    }

    // Clean temporary files
    for temp_file in &[".env.tmp", "test-output.json", "coverage.json"] {
        if Path::new(temp_file).exists() {
            std::fs::remove_file(temp_file)
                .with_context(|| format!("Failed to remove {temp_file}"))?;
        }
    }

    if aws_resources {
        println!(
            "{}",
            "⚠️  Cleaning AWS resources (this will delete data!)"
                .red()
                .bold()
        );
        println!("Are you sure? This will delete DynamoDB tables and Lambda functions.");
        println!("Type 'yes' to continue:");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if input.trim().to_lowercase() == "yes" {
            clean_aws_resources(env).await?;
        } else {
            println!("Skipping AWS resource cleanup.");
        }
    }

    Ok(())
}

async fn check_aws_credentials() -> Result<()> {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;
    let sts_client = aws_sdk_sts::Client::new(&config);

    match sts_client.get_caller_identity().send().await {
        Ok(identity) => {
            if let Some(arn) = identity.arn() {
                println!("✅ AWS credentials valid: {arn}");
            }
            Ok(())
        }
        Err(e) => {
            anyhow::bail!("❌ AWS credentials not configured or invalid: {}", e);
        }
    }
}

fn check_required_tools() -> Result<()> {
    let tools = vec![
        ("cargo", "cargo --version"),
        ("cargo-lambda", "cargo lambda --version"),
    ];

    for (tool, command) in tools {
        let parts: Vec<&str> = command.split_whitespace().collect();
        let result = match parts.as_slice() {
            [program] => cmd!(program).run(),
            [program, arg] => cmd!(program, arg).run(),
            [program, arg1, arg2] => cmd!(program, arg1, arg2).run(),
            _ => {
                anyhow::bail!("Command too complex: {}", command);
            }
        };

        match result {
            Ok(_) => println!("✅ {tool} is available"),
            Err(_) => {
                if tool == "cargo-lambda" {
                    println!("⚠️  {tool} not found, will install during deploy");
                } else {
                    anyhow::bail!("❌ {} is required but not found", tool);
                }
            }
        }
    }

    Ok(())
}

async fn create_iam_roles(region: &str, env: &str) -> Result<()> {
    println!("🔑 Creating IAM roles for environment: {env}");

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .load()
        .await;

    let iam_client = aws_sdk_iam::Client::new(&config);

    // Check if Lambda execution role already exists
    let role_name = format!("passkey-lambda-role-{env}");

    match iam_client.get_role().role_name(&role_name).send().await {
        Ok(_) => {
            println!("✅ IAM role {role_name} already exists");
        }
        Err(_) => {
            // Create the role
            let trust_policy = r#"{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}"#;

            iam_client
                .create_role()
                .role_name(&role_name)
                .assume_role_policy_document(trust_policy)
                .description(format!(
                    "Lambda execution role for Passkey service in {env} environment"
                ))
                .send()
                .await
                .with_context(|| format!("Failed to create IAM role {role_name}"))?;

            // Attach necessary policies
            let policies = vec![
                "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
                "arn:aws:iam::aws:policy/AmazonSESFullAccess",
            ];

            for policy_arn in policies {
                iam_client
                    .attach_role_policy()
                    .role_name(&role_name)
                    .policy_arn(policy_arn)
                    .send()
                    .await
                    .with_context(|| format!("Failed to attach policy {policy_arn}"))?;
            }

            println!("✅ Created IAM role: {role_name}");
        }
    }

    Ok(())
}

fn generate_env_config(region: &str, env: &str) -> Result<()> {
    let db_config = DynamoDbConfig::new("passkey", env, region);

    let config_content = format!(
        r#"# Passkey Configuration for environment: {env}
AWS_REGION={region}
ENVIRONMENT={env}

# DynamoDB Configuration
TABLE_PREFIX=passkey
USERS_TABLE={}
CREDENTIALS_TABLE={}
SESSIONS_TABLE={}
PENDING_USERS_TABLE={}
APP_CONFIGS_TABLE={}

# WebAuthn Configuration
RELYING_PARTY_ID=localhost:3000
RELYING_PARTY_NAME="Passkey Demo"
RELYING_PARTY_ORIGIN=http://localhost:3000

# JWT Configuration
JWT_SECRET=your-jwt-secret-change-this-in-production
JWT_EXPIRES_IN=3600

# Lambda Configuration
LAMBDA_TIMEOUT=30
LAMBDA_MEMORY=256
"#,
        db_config.table_name("users"),
        db_config.table_name("credentials"),
        db_config.table_name("sessions"),
        db_config.table_name("pending-users"),
        db_config.table_name("app-configs")
    );

    let config_file = format!(".env.{env}");
    std::fs::write(&config_file, config_content)
        .with_context(|| format!("Failed to write {config_file}"))?;

    println!("✅ Generated configuration: {config_file}");
    Ok(())
}

fn build_lambda_function(function: &str) -> Result<()> {
    if function == "lambda" {
        cmd!("cargo", "lambda", "build", "--release", "--arm64")
            .current_dir(function)
            .run()
            .with_context(|| format!("Failed to build {function}"))?;
    } else {
        anyhow::bail!("Unknown function: {function}. Available: lambda");
    }

    Ok(())
}

async fn deploy_lambda_function(function: &str, region: &str, env: &str) -> Result<()> {
    let function_name = format!("passkey-{function}-{env}");

    if function == "lambda" {
        // Check if IAM role exists, create if needed
        let iam_role = ensure_lambda_role(region, env).await?;

        cmd!("cargo", "lambda", "deploy", "--iam-role", &iam_role)
            .current_dir(function)
            .env("AWS_REGION", region)
            .run()
            .with_context(|| format!("Failed to deploy {function_name}"))?;
    } else {
        anyhow::bail!("Unknown function: {function}. Available: lambda");
    }

    Ok(())
}

async fn update_api_gateway(region: &str, env: &str) -> Result<()> {
    println!("🌐 Setting up API Gateway for {env} environment");

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .load()
        .await;

    let _api_client = aws_sdk_apigateway::Client::new(&config);
    let lambda_client = aws_sdk_lambda::Client::new(&config);

    // Get Lambda function ARN
    let function_name = format!("passkey-lambda-{env}");
    let function_response = lambda_client
        .get_function()
        .function_name(&function_name)
        .send()
        .await
        .with_context(|| format!("Failed to get Lambda function {function_name}"))?;

    let function_arn = function_response
        .configuration()
        .and_then(|c| c.function_arn())
        .ok_or_else(|| anyhow::anyhow!("Lambda function ARN not found"))?;

    println!("✅ Found Lambda function: {function_arn}");
    println!("📝 API Gateway integration will be implemented in next phase");

    Ok(())
}

fn run_integration_tests() -> Result<()> {
    println!("🔄 Running integration tests...");

    // Check if there are any integration test files
    let test_dirs = vec!["lambda/tests", "shared/tests", "tests"];
    let mut found_tests = false;

    for test_dir in test_dirs {
        if Path::new(test_dir).exists() {
            println!("Found integration tests in: {test_dir}");
            found_tests = true;
        }
    }

    if found_tests {
        cmd!("cargo", "test", "--test", "*")
            .run()
            .context("Integration tests failed")?;
        println!("✅ Integration tests completed successfully");
    } else {
        println!(
            "📝 No integration tests found. Create tests in lambda/tests/ or tests/ directory"
        );
    }

    Ok(())
}

async fn clean_aws_resources(env: &str) -> Result<()> {
    println!("🗑️  Cleaning AWS resources for environment: {env}");

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .load()
        .await;

    let dynamodb = aws_sdk_dynamodb::Client::new(&config);
    let lambda_client = aws_sdk_lambda::Client::new(&config);
    let iam_client = aws_sdk_iam::Client::new(&config);

    // Delete DynamoDB tables
    let db_config = DynamoDbConfig::new("passkey", env, "us-east-1");
    let tables = vec![
        "users",
        "credentials",
        "sessions",
        "pending-users",
        "app-configs",
    ];

    for table_type in tables {
        let table_name = db_config.table_name(table_type);
        match dynamodb.delete_table().table_name(&table_name).send().await {
            Ok(_) => println!("✅ Deleted table: {table_name}"),
            Err(e) => {
                if e.to_string().contains("ResourceNotFoundException") {
                    println!("⚠️  Table {table_name} does not exist");
                } else {
                    println!("❌ Failed to delete table {table_name}: {e}");
                }
            }
        }
    }

    // Delete Lambda function
    let function_name = format!("passkey-lambda-{env}");
    match lambda_client
        .delete_function()
        .function_name(&function_name)
        .send()
        .await
    {
        Ok(_) => println!("✅ Deleted Lambda function: {function_name}"),
        Err(e) => {
            if e.to_string().contains("ResourceNotFoundException") {
                println!("⚠️  Lambda function {function_name} does not exist");
            } else {
                println!("❌ Failed to delete Lambda function {function_name}: {e}");
            }
        }
    }

    // Delete IAM role
    let role_name = format!("passkey-lambda-role-{env}");

    // First detach policies
    let policies = vec![
        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        "arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess",
        "arn:aws:iam::aws:policy/AmazonSESFullAccess",
    ];

    for policy_arn in policies {
        let _ = iam_client
            .detach_role_policy()
            .role_name(&role_name)
            .policy_arn(policy_arn)
            .send()
            .await;
    }

    // Then delete role
    match iam_client.delete_role().role_name(&role_name).send().await {
        Ok(_) => println!("✅ Deleted IAM role: {role_name}"),
        Err(e) => {
            if e.to_string().contains("NoSuchEntity") {
                println!("⚠️  IAM role {role_name} does not exist");
            } else {
                println!("❌ Failed to delete IAM role {role_name}: {e}");
            }
        }
    }

    println!("✅ AWS resource cleanup completed");
    Ok(())
}

/// Ensures the Lambda execution role exists and returns its ARN.
async fn ensure_lambda_role(region: &str, env: &str) -> Result<String> {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .load()
        .await;

    let iam_client = aws_sdk_iam::Client::new(&config);
    let sts_client = aws_sdk_sts::Client::new(&config);

    // Get current AWS account ID
    let caller_identity = sts_client.get_caller_identity().send().await?;
    let account_id = caller_identity.account().unwrap_or("123456789012");

    let role_name = format!("passkey-lambda-role-{env}");
    let role_arn = format!("arn:aws:iam::{account_id}:role/{role_name}");

    // Check if role exists
    match iam_client.get_role().role_name(&role_name).send().await {
        Ok(_) => {
            println!("✅ IAM role {role_name} already exists");
            Ok(role_arn)
        }
        Err(_) => {
            println!("🔑 Creating IAM role: {role_name}");
            create_iam_roles(region, env).await?;
            Ok(role_arn)
        }
    }
}

/// Runs pre-commit checks including fmt, check, clippy, and test.
fn precommit_command(skip_fmt: bool, skip_clippy: bool, skip_test: bool) -> Result<()> {
    let mut has_errors = false;

    // 1. Run cargo fmt
    if !skip_fmt {
        println!("🎨 Running cargo fmt...");
        match cmd!("cargo", "fmt", "--all", "--check").run() {
            Ok(_) => println!("✅ Code formatting is correct"),
            Err(_) => {
                println!("❌ Code formatting issues found. Run 'cargo fmt' to fix them.");
                has_errors = true;
            }
        }
    } else {
        println!("⏭️  Skipping cargo fmt");
    }

    // 2. Run cargo check
    println!("🔍 Running cargo check...");
    match cmd!("cargo", "check", "--all-targets", "--all-features").run() {
        Ok(_) => println!("✅ Compilation check passed"),
        Err(_) => {
            println!("❌ Compilation check failed");
            has_errors = true;
        }
    }

    // 3. Run cargo clippy
    if !skip_clippy {
        println!("📎 Running cargo clippy...");
        match cmd!(
            "cargo",
            "clippy",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings"
        )
        .run()
        {
            Ok(_) => println!("✅ Clippy linting passed"),
            Err(_) => {
                println!("❌ Clippy linting failed");
                has_errors = true;
            }
        }
    } else {
        println!("⏭️  Skipping cargo clippy");
    }

    // 4. Run cargo test
    if !skip_test {
        println!("🧪 Running cargo test...");
        match cmd!("cargo", "test", "--all-targets", "--all-features").run() {
            Ok(_) => println!("✅ All tests passed"),
            Err(_) => {
                println!("❌ Tests failed");
                has_errors = true;
            }
        }
    } else {
        println!("⏭️  Skipping cargo test");
    }

    if has_errors {
        anyhow::bail!("Pre-commit checks failed! Please fix the issues above.");
    }

    println!("{}", "🎉 All pre-commit checks passed!".green().bold());
    Ok(())
}
