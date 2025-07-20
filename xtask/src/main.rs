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
        #[arg(short, long, default_value = "us-west-2")]
        region: String,
        /// Environment name (dev, staging, prod)
        #[arg(short, long, default_value = "dev")]
        env: String,
    },
    /// Build and deploy Lambda functions
    Deploy {
        /// AWS region to deploy to
        #[arg(short, long, default_value = "us-west-2")]
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
        None => vec![
            "authorizer".to_string(),
            "register".to_string(),
            "authenticate".to_string(),
        ],
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
    for func in &["authorizer", "register", "authenticate"] {
        let target_dir = format!("lambdas/{func}/target");
        if Path::new(&target_dir).exists() {
            std::fs::remove_dir_all(&target_dir)
                .with_context(|| format!("Failed to remove {target_dir}"))?;
        }
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

async fn create_iam_roles(_region: &str, env: &str) -> Result<()> {
    // TODO: Implement IAM role creation
    println!("⚠️  IAM role creation not yet implemented for env: {env}");
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
        db_config.table_name("sessions")
    );

    let config_file = format!(".env.{env}");
    std::fs::write(&config_file, config_content)
        .with_context(|| format!("Failed to write {config_file}"))?;

    println!("✅ Generated configuration: {config_file}");
    Ok(())
}

fn build_lambda_function(function: &str) -> Result<()> {
    let function_dir = format!("lambdas/{function}");

    cmd!("cargo", "lambda", "build", "--release", "--arm64")
        .current_dir(&function_dir)
        .run()
        .with_context(|| format!("Failed to build {function}"))?;

    Ok(())
}

async fn deploy_lambda_function(function: &str, region: &str, env: &str) -> Result<()> {
    let function_name = format!("passkey-{function}-{env}");
    let function_dir = format!("lambdas/{function}");

    // TODO: Implement proper IAM role ARN
    let iam_role = format!("arn:aws:iam::123456789012:role/passkey-lambda-role-{env}");

    cmd!("cargo", "lambda", "deploy", "--iam-role", &iam_role)
        .current_dir(&function_dir)
        .env("AWS_REGION", region)
        .run()
        .with_context(|| format!("Failed to deploy {function_name}"))?;

    Ok(())
}

async fn update_api_gateway(_region: &str, _env: &str) -> Result<()> {
    // TODO: Implement API Gateway update
    println!("⚠️  API Gateway update not yet implemented");
    Ok(())
}

fn run_integration_tests() -> Result<()> {
    // TODO: Implement integration tests
    println!("⚠️  Integration tests not yet implemented");
    Ok(())
}

async fn clean_aws_resources(_env: &str) -> Result<()> {
    // TODO: Implement AWS resource cleanup
    println!("⚠️  AWS resource cleanup not yet implemented");
    Ok(())
}
