# 設計: Passkey GraphQL認証基盤の実装設計

## 前段階確認
`.claude_workflow/requirements.md`を読み込みました。

## アーキテクチャ設計

### 1. 全体アーキテクチャ

#### システム構成
```
[Client Apps] → [API Gateway] → [Lambda] → [DynamoDB]
                                    ↓
                               [AWS SES]
```

#### レイヤー分離
- **API Layer**: GraphQL schema, resolvers
- **Business Logic Layer**: WebAuthn処理, JWT管理, OTP検証
- **Data Access Layer**: DynamoDB操作, SES統合
- **Shared Utilities**: 共通型定義, 設定管理

### 2. プロジェクト構造設計

#### Cargoワークスペース構成
```toml
# Cargo.toml (ワークスペース)
[workspace]
members = ["lambda", "shared", "xtask"]
resolver = "2"

[workspace.dependencies]
# 共通依存関係をワークスペースレベルで管理
async-graphql = "7.0"
lambda_runtime = "0.14.2"
aws-sdk-dynamodb = "1.84.0"
webauthn-rs = "0.5.2"
serde = { version = "1.0.219", features = ["derive"] }
tokio = { version = "1.46.1", features = ["macros"] }
thiserror = "2.0.12"
```

#### モジュール設計
```rust
// lambda/src/
main.rs           // Lambda エントリーポイント
schema.rs         // GraphQL スキーマ定義
auth.rs           // JWT認証ミドルウェア
errors.rs         // エラー型定義

// lambda/src/resolvers/
mod.rs            // リゾルバーモジュール
query.rs          // Query リゾルバー
mutation.rs       // Mutation リゾルバー
subscription.rs   // Subscription リゾルバー

// shared/src/
lib.rs            // 公開API
types.rs          // 共通データ型
config.rs         // 設定管理
dynamodb.rs       // DynamoDB操作
webauthn.rs       // WebAuthn設定
email.rs          // SES統合
otp.rs            // OTP生成・検証
utils.rs          // ユーティリティ関数
```

## データベース設計

### DynamoDBテーブル設計

#### 1. Users テーブル
```rust
#[derive(Serialize, Deserialize)]
struct User {
    user_id: String,          // PK: user_#{uuid}
    app_id: String,          // SK: app_#{app_name}
    email: String,
    display_name: String,
    role: UserRole,
    is_active: bool,
    created_at: String,      // ISO8601
    updated_at: String,
    last_login: Option<String>,
}

// GSI: email-app_id-index (email as PK, app_id as SK)
// GSI: app_id-created_at-index (app_id as PK, created_at as SK)
```

#### 2. Credentials テーブル
```rust
#[derive(Serialize, Deserialize)]
struct Credential {
    credential_id: String,    // PK: cred_#{credential_id}
    user_id: String,         // SK: user_#{uuid}
    public_key: String,      // Base64エンコード済み公開鍵
    counter: u32,
    backup_eligible: bool,
    backup_state: bool,
    created_at: String,
    last_used: Option<String>,
}

// GSI: user_id-created_at-index (user_id as PK, created_at as SK)
```

#### 3. Sessions テーブル
```rust
#[derive(Serialize, Deserialize)]
struct Session {
    session_id: String,      // PK: session_#{uuid}
    user_id: Option<String>, // 登録セッションの場合はNone
    app_id: String,
    session_type: SessionType, // Registration | Authentication
    challenge: String,       // Base64エンコード
    expires_at: u64,        // Unix timestamp
    created_at: String,
}

// TTL設定: expires_at フィールド
```

#### 4. PendingUsers テーブル
```rust
#[derive(Serialize, Deserialize)]
struct PendingUser {
    pending_user_id: String, // PK: pending_#{uuid}
    app_id: String,         // SK: app_#{app_name}
    email: String,
    otp_hash: String,       // SHA-256ハッシュ
    salt: String,           // OTPソルト
    otp_attempts: u32,
    invited_at: String,
    expires_at: u64,        // Unix timestamp (TTL)
}

// GSI: email-app_id-index
// TTL設定: expires_at フィールド
```

#### 5. AppConfigs テーブル
```rust
#[derive(Serialize, Deserialize)]
struct AppConfig {
    app_id: String,         // PK: app_#{app_name}
    name: String,
    relying_party_id: String,
    relying_party_name: String,
    allowed_origins: Vec<String>,
    jwt_secret: String,     // 暗号化保存
    jwt_expires_in: u32,    // 秒
    session_timeout_seconds: u32,
    otp_expires_in: u32,    // 秒
    created_at: String,
    updated_at: String,
}
```

### インデックス戦略
- **Primary Key**: 効率的な単一項目検索
- **Global Secondary Index**: クエリパターンに基づく複合検索
- **TTL**: セッション・OTPの自動削除

## GraphQL API設計

### スキーマアーキテクチャ

#### Context設計
```rust
#[derive(Clone)]
pub struct GraphQLContext {
    pub dynamodb: aws_sdk_dynamodb::Client,
    pub ses: aws_sdk_ses::Client,
    pub webauthn: Arc<webauthn_rs::Webauthn>,
    pub app_configs: Arc<DashMap<String, AppConfig>>,
    pub current_user: Option<AuthenticatedUser>,
}
```

#### エラーハンドリング設計
```rust
#[derive(thiserror::Error, Debug)]
pub enum PasskeyError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Invalid OTP")]
    InvalidOTP,
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(#[from] webauthn_rs::error::WebauthnError),
    
    #[error("Database error")]
    Database(#[from] aws_sdk_dynamodb::Error),
    
    #[error("Email sending failed")]
    EmailFailed(#[from] aws_sdk_ses::Error),
}

impl From<PasskeyError> for async_graphql::Error {
    fn from(err: PasskeyError) -> Self {
        // セキュリティのため内部エラー詳細は非公開
        async_graphql::Error::new(match err {
            PasskeyError::UserNotFound => "User not found",
            PasskeyError::InvalidOTP => "Invalid OTP", 
            PasskeyError::AuthenticationFailed(_) => "Authentication failed",
            _ => "Internal server error",
        })
    }
}
```

### Resolver設計パターン

#### 共通バリデーション
```rust
// すべてのMutationで app_id バリデーション
async fn validate_app_config(
    ctx: &Context<'_>, 
    app_id: &str
) -> Result<AppConfig, PasskeyError> {
    ctx.data::<GraphQLContext>()?
        .app_configs
        .get(app_id)
        .ok_or(PasskeyError::InvalidAppId)
        .map(|config| config.clone())
}
```

#### データローダーパターン
```rust
// N+1問題対策
pub struct UserLoader;

impl Loader<String> for UserLoader {
    type Value = User;
    type Error = PasskeyError;
    
    async fn load(&self, keys: &[String]) -> Result<HashMap<String, User>, Self::Error> {
        // バッチでユーザー情報を取得
    }
}
```

## セキュリティ設計

### 認証・認可アーキテクチャ

#### JWT設計
```rust
#[derive(Serialize, Deserialize)]
struct JWTClaims {
    sub: String,        // user_id
    app_id: String,     // アプリケーションID
    role: UserRole,     // ユーザーロール
    exp: u64,          // 有効期限
    iat: u64,          // 発行時刻
    jti: String,       // JWT ID (revocation用)
}
```

#### OTP設計
```rust
struct OTPGenerator {
    length: usize,      // 6桁
    charset: &'static str, // 数字のみ
    salt_length: usize, // 32バイト
}

impl OTPGenerator {
    fn generate() -> (String, String) {
        // (otp, salt) を返す
    }
    
    fn verify(otp: &str, hash: &str, salt: &str) -> bool {
        // SHA-256での検証
    }
}
```

### WebAuthn設定
```rust
fn create_webauthn_config(app_config: &AppConfig) -> Result<Webauthn, WebauthnError> {
    WebauthnBuilder::new(
        &app_config.relying_party_id,
        &url::Url::parse(&app_config.allowed_origins[0])?
    )?
    .rp_name(&app_config.relying_party_name)
    .build()
}
```

## インフラ設計

### Lambda関数設定
```rust
// main.rs Lambda設定
#[derive(Deserialize)]
struct Config {
    dynamodb_table_prefix: String,
    ses_region: String,
    jwt_secret_key: String,
    cors_origins: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    let config = envy::from_env::<Config>()?;
    
    let aws_config = aws_config::load_from_env().await;
    let dynamodb = aws_sdk_dynamodb::Client::new(&aws_config);
    let ses = aws_sdk_ses::Client::new(&aws_config);
    
    let schema = create_schema(dynamodb, ses).await?;
    
    lambda_runtime::run(service_fn(|event| {
        async_graphql_lambda::run(event, schema.clone())
    })).await
}
```

### API Gateway統合
```yaml
# OpenAPI仕様書 (API Gateway設定用)
openapi: 3.0.0
info:
  title: Passkey GraphQL API
  version: 1.0.0
paths:
  /graphql:
    post:
      summary: GraphQL endpoint
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
      responses:
        '200':
          description: GraphQL response
      x-amazon-apigateway-integration:
        type: aws_proxy
        httpMethod: POST
        uri: arn:aws:lambda:region:account:function:passkey-graphql
```

## xtask実装設計

### コマンド構造
```rust
// xtask/src/main.rs
#[derive(Parser)]
#[command(name = "xtask")]
enum Cli {
    Init {
        #[arg(long)]
        aws_profile: Option<String>,
    },
    Deploy {
        #[arg(long)]
        stage: Option<String>,
    },
    Domain {
        #[arg(long)]
        domain_name: String,
    },
    Test {
        #[arg(long)]
        integration: bool,
    },
    Clean,
}
```

### AWS リソース管理
```rust
struct AWSResourceManager {
    dynamodb: aws_sdk_dynamodb::Client,
    apigateway: aws_sdk_apigateway::Client,
    lambda: aws_sdk_lambda::Client,
    acm: aws_sdk_acm::Client,
}

impl AWSResourceManager {
    async fn create_dynamodb_tables(&self) -> Result<(), Box<dyn std::error::Error>> {
        // DynamoDBテーブル作成
    }
    
    async fn deploy_lambda(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Lambda関数デプロイ
    }
    
    async fn setup_api_gateway(&self) -> Result<(), Box<dyn std::error::Error>> {
        // API Gateway設定
    }
}
```

## 実装手順

### Phase 1: 基盤実装
1. **Cargoワークスペース設定**
   - `Cargo.toml`ワークスペース設定
   - 依存関係の整理

2. **shared クレート実装**
   - 基本型定義 (`types.rs`)
   - 設定管理 (`config.rs`)
   - DynamoDB基本操作 (`dynamodb.rs`)

3. **xtask基本実装**
   - CLI構造実装
   - DynamoDBテーブル作成機能

### Phase 2: コア機能実装
1. **WebAuthn統合**
   - `shared/src/webauthn.rs`実装
   - 登録・認証フロー

2. **OTP機能実装**
   - `shared/src/otp.rs`実装
   - SES統合 (`shared/src/email.rs`)

3. **Lambda基盤**
   - `lambda/src/main.rs`エントリーポイント
   - GraphQLコンテキスト設定

### Phase 3: GraphQL API実装
1. **スキーマ定義**
   - `lambda/src/schema.rs`
   - 基本型定義

2. **Resolver実装**
   - ユーザー管理Mutation
   - 認証フローMutation
   - クエリResolver

### Phase 4: 統合・デプロイ
1. **xtask完全実装**
   - Lambda デプロイ機能
   - API Gateway設定
   - カスタムドメイン設定

2. **テスト実装**
   - 単体テスト
   - 統合テスト

## 技術的課題と解決策

### 1. Lambda Cold Start対策
**課題**: Lambda初回実行時の遅延
**解決策**:
- 依存関係の最小化
- AWS SDKクライアントの再利用
- Provisioned Concurrency（必要に応じて）

### 2. GraphQL N+1問題
**課題**: 関連データの非効率な取得
**解決策**:
- DataLoaderパターン実装
- DynamoDBバッチ取得API活用
- 適切なGSI設計

### 3. DynamoDB設計最適化
**課題**: アクセスパターンの効率化
**解決策**:
- Single Table Design適用検討
- TTL機能でのデータライフサイクル管理
- Read/Write Capacity適切な設定

### 4. セキュリティ強化
**課題**: 多層防御の実装
**解決策**:
- Lambda環境変数暗号化
- VPC内Lambda配置（必要に応じて）
- CloudWatch監視とアラート

## パフォーマンス設計

### 応答時間目標
- GraphQL Query: < 500ms
- GraphQL Mutation: < 1000ms
- WebAuthn Challenge生成: < 200ms

### スケーラビリティ
- Lambda同時実行: 100~1000
- DynamoDB読み書き: Auto Scaling
- API Gateway制限: 10,000 req/sec

## 監視・ログ設計

### CloudWatchメトリクス
- Lambda実行時間、エラー率
- DynamoDBスロットリング
- API Gatewayレスポンス時間

### 構造化ログ
```rust
use tracing::{info, error, instrument};

#[instrument]
async fn complete_authentication(
    session_id: String,
    credential: PublicKeyCredential
) -> Result<AuthenticationResult, PasskeyError> {
    info!("Starting authentication completion");
    // 実装
}
```

設計フェーズが完了しました。タスク化フェーズに進んでよろしいですか？