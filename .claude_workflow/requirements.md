# 要件定義: PasskeyサービスのGraphQL化とユーザー管理機能拡張

## プロジェクト概要

**目的**: 各種アプリケーション（Webサービス、モバイルアプリ、SaaS等）がPasskey認証機能を簡単に導入できる**認証基盤サービス**を構築する。

**価値提案**: アプリケーション開発者は、このPasskeyサービスのGraphQL APIを呼び出すだけで、WebAuthn/FIDO2の複雑な実装を行うことなく、最新のパスワードレス認証機能を自分のアプリケーションに統合できる。

### 主要機能

1. **GraphQL認証基盤**: 各種アプリケーションが利用する型安全なAPI
2. **ユーザー管理機能**: 管理者によるユーザー登録管理
3. **セキュアな登録フロー**: ワンタイムパスワード（OTP）による認証
4. **マルチアプリケーション対応**: app_id分離による複数アプリ対応

### 利用シナリオ例

- **ブログサイト**: GraphQL APIを呼び出してユーザーログイン機能を実装
- **ECサイト**: 購入時の認証にPasskey基盤を利用
- **社内システム**: 管理画面のセキュアログインを簡単に実装
- **SaaSアプリ**: 顧客向けパスワードレス認証を数行のコードで実現

各アプリケーションは自分でWebAuthn仕様を実装する必要がなく、このサービスが提供するGraphQL APIを利用することで、即座に最新のPasskey認証機能を導入できる。

## 技術スタック

### 言語・ランタイム・インフラ
- **言語**: Rust（最新安定版、edition 2024）
- **アーキテクチャ**: aarch64（AWS Graviton2）
- **ランタイム**: `lambda_runtime`クレートを使用したAWS Lambda
- **API Gateway**: カスタムドメイン（例: `auth.example.com`）でHTTPS提供
- **データベース**: DynamoDB（マネージドNoSQL）
- **メール**: AWS SES（Simple Email Service）

### 主要依存関係
```toml
# GraphQL
async-graphql = "7.0"
async-graphql-lambda = "5.0"

# AWS SDK
lambda_runtime = "0.14.2"
aws-sdk-dynamodb = "1.84.0"
aws-sdk-ses = "1.84.0"

# WebAuthn
webauthn-rs = "0.5.2"

# 基本ライブラリ
serde = { version = "1.0.219", features = ["derive"] }
serde_json = "1.0.141"
uuid = { version = "1.17.0", features = ["v4"] }
tokio = { version = "1.46.1", features = ["macros"] }
thiserror = "2.0.12"
time = "0.3"

# 暗号・セキュリティ
base64 = "0.22.1"
sha2 = "0.10"
rand = "0.8"

# xtaskツール
clap = "4.5.41"
scripty = "0.3.3"
```

## システムアーキテクチャ

### 全体構成
```
[各種アプリケーション] 
         ↓ HTTPS GraphQL API
    [API Gateway]
         ↓ カスタムドメイン (auth.example.com)
    [Lambda Function]
         ↓ Passkey GraphQL Service
    [DynamoDB] + [SES]
```

### 主要コンポーネント

1. **API Gateway**
   - カスタムドメイン設定（例: `auth.example.com`）
   - TLS/SSL証明書管理（AWS Certificate Manager）
   - CORS設定とレート制限
   - GraphQLエンドポイント：`POST /graphql`

2. **Lambda Function（Passkey Service）**
   - Rust + async-graphql実装
   - WebAuthn/FIDO2処理
   - JWT発行・検証
   - DynamoDB・SES統合

3. **DynamoDB**
   - ユーザー・認証情報・セッション管理
   - マルチアプリケーションデータ分離
   - TTL自動削除機能

4. **SES（Simple Email Service）**
   - OTP招待メール送信
   - 認証完了通知
   - HTMLテンプレート対応

### API利用例
```bash
# カスタムドメインでのGraphQL API呼び出し
curl -X POST https://auth.example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { inviteUser(appId: \"myapp\", email: \"user@example.com\") { success } }"
  }'
```

### プロジェクト構造
```
passkey-foundation/
├── .cargo/config.toml     # Cargoエイリアスとビルド設定
├── .claude_workflow/      # 開発ワークフロー文書
├── Cargo.toml            # ワークスペース設定
├── README.md             # プロジェクト概要とセットアップ
├── CONTRIBUTING.md       # 開発プロセスと技術詳細
├── xtask/                # ビルドとデプロイメントの自動化
│   ├── Cargo.toml
│   └── src/main.rs
├── lambda/               # GraphQL Lambda関数
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs       # Lambdaエントリーポイント
│       ├── schema.rs     # GraphQLスキーマ定義
│       ├── resolvers/    # GraphQLリゾルバー
│       ├── auth.rs       # JWTと認証ロジック
│       └── errors.rs     # エラーハンドリング
└── shared/               # 共通ユーティリティ
    ├── Cargo.toml
    └── src/
        ├── lib.rs        # モジュールエクスポート
        ├── types.rs      # 共有データ構造
        ├── dynamodb.rs   # データベース操作
        ├── webauthn.rs   # WebAuthn設定
        ├── email.rs      # メール送信機能
        └── otp.rs        # OTP生成・検証
```

## DynamoDBテーブル設計

### 基本テーブル
1. **Users**: user_id (PK), app_id (SK), email, display_name, role, timestamps
2. **Credentials**: credential_id (PK), user_id (SK), public_key, counter, timestamps
3. **Sessions**: session_id (PK), user_id, challenge, expires_at, session_type

### 追加テーブル（ユーザー管理機能）
4. **PendingUsers**: 
   - pending_user_id (PK), app_id (SK)
   - email, invited_at, expires_at, otp_hash, otp_attempts
5. **Admins**:
   - admin_id (PK), app_id (SK)
   - email, role, permissions, created_at
6. **UserRoles**:
   - user_id (PK), app_id (SK)
   - role, permissions, created_at
7. **AppConfigs**:
   - app_id (PK)
   - name, relying_party_id, allowed_origins, jwt_secret, timeouts

## GraphQL API設計

### Schema概要
```graphql
type Query {
  # ユーザー管理
  user(id: ID!): User
  users(appId: String!, first: Int, after: String): UserConnection
  
  # 管理者機能
  pendingUsers(appId: String!): [PendingUser!]!
  appConfig(appId: String!): AppConfig
}

type Mutation {
  # 管理者によるユーザー招待
  inviteUser(appId: String!, email: String!): InviteResult!
  
  # OTP検証・WebAuthn登録開始
  verifyOtpAndStartRegistration(
    appId: String!,
    email: String!, 
    otp: String!,
    displayName: String!
  ): RegistrationChallenge!
  
  # WebAuthn登録完了
  completeRegistration(
    sessionId: String!, 
    credential: PublicKeyCredential!
  ): RegistrationResult!
  
  # WebAuthn認証開始
  startAuthentication(appId: String!, email: String!): AuthenticationChallenge!
  
  # WebAuthn認証完了
  completeAuthentication(
    sessionId: String!, 
    credential: PublicKeyCredential!
  ): AuthenticationResult!
  
  # 管理者機能
  updateUserRole(userId: ID!, appId: String!, role: UserRole!): User!
  deactivateUser(userId: ID!, appId: String!): User!
}

type Subscription {
  # リアルタイム通知（将来拡張）
  userRegistered(appId: String!): User!
}
```

### 主要型定義
```graphql
type User {
  id: ID!
  appId: String!
  email: String!
  displayName: String!
  role: UserRole!
  isActive: Boolean!
  createdAt: DateTime!
  lastLogin: DateTime
}

type PendingUser {
  id: ID!
  appId: String!
  email: String!
  invitedAt: DateTime!
  expiresAt: DateTime!
  attempts: Int!
}

enum UserRole {
  USER
  ADMIN
  SUPER_ADMIN
}

type AuthenticationResult {
  accessToken: String!
  userId: ID!
  expiresIn: Int!
}
```

## OTPによる登録フロー

### 1. 管理者による事前登録
```graphql
mutation InviteUser {
  inviteUser(appId: "myapp", email: "user@example.com") {
    success
    pendingUserId
    message
  }
}
```

### 2. ユーザーによる登録完了
```graphql
# OTP検証とWebAuthn開始
mutation VerifyOTP {
  verifyOtpAndStartRegistration(
    appId: "myapp"
    email: "user@example.com"
    otp: "123456"
    displayName: "John Doe"
  ) {
    sessionId
    publicKeyCredentialCreationOptions
  }
}

# WebAuthn登録完了
mutation CompleteRegistration {
  completeRegistration(
    sessionId: "session-id"
    credential: { /* WebAuthn credential */ }
  ) {
    userId
    success
    message
  }
}
```

### セキュリティ要件
- OTPは6桁数字、有効期限30分
- OTPハッシュ化保存（SHA-256 + ソルト）
- 試行回数制限（5回失敗でロック）
- メール送信履歴・監査ログ

## メール送信機能

### AWS SES統合
- HTMLテンプレート対応
- 送信失敗時のリトライ機能
- 送信履歴の記録

### メール種別
1. **ユーザー招待メール**（OTP付き）
   - 件名: "アカウント登録のご案内"
   - 内容: OTP、有効期限、登録手順
2. **認証完了通知**
   - 件名: "ログイン完了のお知らせ"
   - 内容: ログイン時刻、デバイス情報

## マルチアプリケーション機能

### アプリケーション設定
```rust
AppConfig {
    app_id: "myapp".to_string(),
    name: "My Application".to_string(),
    relying_party_id: "myapp.example.com".to_string(),
    relying_party_name: "My Application".to_string(),
    allowed_origins: vec!["https://myapp.example.com".to_string()],
    jwt_secret: "unique-secret-per-app".to_string(),
    jwt_expires_in: 3600,                    // 1時間
    session_timeout_seconds: 300,            // 5分
    otp_expires_in: 1800,                    // 30分
}
```

### データ分離
- 各アプリケーションのユーザー、認証情報、セッションは完全に分離
- GraphQLクエリではapp_idによるフィルタリング必須
- JWT も app_id でスコープ分離

## xtaskコマンド

### 利用可能なコマンド
```bash
cargo xtask init      # AWSリソース（DynamoDB、API Gateway、Certificate Manager）の初期化
cargo xtask deploy    # ビルド（aarch64）、Lambda関数、API Gateway設定のデプロイ
cargo xtask domain    # カスタムドメイン設定（TLS証明書作成・関連付け）
cargo xtask test      # 統合テストを含むすべてのテスト実行
cargo xtask clean     # ビルド成果物と一時ファイルのクリーンアップ
```

### デプロイ詳細
- **Lambda関数**: `cargo lambda build` + `cargo lambda deploy`
- **API Gateway**: RESTAPIリソース作成、GraphQLエンドポイント設定
- **カスタムドメイン**: Certificate Manager証明書作成、ドメイン関連付け
- **Route 53**: DNS設定（オプション）

### cargo lambdaコマンド
```bash
cargo lambda build --release --arm64    # aarch64アーキテクチャ用ビルド
cargo lambda deploy --iam-role <role>   # AWS Lambdaへのデプロイ
cargo lambda invoke --data-file test.json  # ローカルテスト
```

## セキュリティ考慮事項

### 通信・認証
- すべての通信はHTTPSのみ（API GatewayでTLS終端）
- AWS Certificate Manager管理のTLS証明書（自動更新）
- カスタムドメインでの安全なエンドポイント提供
- 公開鍵はDynamoDBに保存、秘密鍵は送信されません
- 一意のナンスを使用したチャレンジレスポンス認証
- セッションタイムアウトと適切なJWT検証

### データ保護
- DynamoDBの保存時暗号化
- Lambda環境変数の暗号化
- OTPハッシュ化保存
- セキュリティイベントのCloudWatchログ監視

### WebAuthn設定
- Relying Party ID: 環境ごとに設定
- チャレンジタイムアウト: 300秒（5分）
- ユーザー検証: 必須
- 常駐キー: 推奨
- サポートアルゴリズム: ES256、RS256

## 開発ガイドライン

### コードスタイル
- Rust edition 2024の機能と構文を使用
- デフォルト設定で`rustfmt`を使用
- Rustの命名規則に従う
- `thiserror`で明示的なエラーハンドリングを推奨
- `tokio`ランタイムでAsync/awaitを使用

### エラーハンドリング
- カスタムエラー型には`thiserror`を使用
- 失敗可能なすべての関数から`Result<T, E>`を返す
- CloudWatch用に適切にエラーをログ出力
- 内部エラーをクライアントに公開しない

### テスト戦略
- ビジネスロジックの単体テスト
- GraphQLリゾルバーの統合テスト
- ローカルテスト用のDynamoDBモック
- WebAuthnフローのエンドツーエンド検証

## 成功基準

### 機能要件
- [ ] GraphQL APIが正常動作
- [ ] 管理者がユーザーを事前登録可能
- [ ] OTPメールが正常送信
- [ ] ユーザーがOTP入力で登録完了
- [ ] WebAuthn認証が正常動作
- [ ] マルチアプリケーション分離が動作

### 非機能要件
- [ ] レスポンス時間3秒以内
- [ ] 同時接続100ユーザー対応
- [ ] 99.9%のサービス可用性
- [ ] セキュリティベストプラクティス準拠

### 技術要件
- [ ] Rust edition 2024使用
- [ ] async-graphql 7.x使用
- [ ] AWS SES統合
- [ ] DynamoDBテーブル設計完了

## 制約事項

- AWS Lambda制限内での実装
- SES送信制限の考慮
- DynamoDB読み書きキャパシティ制限

## 想定されるリスク

1. **メール配信リスク**: SES設定・配信制限
2. **パフォーマンスリスク**: GraphQL N+1問題
3. **セキュリティリスク**: OTP生成・検証の脆弱性
4. **スケーラビリティリスク**: Lambda同時実行数制限

## 次ステップ

要件定義完了後、設計フェーズでGraphQLスキーマ設計とDynamoDBテーブル設計の詳細化を行う。