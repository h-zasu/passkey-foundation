# Passkey Foundation

## プロジェクト概要

各種アプリケーションが簡単にPasskey認証を導入できる**API認証基盤サービス**を実装。アプリケーション開発者はWebAuthn/FIDO2の複雑な実装を行うことなく、APIを呼び出すだけで最新のパスワードレス認証機能を統合可能。マルチアプリケーション対応で、管理者によるユーザー管理とOTP認証機能を提供。

初期段階ではGraphQL APIを提供し、将来的にはREST APIの実装も検討される可能性があります。

## 技術スタック

- **言語**: Rust（edition 2024）
- **API**: GraphQL（async-graphql 7.x）
  - *初期実装、将来REST API対応検討*
- **アーキテクチャ**: aarch64/x86_64両対応（AWS Graviton2/Intel）
- **ランタイム**: AWS Lambda + lambda_runtime
- **エンドポイント**: API Gateway + カスタムドメイン（HTTPS）
- **データベース**: DynamoDB
- **メール**: AWS SES
- **WebAuthn**: webauthn-rs 0.5.2

## プロジェクト構造

```
passkey-foundation/
├── .cargo/config.toml     # Cargoエイリアス設定
├── .claude_workflow/      # 開発ワークフロー文書
├── Cargo.toml            # ワークスペース設定
├── xtask/                # ビルド・デプロイ自動化
├── lambda/               # API Lambda関数
│   └── src/
│       ├── main.rs       # Lambdaエントリーポイント
│       ├── schema.rs     # APIスキーマ定義
│       ├── resolvers/    # APIリゾルバー
│       ├── auth.rs       # JWT認証ロジック
│       └── errors.rs     # エラーハンドリング
└── shared/               # 共通ユーティリティ
    └── src/
        ├── lib.rs        # モジュールエクスポート
        ├── types.rs      # 共有データ構造
        ├── dynamodb.rs   # データベース操作
        ├── webauthn.rs   # WebAuthn設定
        ├── email.rs      # メール送信機能
        └── otp.rs        # OTP生成・検証
```

## xtaskコマンド

```toml
[alias]
xtask = "run --package xtask --"
```

利用可能なコマンド：
- `cargo xtask init` - AWSリソース初期化（DynamoDB、API Gateway、ACM）
- `cargo xtask deploy` - Lambda関数、API Gateway設定デプロイ（マルチアーキテクチャ）
- `cargo xtask domain` - カスタムドメイン・TLS証明書設定
- `cargo xtask test` - 統合テスト実行
- `cargo xtask precommit` - プリコミットチェック（fmt、check、clippy、test）
- `cargo xtask clean` - ビルド成果物クリーンアップ

## cargo lambdaコマンド

- `cargo lambda build --release --arm64` - aarch64ビルド
- `cargo lambda build --release --x86-64` - x86_64ビルド
- `cargo lambda deploy --iam-role <role>` - デプロイ
- `cargo lambda invoke --data-file test.json` - ローカルテスト

## 開発ガイドライン

### コードスタイル
- Rust edition 2024使用
- `rustfmt`デフォルト設定
- `thiserror`によるエラーハンドリング
- `tokio`によるAsync/await
- `serde`によるシリアライゼーション

### ドキュメント参照
- [async-graphql](https://docs.rs/async-graphql)
- [lambda_runtime](https://docs.rs/lambda_runtime)
- [aws-sdk-dynamodb](https://docs.rs/aws-sdk-dynamodb)
- [webauthn-rs](https://docs.rs/webauthn-rs)
- [tokio](https://docs.rs/tokio)

### エラーハンドリング
- `Result<T, E>`を返す
- CloudWatchログ出力
- 内部エラー非公開

### テスト戦略
- 単体テスト（ビジネスロジック）
- 統合テスト（APIリゾルバー）
- DynamoDBモック
- WebAuthnエンドツーエンド検証

## セキュリティ考慮事項

- HTTPS通信のみ
- 公開鍵のみDynamoDB保存
- チャレンジレスポンス認証
- JWT検証
- DynamoDB暗号化
- Lambda環境変数暗号化
- OTPハッシュ化保存
- CloudWatchログ監視

## WebAuthn設定

- Relying Party ID: 環境ごと設定
- チャレンジタイムアウト: 300秒
- ユーザー検証: 必須
- 常駐キー: 推奨
- アルゴリズム: ES256、RS256

## パフォーマンス考慮事項

- DynamoDBキャパシティ計画
- Lambdaコールドスタート最適化
- AWSクライアント接続プーリング
- 効率的JSONシリアライゼーション
- API N+1問題対策

## 貢献ガイド

プロジェクトへの貢献方法については、[CONTRIBUTING.md](./CONTRIBUTING.md)を参照してください。
