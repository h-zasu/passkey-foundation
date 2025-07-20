## タスク実行の4段階フロー

### 1. 要件定義
- `.claude_workflow/complete.md`が存在すれば参照
- 目的の明確化、現状把握、成功基準の設定
- `.claude_workflow/requirements.md`に文書化
- **必須確認**: 「要件定義フェーズが完了しました。設計フェーズに進んでよろしいですか？」

### 2. 設計
- **必ず`.claude_workflow/requirements.md`を読み込んでから開始**
- アプローチ検討、実施手順決定、問題点の特定
- `.claude_workflow/design.md`に文書化
- **必須確認**: 「設計フェーズが完了しました。タスク化フェーズに進んでよろしいですか？」

### 3. タスク化
- **必ず`.claude_workflow/design.md`を読み込んでから開始**
- タスクを実行可能な単位に分解、優先順位設定
- `.claude_workflow/tasks.md`に文書化
- **必須確認**: 「タスク化フェーズが完了しました。実行フェーズに進んでよろしいですか？」

### 4. 実行
- **必ず`.claude_workflow/tasks.md`を読み込んでから開始**
- タスクを順次実行、進捗を`.claude_workflow/tasks.md`に更新
- 各タスク完了時に報告

## 実行ルール
### ファイル操作
- 新規タスク開始時: 既存ファイルの**内容を全て削除して白紙から書き直す**
- ファイル編集前に必ず現在の内容を確認

### フェーズ管理
- 各段階開始時: 「前段階のmdファイルを読み込みました」と報告
- 各段階の最後に、期待通りの結果になっているか確認
- 要件定義なしにいきなり実装を始めない

### 実行方針
- 段階的に進める: 一度に全てを変更せず、小さな変更を積み重ねる
- 複数のタスクを同時並行で進めない
- エラーは解決してから次へ進む
- エラーを無視して次のステップに進まない
- 指示にない機能を勝手に追加しない

# Passkey GraphQL認証基盤

## プロジェクト概要

各種アプリケーションが簡単にPasskey認証を導入できる**GraphQL認証基盤サービス**を実装。アプリケーション開発者はWebAuthn/FIDO2の複雑な実装を行うことなく、GraphQL APIを呼び出すだけで最新のパスワードレス認証機能を統合可能。マルチアプリケーション対応で、管理者によるユーザー管理とOTP認証機能を提供。

## 技術スタック

- **言語**: Rust（edition 2024）
- **API**: GraphQL（async-graphql 7.x）
- **アーキテクチャ**: aarch64（AWS Graviton2）
- **ランタイム**: AWS Lambda + lambda_runtime
- **エンドポイント**: API Gateway + カスタムドメイン（HTTPS）
- **データベース**: DynamoDB
- **メール**: AWS SES
- **WebAuthn**: webauthn-rs 0.5.2

## プロジェクト構造

```
passkey/
├── .cargo/config.toml     # Cargoエイリアス設定
├── .claude_workflow/      # 開発ワークフロー文書
├── Cargo.toml            # ワークスペース設定
├── xtask/                # ビルド・デプロイ自動化
├── lambda/               # GraphQL Lambda関数
│   └── src/
│       ├── main.rs       # Lambdaエントリーポイント
│       ├── schema.rs     # GraphQLスキーマ定義
│       ├── resolvers/    # GraphQLリゾルバー
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
- `cargo xtask deploy` - Lambda関数、API Gateway設定デプロイ（aarch64）
- `cargo xtask domain` - カスタムドメイン・TLS証明書設定
- `cargo xtask test` - 統合テスト実行
- `cargo xtask precommit` - プリコミットチェック（fmt、check、clippy、test）
- `cargo xtask clean` - ビルド成果物クリーンアップ

## cargo lambdaコマンド

- `cargo lambda build --release --arm64` - aarch64ビルド
- `cargo lambda deploy --iam-role <role>` - デプロイ
- `cargo lambda invoke --data-file test.json` - ローカルテスト

## 開発ガイドライン

### コードスタイル
- Rust edition 2024使用
- `rustfmt`デフォルト設定
- `thiserror`によるエラーハンドリング
- `tokio`によるAsync/await
- `serde`によるシリアライゼーション

### コード品質管理
#### **必須：コミット前のprecommitチェック**
- **全てのコミット前に必ず`cargo xtask precommit`を実行**
- 全てのエラーと警告を修正してからコミットすること
- 以下のチェックが全て成功する必要あり：
  - `cargo fmt --check` - コードフォーマット
  - `cargo check` - コンパイルチェック
  - `cargo clippy` - Lintチェック（警告をエラー扱い）
  - `cargo test` - 全テスト実行

#### Clippy警告の自動修正
- `cargo clippy --fix --allow-dirty` - 自動修正可能な警告を修正
- clippyが検出する一般的な問題：
  - `uninlined_format_args` - format!内の変数直接使用
  - `unwrap_or_default` - unwrap_or_else(Default::default)の簡略化
  - `map_clone` - .map(|x| x.clone())を.cloned()に
  - `derivable_impls` - 導出可能なDefaultトレイト実装
- 自動修正後は必ず`cargo fmt`でフォーマット調整

#### スキップオプション（緊急時のみ）
- `--skip-fmt` - フォーマットチェックをスキップ
- `--skip-clippy` - clippyチェックをスキップ
- `--skip-test` - テスト実行をスキップ

### 依存関係の管理
#### **必須：パッチバージョンまでの明示**
- **Rustベストプラクティス**: 全ての依存関係でパッチバージョン（major.minor.patch）まで明示
- ❌ 悪い例: `serde = "1.0"`, `tokio = "1"`
- ✅ 良い例: `serde = "1.0.219"`, `tokio = "1.46.1"`
- **理由**: 再現可能なビルドの保証、予期しない破壊的変更の回避

#### cargo-editツールの使用
- `cargo install cargo-edit` - cargo upgradeコマンドを利用可能に
- `cargo upgrade` - 互換性のある依存関係を最新バージョンに自動更新
- `cargo upgrade --incompatible --dry-run` - 非互換バージョンアップの確認
- `cargo search <crate-name>` - 個別クレートの最新バージョン確認

#### 更新手順とベストプラクティス
1. `cargo upgrade` - パッチバージョンまで自動更新
2. 必要に応じて手動でパッチバージョンを明示的に記載
3. `cargo check` - コンパイルエラーがないことを確認
4. `cargo xtask precommit` - 全チェックが通ることを確認
5. 問題があれば元のバージョンに戻すか、コードを修正

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
- 統合テスト（GraphQLリゾルバー）
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
- GraphQL N+1問題対策