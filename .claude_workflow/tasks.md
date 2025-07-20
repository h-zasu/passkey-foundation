# タスク化: Passkey GraphQL認証基盤の実装タスク

## 前段階確認
`.claude_workflow/design.md`を読み込みました。

## タスク分解戦略

設計書に基づき、以下の4つのPhaseで段階的に実装を進める：

1. **Phase 1: 基盤実装** - ワークスペース、共通モジュール、DynamoDB基盤
2. **Phase 2: コア機能実装** - WebAuthn、OTP、メール、JWT
3. **Phase 3: GraphQL API実装** - スキーマ、リゾルバー、Lambda関数
4. **Phase 4: 統合・デプロイ** - xtask完全実装、テスト、AWSデプロイ

## Phase 1: 基盤実装 (Priority: HIGH)

### 1.1 Cargoワークスペース整理
**Status**: 未着手  
**Estimate**: 30分  
**Dependencies**: None  

- [ ] `Cargo.toml` ワークスペース設定更新
  - async-graphql 7.x 追加
  - lambda_runtime 0.14.2 追加
  - webauthn-rs 0.5.2 追加
  - その他必要依存関係追加
- [ ] `lambda/Cargo.toml` 依存関係更新
- [ ] `shared/Cargo.toml` 依存関係更新
- [ ] `xtask/Cargo.toml` 依存関係更新

### 1.2 sharedクレート基盤実装
**Status**: 未着手  
**Estimate**: 2時間  
**Dependencies**: 1.1 完了後  

- [ ] `shared/src/types.rs` 拡張
  - PendingUser 構造体追加
  - AppConfig 構造体拡張
  - SessionType, UserRole 列挙型追加
  - GraphQL対応用のデシリアライザ追加
- [ ] `shared/src/config.rs` 新規作成
  - 環境変数管理
  - AWS SDK設定
  - WebAuthn設定
- [ ] `shared/src/errors.rs` 新規作成
  - PasskeyError エラー型定義
  - thiserror 統合
  - GraphQLエラー変換

### 1.3 DynamoDB操作拡張
**Status**: 未着手  
**Estimate**: 3時間  
**Dependencies**: 1.2 完了後  

- [ ] `shared/src/dynamodb.rs` 拡張
  - PendingUsers テーブル作成関数
  - AppConfigs テーブル作成関数
  - Users/Credentials/Sessions テーブルのapp_id対応
  - GSI設定とTTL設定
- [ ] CRUD操作関数実装
  - create_user, get_user, update_user
  - create_credential, get_credentials_by_user
  - create_session, get_session, update_session
  - create_pending_user, get_pending_user, delete_pending_user
  - get_app_config

### 1.4 基本xtaskコマンド実装
**Status**: 未着手  
**Estimate**: 2時間  
**Dependencies**: 1.3 完了後  

- [ ] `xtask/src/main.rs` 拡張
  - CLI構造定義（init, deploy, domain, test, clean）
  - AWSクライアント初期化
- [ ] initコマンド実装
  - DynamoDBテーブル作成（新テーブル含む）
  - IAMロール作成スケルトン
  - 環境設定ファイル生成
- [ ] cleanコマンド実装

---

## Phase 2: コア機能実装 (Priority: HIGH)

### 2.1 WebAuthn統合
**Status**: 未着手  
**Estimate**: 4時間  
**Dependencies**: Phase 1 完了後  

- [ ] `shared/src/webauthn.rs` 新規作成
  - WebAuthnインスタンス作成関数
  - 登録チャレンジ生成
  - 登録レスポンス検証
  - 認証チャレンジ生成
  - 認証レスポンス検証
- [ ] WebAuthn設定のアプリ毎カスタマイズ
- [ ] エラーハンドリング統合

### 2.2 OTP機能実装
**Status**: 未着手  
**Estimate**: 2時間  
**Dependencies**: Phase 1 完了後  

- [ ] `shared/src/otp.rs` 新規作成
  - 6桁OTP生成関数
  - ランダムソルト生成
  - SHA-256ハッシュ関数
  - OTP検証関数（試行回数制限含む）
- [ ] OTP有効期限管理
- [ ] セキュリティテスト（ブルートフォース対策）

### 2.3 メール送信機能
**Status**: 未着手  
**Estimate**: 3時間  
**Dependencies**: 2.2 完了後  

- [ ] `shared/src/email.rs` 新規作成
  - AWS SESクライアント統合
  - ユーザー招待メールテンプレート
  - 認証完了通知メールテンプレート
  - HTMLメール対応
- [ ] メール送信失敗時のリトライ機構
- [ ] 送信履歴ログ出力

### 2.4 JWT認証システム
**Status**: 未着手  
**Estimate**: 3時間  
**Dependencies**: Phase 1 完了後  

- [ ] `shared/src/jwt.rs` 新規作成
  - JWTクレーム構造体定義
  - JWT生成関数（アプリ固有シークレット）
  - JWT検証関数
  - JWTリフレッシュ機能（オプション）
- [ ] アプリ毎の署名キー管理
- [ ] JWTリボケーション機構（将来拡張）

---

## Phase 3: GraphQL API実装 (Priority: HIGH)

### 3.1 Lambda関数基盤
**Status**: 未着手  
**Estimate**: 2時間  
**Dependencies**: Phase 2 完了後  

- [ ] `lambda/src/main.rs` 書き換え
  - Lambdaエントリーポイント実装
  - AWS SDKクライアント初期化
  - GraphQLコンテキスト作成
  - async-graphql-lambda 統合
- [ ] `lambda/src/context.rs` 新規作成
  - GraphQLContext構造体定義
  - AWSクライアント保持
  - WebAuthnインスタンス管理
  - AppConfigキャッシュ

### 3.2 GraphQLスキーマ定義
**Status**: 未着手  
**Estimate**: 4時間  
**Dependencies**: 3.1 完了後  

- [ ] `lambda/src/schema.rs` 新規作成
  - Query型定義
  - Mutation型定義
  - 入力型定義（Input types）
  - 出力型定義（Output types）
  - 列挙型定義（Enums）
- [ ] カスタムスカラー定義（DateTime, JSON）
- [ ] ページネーション型定義

### 3.3 リゾルバー基盤実装
**Status**: 未着手  
**Estimate**: 2時間  
**Dependencies**: 3.2 完了後  

- [ ] `lambda/src/resolvers/mod.rs` 新規作成
- [ ] `lambda/src/resolvers/query.rs` 新規作成
  - user, users クエリリゾルバー
  - pendingUsers, appConfig クエリリゾルバー
  - session クエリリゾルバー
- [ ] ページネーションロジック
- [ ] DataLoaderパターン基盤（N+1問題対策）

### 3.4 認証フローリゾルバー
**Status**: 未着手  
**Estimate**: 6時間  
**Dependencies**: 3.3 完了後  

- [ ] `lambda/src/resolvers/mutation.rs` 新規作成
- [ ] inviteUser ミューテーション
  - ユーザー招待フロー
  - OTP生成とメール送信
  - PendingUsersテーブル登録
- [ ] verifyOtpAndStartRegistration ミューテーション
  - OTP検証ロジック
  - WebAuthn登録チャレンジ生成
  - セッション作成
- [ ] completeRegistration ミューテーション
  - WebAuthnレスポンス検証
  - ユーザー作成と認証情報保存
  - JWT発行
  - PendingUsers削除

### 3.5 認証フローリゾルバー
**Status**: 未着手  
**Estimate**: 4時間  
**Dependencies**: 3.4 完了後  

- [ ] startAuthentication ミューテーション
  - ユーザー存在確認
  - 登録済み認証情報取得
  - WebAuthn認証チャレンジ生成
  - セッション作成
- [ ] completeAuthentication ミューテーション
  - WebAuthnレスポンス検証
  - カウンター検証・更新
  - JWT発行
  - last_login更新

### 3.6 管理機能リゾルバー
**Status**: 未着手  
**Estimate**: 3時間  
**Dependencies**: 3.5 完了後  

- [ ] updateUser ミューテーション
- [ ] deactivateUser ミューテーション
- [ ] deleteCredential ミューテーション
- [ ] updateCredentialName ミューテーション
- [ ] 管理者権限チェックミドルウェア

### 3.7 エラーハンドリング統合
**Status**: 未着手  
**Estimate**: 2時間  
**Dependencies**: 3.6 完了後  

- [ ] `lambda/src/errors.rs` 更新
  - GraphQLエラー変換実装
  - エラーコード体系化
  - セキュリティ考慮したエラーメッセージ
- [ ] 構造化ログ出力実装（tracing）
- [ ] CloudWatchログ統合

---

## Phase 4: 統合・デプロイ (Priority: MEDIUM)

### 4.1 xtaskデプロイ機能
**Status**: 未着手  
**Estimate**: 4時間  
**Dependencies**: Phase 3 完了後  

- [ ] deployコマンド実装
  - cargo lambda build --release --arm64
  - Lambda関数作成/更新
  - 環境変数設定
  - IAMロールアタッチ
- [ ] API Gateway設定自動化
  - REST API作成
  - GraphQLエンドポイント設定
  - CORS設定
  - Lambda統合設定

### 4.2 カスタムドメイン設定
**Status**: 未着手  
**Estimate**: 3時間  
**Dependencies**: 4.1 完了後  

- [ ] domainコマンド実装
  - ACM証明書作成
  - ドメイン検証自動化
  - API Gatewayカスタムドメイン設定
  - Route 53設定（オプション）

### 4.3 テスト実装
**Status**: 未着手  
**Estimate**: 6時間  
**Dependencies**: Phase 3 完了後  

- [ ] 単体テスト実装
  - sharedクレートの各モジュールテスト
  - WebAuthn処理テスト
  - OTP生成・検証テスト
  - JWT生成・検証テスト
- [ ] 統合テスト実装
  - GraphQLリゾルバーエンドツーエンドテスト
  - DynamoDB Localテスト
  - SESシミュレータテスト
- [ ] testコマンド実装
  - 単体テスト実行
  - 統合テスト実行
  - カバレッジレポート生成

### 4.4 監視・ログ設定
**Status**: 未着手  
**Estimate**: 3時間  
**Dependencies**: 4.1 完了後  

- [ ] CloudWatchメトリクス設定
- [ ] CloudWatchアラーム設定
- [ ] 構造化ログ出力実装
- [ ] セキュリティイベント監視

### 4.5 ドキュメント作成
**Status**: 未着手  
**Estimate**: 2時間  
**Dependencies**: 全機能完了後  

- [ ] APIドキュメント作成（GraphQLスキーマベース）
- [ ] デプロイマニュアル作成
- [ ] クライアント統合ガイド作成
- [ ] トラブルシューティングガイド作成

---

## リスク・ブロッカー分析

### 高リスクタスク
1. **WebAuthn統合 (2.1)**: 新しいライブラリ、複雑な仕様
2. **GraphQLスキーマ設計 (3.2)**: 型安全性、パフォーマンス考慮
3. **AWSデプロイ自動化 (4.1)**: 複数サービス連携の複雑さ

### 依存関係クリティカルパス
1. Phase 1 → Phase 2 → Phase 3 → Phase 4
2. 各Phase内での依存関係に注意
3. WebAuthn統合が全体のボトルネック

### 緩和策
1. **早期プロトタイピング**: WebAuthnの簡単なテストを優先
2. **モジュール化**: 各コンポーネントを独立してテスト可能に
3. **段階リリース**: 基本機能から段階的に機能拡張

## 成功指標

### Phase 1 完了時
- [ ] cargo build が全クレートで成功
- [ ] DynamoDBテーブルが作成される
- [ ] 基本CRUD操作が動作

### Phase 2 完了時
- [ ] WebAuthnチャレンジ生成・検証が動作
- [ ] OTP生成・検証が動作
- [ ] メール送信が成功
- [ ] JWT生成・検証が動作

### Phase 3 完了時
- [ ] GraphQLスキーマがコンパイル
- [ ] 全リゾルバーが実装される
- [ ] Lambda関数がローカルで動作
- [ ] エンドツーエンドの認証フローが動作

### Phase 4 完了時
- [ ] AWSへのデプロイが成功
- [ ] API Gateway経由でGraphQL APIにアクセス可能
- [ ] カスタムドメインでHTTPSアクセス可能
- [ ] 監視・ログが正常動作

## タスク総計

- **総タスク数**: 45タスク
- **総作業時間**: 約63時間
- **クリティカルパス**: Phase 1 → 2 → 3 → 4
- **最初のPhase 1完了目標**: 1週間
- **全体完了目標**: 3-4週間

## 実行ルール

### 段階的実行
1. **Phaseごとの進行**: 前Phaseが完了してから次へ
2. **単一タスク集中**: 複数タスクを同時並行で進めない
3. **エラー優先解決**: エラーを無視して次のステップに進まない
4. **段階的変更**: 一度に全てを変更せず、小さな変更を積み重ねる

### タスク管理
1. **進捗の可視化**: 各タスクのステータスを随時更新
2. **完了確認**: 各タスク完了時に動作確認
3. **ドキュメント更新**: 変更点を適切に記録
4. **次のタスクの前提条件確認**: 依存関係の検証

### 品質管理
1. **Rust edition 2024使用**: 最新の言語機能活用
2. **async/await**: 非同期処理の統一
3. **セキュリティ**: ベストプラクティス遵守
4. **テスト**: 実装と並行してテスト実行

## 次のアクション

**タスク化フェーズが完了しました。実行フェーズに進んでよろしいですか？**

実行フェーズでは、Phase 1から順次タスクを実行し、進捗を `tasks.md` に更新していきます。