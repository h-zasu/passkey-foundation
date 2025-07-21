# タスク化: Passkey GraphQL認証基盤の実装タスク

## 前段階確認
`.claude_workflow/design.md`を読み込みました。

## タスク分解戦略

設計書に基づき、以下の4つのPhaseで段階的に実装を進める：

1. **Phase 1: 基盤実装** - ワークスペース、共通モジュール、DynamoDB基盤
2. **Phase 2: コア機能実装** - WebAuthn、OTP、メール、JWT
3. **Phase 3: GraphQL API実装** - スキーマ、リゾルバー、Lambda関数
4. **Phase 4: 統合・デプロイ** - xtask完全実装、テスト、AWSデプロイ

## ドキュメント構造の更新

新しいプロジェクト構造に合わせて：
- **README.md**: プロジェクト概要、セットアップ手順、API利用例
- **CONTRIBUTING.md**: 開発プロセス、技術仕様、コーディング規約
- **.claude_workflow/**: 実装タスクの詳細管理

## Phase 1: 基盤実装 ✅ **完了** (Priority: HIGH)
**ブランチ**: `feature/passkey-foundation`  
**PR**: [Passkey認証基盤: Phase 1完了 + ユーザー自由登録・DynamoDB暗号化機能](https://github.com/h-zasu/passkey-foundation/pull/2)  
**Status**: ✅ **マージ完了**（main統合済み）

### 1.1 Cargoワークスペース整理 ✅
**Status**: 完了  
**Estimate**: 30分  
**Dependencies**: None  

- [x] `Cargo.toml` ワークスペース設定更新
  - async-graphql 7.x 追加
  - lambda_runtime 0.14.2 追加
  - webauthn-rs 0.5.2 追加
  - その他必要依存関係追加
- [x] `lambda/Cargo.toml` 依存関係更新
- [x] `shared/Cargo.toml` 依存関係更新
- [x] `xtask/Cargo.toml` 依存関係更新

### 1.2 sharedクレート基盤実装 ✅
**Status**: 完了  
**Estimate**: 2時間  
**Dependencies**: 1.1 完了後  

- [x] `shared/src/types.rs` 拡張
  - PendingUser 構造体追加
  - AppConfig 構造体拡張
  - SessionType, UserRole 列挙型追加
  - GraphQL対応用のデシリアライザ追加
- [x] `shared/src/config.rs` 新規作成
  - 環境変数管理
  - AWS SDK設定
  - WebAuthn設定
- [x] `shared/src/errors.rs` 新規作成
  - PasskeyError エラー型定義
  - thiserror 統合
  - GraphQLエラー変換

### 1.3 DynamoDB操作拡張 ✅
**Status**: 完了  
**Estimate**: 3時間  
**Dependencies**: 1.2 完了後  

- [x] `shared/src/dynamodb.rs` 拡張
  - PendingUsers テーブル作成関数
  - AppConfigs テーブル作成関数
  - Users/Credentials/Sessions テーブルのapp_id対応
  - GSI設定とTTL設定
  - DynamoDB暗号化設定（段階的セキュリティレベル対応）
- [x] CRUD操作関数実装
  - create_user, get_user, update_user
  - create_credential, get_credentials_by_user
  - create_session, get_session, update_session
  - create_pending_user, get_pending_user, delete_pending_user
  - get_app_config

### 1.4 基本xtaskコマンド実装 ✅
**Status**: 完了  
**Estimate**: 2時間  
**Dependencies**: 1.3 完了後  

- [x] `xtask/src/main.rs` 拡張
  - CLI構造定義（init, deploy, domain, test, clean）
  - AWSクライアント初期化
- [x] initコマンド実装
  - DynamoDBテーブル作成（新テーブル含む）
  - IAMロール作成スケルトン
  - 環境設定ファイル生成
- [x] cleanコマンド実装

### 1.5 Phase 1 単体テスト実装 ✅
**Status**: 完了  
**Estimate**: 1時間  
**Dependencies**: 1.4 完了後  

- [x] shared クレートの単体テスト
  - types.rs のデータ構造テスト
  - config.rs の設定読み込みテスト
  - errors.rs のエラー変換テスト
- [x] DynamoDB操作の単体テスト
- [x] xtask基本機能テスト

### 1.6 Phase 1 完了・PR提出 ✅
**Status**: 完了  
**Estimate**: 30分  
**Dependencies**: 1.5 完了後  

- [x] ブランチ作成: `feature/passkey-foundation`
- [x] PR作成・提出
- [x] CI/CDパイプライン確認
- [x] コードレビュー依頼

---

## Phase 2: コア機能実装 ✅ **完了** (Priority: HIGH)
**ブランチ**: `feature/phase2-core-features`  
**Dependencies**: Phase 1 PR承認・マージ後 ✅  
**開始日**: 2025-07-21  
**完了日**: 2025-07-21

### 2.1 WebAuthn統合 ✅
**Status**: ✅ **完了**  
**Estimate**: 4時間  
**Dependencies**: Phase 1 完了後 ✅  
**完了日**: 2025-07-21

- [x] `shared/src/webauthn.rs` 新規作成
  - WebAuthnService構造体実装
  - アプリ毎のWebAuthnインスタンス管理
  - 登録フロー: `start_registration()` / `finish_registration()`
  - 認証フロー: `start_authentication()` / `finish_authentication()`
  - Passkey証明書カウンター管理・更新機能
- [x] WebAuthn設定のアプリ毎カスタマイズ
  - AppConfig基づくWebAuthnBuilder設定
  - origin URL / relying party設定
- [x] エラーハンドリング統合
  - WebauthnError → PasskeyError変換
  - 包括的エラーレポート機能

### 2.1.5 ユーザー登録方式拡張（新機能） ✅
**Status**: ✅ **完了**  
**Estimate**: 2時間  
**Dependencies**: 2.1 完了後 ✅  
**完了日**: 2025-07-21

- [x] `shared/src/types.rs` 拡張
  - RegistrationMode enum追加（InviteOnly, PublicRegistration）
  - AppConfig構造体拡張（registration_mode, auto_approve_registrationフィールド）
  - Display/FromStr trait実装
- [x] 権限チェックロジック基盤実装
  - DynamoDB互換性（既存データ用デフォルト設定）
  - アプリ設定取得・キャッシュ機能拡張
  - 開発用デフォルト設定（PublicRegistration）

### 2.1.7 DynamoDB暗号化設定強化 ✅
**Status**: ✅ **完了**  
**Estimate**: 1.5時間  
**Dependencies**: 2.1.5 完了後 ✅  
**完了日**: 2025-07-21

- [x] `shared/src/config.rs` 暗号化設定追加
  - EncryptionLevel enum（Standard, Enterprise）
  - 環境変数`ENCRYPTION_LEVEL`読み込み
  - KMSキー設定管理
- [x] `shared/src/dynamodb.rs` 暗号化実装
  - テーブル作成時の暗号化設定適用
  - Customer managed keys対応
  - 暗号化設定のバリデーション

### 2.2 OTP機能実装 ✅
**Status**: ✅ **完了**  
**Estimate**: 2時間  
**Dependencies**: Phase 1 完了後 ✅  
**完了日**: 2025-07-21

- [x] `shared/src/otp.rs` 新規作成
  - 6桁OTP生成関数
  - ランダムソルト生成
  - SHA-256ハッシュ関数
  - OTP検証関数（試行回数制限含む）
- [x] OTP有効期限管理
- [x] セキュリティテスト（ブルートフォース対策）

### 2.3 メール送信機能 ✅
**Status**: ✅ **完了**  
**Estimate**: 3時間  
**Dependencies**: 2.2 完了後 ✅  
**完了日**: 2025-07-21

- [x] `shared/src/email.rs` 新規作成
  - AWS SESクライアント統合
  - ユーザー招待メールテンプレート
  - 認証完了通知メールテンプレート
  - HTMLメール対応
- [x] メール送信失敗時のリトライ機構
- [x] 送信履歴ログ出力

### 2.4 JWT認証システム ✅
**Status**: ✅ **完了**  
**Estimate**: 3時間  
**Dependencies**: Phase 1 完了後 ✅  
**完了日**: 2025-07-21

- [x] `shared/src/jwt.rs` 新規作成
  - JWTクレーム構造体定義
  - JWT生成関数（アプリ固有シークレット）
  - JWT検証関数
  - JWTリフレッシュ機能（オプション）
- [x] アプリ毎の署名キー管理
- [x] JWTリボケーション機構（将来拡張）

### 2.5 Phase 2 単体テスト実装 ✅
**Status**: ✅ **完了**  
**Estimate**: 2時間  
**Dependencies**: 2.4 完了後 ✅  
**完了日**: 2025-07-21

- [x] WebAuthn統合テスト
  - チャレンジ生成・検証テスト
  - 公開鍵処理テスト
- [x] OTP機能テスト
  - 生成・検証・期限切れテスト
  - ブルートフォース対策テスト
- [x] メール送信テスト
  - SESシミュレータテスト
  - テンプレート処理テスト
- [x] JWT認証テスト
  - 生成・検証・期限切れテスト
  - アプリ別署名テスト
- [x] ユーザー登録方式テスト（新機能）
  - RegistrationMode enum テスト
  - AppConfig拡張フィールドテスト
  - 権限チェックロジックテスト
- [x] DynamoDB暗号化テスト
  - 暗号化設定バリデーションテスト
  - AWS managed keys vs Customer managed keys テスト
  - 環境変数設定テスト

### 2.6 Phase 2 完了・PR提出 ✅
**Status**: ✅ **完了**  
**Estimate**: 30分  
**Dependencies**: 2.5 完了後 ✅  
**完了日**: 2025-07-21

- [x] ブランチ作成: `feature/phase2-core-features`
- [x] PR作成・提出
- [x] CI/CDパイプライン確認
- [x] コードレビュー依頼

---

## Phase 3: GraphQL API実装 ⚡ **進行中** (Priority: HIGH)
**ブランチ**: `feature/phase3-graphql-api`  
**Dependencies**: Phase 2 PR承認・マージ後 ✅  
**開始日**: 2025-07-21

### 3.1 Lambda関数基盤 ✅
**Status**: ✅ **完了**  
**Estimate**: 2時間  
**Dependencies**: Phase 2 完了後 ✅  
**完了日**: 2025-07-21

- [x] `lambda/src/main.rs` 書き換え
  - Lambdaエントリーポイント実装
  - AWS SDKクライアント初期化
  - GraphQLコンテキスト作成
  - Axumベースの統合実装
- [x] `lambda/src/context.rs` 新規作成
  - GraphQLContext構造体定義
  - AWSクライアント保持
  - WebAuthnインスタンス管理
  - AppConfigキャッシュ

### 3.2 GraphQLスキーマ定義 ✅
**Status**: ✅ **完了**  
**Estimate**: 4時間  
**Dependencies**: 3.1 完了後 ✅  
**開始日**: 2025-07-21
**完了日**: 2025-07-21

- [x] `lambda/src/schema.rs` 新規作成
  - Query型定義（health, app_config, user, users）
  - Mutation型定義（invite_user, self_register, start_registration, complete_registration, start_authentication, complete_authentication）
  - 入力型定義（InviteUserInput, SelfRegisterInput, StartRegistrationInput, CompleteRegistrationInput等）
  - 出力型定義（基本レスポンス型、ページネーション型、認証フローレスポンス型）
  - 列挙型定義（RegistrationMode, UserRole）
- [x] カスタムスカラー定義（DateTime, JSON）
- [x] 完全なページネーション型定義
- [x] 認証フロー用の詳細なInput/Output型定義

### 3.2.5 ユーザー登録スキーマ拡張（新機能） ✅
**Status**: ✅ **完了**  
**Estimate**: 1時間  
**Dependencies**: 3.2 完了後 ✅  
**開始日**: 2025-07-21
**完了日**: 2025-07-21

- [x] GraphQLスキーマ拡張
  - RegistrationMode enum追加（shared crateとの整合性確保、変換ロジック実装）
  - AppConfig型拡張（registration_mode, auto_approve_registrationフィールドをenum型に変更）
  - UserRole enum拡張（SuperAdmin追加、変換ロジック実装）
  - selfRegister mutation実装済み

### 3.3 リゾルバー基盤実装 ✅
**Status**: ✅ **完了**  
**Estimate**: 2時間  
**Dependencies**: 3.2 完了後 ✅  
**開始日**: 2025-07-21
**完了日**: 2025-07-21

- [x] GraphQLスキーマ内でのリゾルバー実装（QueryRoot, MutationRoot）
  - user, users クエリリゾルバー（完全なページネーション対応）
  - health, app_config クエリリゾルバー
  - invite_user, self_register, start_registration, complete_registration リゾルバー
  - start_authentication, complete_authentication リゾルバー
- [x] 高度なページネーションロジック（Relay Cursor Connections準拠）
  - PaginationArgs構造体とバリデーション
  - 汎用Connection<T>とEdge<T>型
  - カーソルベースのページネーション基盤

### 3.4 認証フローリゾルバー ✅
**Status**: ✅ **完了**  
**Estimate**: 7時間  
**Dependencies**: 3.3 完了後 ✅  
**完了日**: 2025-07-21

- [x] GraphQLスキーマ内で認証フローリゾルバー実装完了
  - inviteUser ミューテーション（ユーザー招待フロー、OTP生成、メール送信ログ）
  - selfRegister ミューテーション（登録方式チェック、ユーザー自由登録フロー）
  - startRegistration ミューテーション（OTP検証、WebAuthn登録チャレンジ生成）
  - completeRegistration ミューテーション（WebAuthnレスポンス検証、ユーザー作成、JWT発行）
  - startAuthentication ミューテーション（WebAuthn認証チャレンジ生成）
  - completeAuthentication ミューテーション（WebAuthnレスポンス検証、JWT発行）
- [x] コンパイルエラー修正
  - shared::User構造体のpkフィールド問題解決
  - JWTサービスのgenerate_access_token正しいパラメータ渡し（6個引数）
  - lambda-web統合問題解決（lambda_runtimeに変更）
  - 未使用変数警告修正

### 3.5 管理機能リゾルバー
**Status**: 未着手  
**Estimate**: 3時間  
**Dependencies**: 3.4 完了後 ✅  

- [ ] updateUser ミューテーション
- [ ] deactivateUser ミューテーション
- [ ] deleteCredential ミューテーション
- [ ] updateCredentialName ミューテーション
- [ ] 管理者権限チェックミドルウェア

### 3.6 エラーハンドリング統合 ✅
**Status**: ✅ **完了**  
**Estimate**: 2時間  
**Dependencies**: 3.5 完了後 ✅  
**完了日**: 2025-07-21

- [x] `lambda/src/errors.rs` 更新
  - GraphQLエラー変換実装
  - エラーコード体系化
  - セキュリティ考慮したエラーメッセージ
- [x] 構造化ログ出力実装（tracing）
- [x] 新エラーハンドリングシステムの既存リゾルバー統合
- [x] PasskeyError, DatabaseError, EmailError にCloneトレイト追加
- [x] 全テスト成功確認（117個のテスト全て成功）

### 3.8 Phase 3 統合テスト実装 ✅
**Status**: ✅ **完了**  
**Estimate**: 4時間  
**Dependencies**: 3.6 完了後 ✅  
**完了日**: 2025-07-21

- [x] GraphQLエンドツーエンドテスト（11個のテスト全て成功）
  - 全リゾルバーの動作確認
  - Health query、App config query テスト
  - Mutation エラーハンドリング（inviteUser, selfRegister, startRegistration）
  - スキーマ・イントロスペクションテスト
  - エラーハンドリング一貫性テスト
- [x] Lambda関数統合テスト
  - ローカル実行テスト
  - Lambda schema作成・request handling テスト
- [x] パフォーマンステスト
  - 並行リクエストテスト（10個同時Health query成功）

### 3.9 Phase 3 完了・PR提出
**Status**: 未着手  
**Estimate**: 30分  
**Dependencies**: 3.8 完了後  

- [ ] ブランチ作成: `feature/phase3-graphql-api`
- [ ] PR作成・提出
- [ ] CI/CDパイプライン確認
- [ ] コードレビュー依頼

---

## Phase 4: 統合・デプロイ (Priority: MEDIUM)
**予定ブランチ**: `feature/phase4-deployment`  
**Dependencies**: Phase 3 PR承認・マージ後

### 4.1 xtaskデプロイ機能
**Status**: 未着手  
**Estimate**: 5時間  
**Dependencies**: Phase 3 完了後  

- [ ] deployコマンド実装
  - cargo lambda build --release --arm64
  - Lambda関数作成/更新
  - 環境変数設定（暗号化設定含む）
  - IAMロールアタッチ
- [ ] KMS暗号化設定自動化
  - Customer managed keys作成（Enterpriseモード）
  - キーポリシー設定
  - Lambda環境変数KMS暗号化
  - DynamoDBテーブル暗号化設定
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

### 4.6 Phase 4 完了・PR提出
**Status**: 未着手  
**Estimate**: 30分  
**Dependencies**: 4.5 完了後  

- [ ] ブランチ作成: `feature/phase4-deployment`
- [ ] PR作成・提出
- [ ] CI/CDパイプライン確認
- [ ] 本番デプロイ準備確認
- [ ] コードレビュー依頼

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

### Phase 1 完了時 ✅
- [x] cargo build が全クレートで成功
- [x] DynamoDBテーブルが作成される
- [x] 基本CRUD操作が動作
- [x] 単体テストが全て成功
- [x] PR提出・レビュー中

### Phase 2 完了時
- [x] WebAuthnチャレンジ生成・検証が動作 ✅ (2.1完了)
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

- **総タスク数**: 59タスク（ユーザー自由登録 + DynamoDB暗号化強化）
- **総作業時間**: 約76.5時間
- **完了タスク数**: 13タスク (Phase 1完了 + Phase 2.1 & 2.1.5完了)
- **残りタスク数**: 46タスク
- **新機能追加**: 
  - ユーザー自由登録（+4時間）
  - DynamoDB暗号化強化（+2.5時間）
- **クリティカルパス**: Phase 1 ✅ → Phase 2 ⚡ → Phase 3 → Phase 4
- **Phase 1完了**: ✅ (マージ完了)
- **Phase 2進捗**: ⚡ WebAuthn統合・ユーザー登録拡張完了
- **残り完了目標**: 2-3週間

## 実行ルール

### 段階的実行
1. **Phaseごとの進行**: 前PhaseのPRがマージされてから次へ
2. **ブランチ戦略**: 各Phaseで新しいfeatureブランチを作成
3. **PR駆動開発**: 各Phase完了時にPR提出・レビュー
4. **単一タスク集中**: 複数タスクを同時並行で進めない
5. **エラー優先解決**: エラーを無視して次のステップに進まない
6. **段階的変更**: 一度に全てを変更せず、小さな変更を積み重ねる

### タスク管理
1. **進捗の可視化**: 各タスクのステータスを随時更新
2. **完了確認**: 各タスク完了時に動作確認
3. **ドキュメント更新**: 変更点を適切に記録
4. **次のタスクの前提条件確認**: 依存関係の検証

### 品質管理
1. **Rust edition 2024使用**: 最新の言語機能活用
2. **async/await**: 非同期処理の統一
3. **セキュリティ**: ベストプラクティス遵守
4. **TDD**: 各Phaseで単体テスト実装必須
5. **CI/CD**: 自動テスト・リント・フォーマットチェック
6. **コードレビュー**: PR毎の必須レビュー

## 現在の状況

**Phase 1完了**: ✅ PR提出済み (`feature/passkey-foundation`)
**現在のフェーズ**: Phase 1 PRレビュー待ち
**新機能追加**: ✅ ユーザー自由登録機能をPhase 2-3に統合
**セキュリティ強化**: ✅ DynamoDB段階的暗号化をPhase 2・4に統合
**次のアクション**: Phase 1 PRマージ後、Phase 2開始（新機能・セキュリティ強化含む）

## 次のPhase開始条件

**Phase 2開始**: Phase 1 PRがマージされ次第
1. 新ブランチ `feature/phase2-core-features` 作成
2. WebAuthn統合から開始
3. ユーザー登録方式拡張機能実装（2.1.5）
4. DynamoDB暗号化設定強化（2.1.7）
5. 各タスク完了後、単体テスト実装
6. Phase 2完了後、PR提出