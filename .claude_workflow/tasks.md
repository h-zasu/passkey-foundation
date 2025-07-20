# タスク化: Passkey GraphQL認証基盤の実装タスク

## 前段階確認
`.claude_workflow/design.md`を読み込みました。

## タスク実行計画

### Phase 1: プロジェクト基盤構築
**期間**: 1-2日
**目的**: 基本的なCargoワークスペースとプロジェクト構造の構築

#### 1.1 Cargoワークスペース設定
- [ ] **未着手** `Cargo.toml`ワークスペース設定作成
- [ ] **未着手** `.cargo/config.toml`設定ファイル作成（xtaskエイリアス設定）
- [ ] **未着手** `lambda/Cargo.toml`作成（GraphQL Lambda機能）
- [ ] **未着手** `shared/Cargo.toml`作成（共通ライブラリ）
- [ ] **未着手** `xtask/Cargo.toml`作成（デプロイメント自動化）

#### 1.2 基本ディレクトリ構造作成
- [ ] **未着手** `lambda/src/`ディレクトリ構造作成
- [ ] **未着手** `shared/src/`ディレクトリ構造作成
- [ ] **未着手** `xtask/src/`ディレクトリ作成

#### 1.3 基本ファイル作成
- [ ] **未着手** `lambda/src/main.rs`スケルトン作成
- [ ] **未着手** `shared/src/lib.rs`スケルトン作成
- [ ] **未着手** `xtask/src/main.rs`スケルトン作成

### Phase 2: 共通ライブラリ実装
**期間**: 2-3日
**目的**: 全体で使用する共通機能の実装

#### 2.1 基本型定義
- [ ] **未着手** `shared/src/types.rs`実装
  - UserRole enum定義
  - User, Credential, Session構造体
  - PendingUser, AppConfig構造体
  - GraphQL入出力型

#### 2.2 設定管理実装
- [ ] **未着手** `shared/src/config.rs`実装
  - 環境変数からの設定読み込み
  - AppConfig管理機能
  - AWS設定初期化

#### 2.3 DynamoDB基本操作実装
- [ ] **未着手** `shared/src/dynamodb.rs`実装
  - DynamoDBクライアント初期化
  - 基本CRUD操作
  - テーブル名管理
  - エラーハンドリング

#### 2.4 エラーハンドリング実装
- [ ] **未着手** `shared/src/errors.rs`実装
  - PasskeyError型定義
  - thiserrorベースエラー実装
  - GraphQLエラー変換

#### 2.5 ユーティリティ実装
- [ ] **未着手** `shared/src/utils.rs`実装
  - UUID生成
  - タイムスタンプ処理
  - Base64エンコード/デコード

### Phase 3: WebAuthn・認証機能実装
**期間**: 3-4日
**目的**: 認証機能のコア実装

#### 3.1 WebAuthn統合
- [ ] **未着手** `shared/src/webauthn.rs`実装
  - WebAuthn設定初期化
  - 登録チャレンジ生成
  - 認証チャレンジ生成
  - クリデンシャル検証

#### 3.2 OTP機能実装
- [ ] **未着手** `shared/src/otp.rs`実装
  - OTP生成機能
  - ハッシュ化・検証機能
  - 試行回数制限
  - 有効期限管理

#### 3.3 JWT認証実装
- [ ] **未着手** `shared/src/jwt.rs`実装
  - JWT生成機能
  - JWT検証機能
  - クレーム管理
  - トークンrefresh機能

#### 3.4 メール送信機能実装
- [ ] **未着手** `shared/src/email.rs`実装
  - SESクライアント初期化
  - OTP招待メール送信
  - HTMLテンプレート処理
  - 送信履歴記録

### Phase 4: DynamoDBデータアクセス層実装
**期間**: 2-3日
**目的**: データベース操作の完全実装

#### 4.1 ユーザー管理操作
- [ ] **未着手** `shared/src/dynamodb/users.rs`実装
  - ユーザー作成・取得・更新
  - メールでのユーザー検索
  - アプリIDによるフィルタリング

#### 4.2 認証情報管理操作
- [ ] **未着手** `shared/src/dynamodb/credentials.rs`実装
  - クリデンシャル保存・取得
  - ユーザーのクリデンシャル一覧
  - カウンター更新

#### 4.3 セッション管理操作
- [ ] **未着手** `shared/src/dynamodb/sessions.rs`実装
  - セッション作成・取得・削除
  - TTL自動削除設定
  - チャレンジ管理

#### 4.4 事前登録ユーザー管理操作
- [ ] **未着手** `shared/src/dynamodb/pending_users.rs`実装
  - 事前登録ユーザー作成・取得
  - OTP試行回数管理
  - 有効期限管理

#### 4.5 アプリ設定管理操作
- [ ] **未着手** `shared/src/dynamodb/app_configs.rs`実装
  - アプリ設定取得・更新
  - 設定キャッシュ機能

### Phase 5: GraphQL API実装
**期間**: 4-5日
**目的**: GraphQL APIの完全実装

#### 5.1 GraphQLスキーマ定義
- [ ] **未着手** `lambda/src/schema.rs`実装
  - async-graphql型定義
  - Query/Mutation/Subscription定義
  - Context型定義

#### 5.2 認証ミドルウェア実装
- [ ] **未着手** `lambda/src/auth.rs`実装
  - JWT検証ミドルウェア
  - ユーザー認証状態管理
  - 権限チェック機能

#### 5.3 Query Resolver実装
- [ ] **未着手** `lambda/src/resolvers/query.rs`実装
  - user クエリ
  - users クエリ（ページネーション）
  - pendingUsers クエリ
  - appConfig クエリ

#### 5.4 ユーザー管理Mutation実装
- [ ] **未着手** `lambda/src/resolvers/user_management.rs`実装
  - inviteUser Mutation
  - updateUserRole Mutation
  - deactivateUser Mutation

#### 5.5 認証フローMutation実装
- [ ] **未着手** `lambda/src/resolvers/auth_flow.rs`実装
  - verifyOtpAndStartRegistration Mutation
  - completeRegistration Mutation
  - startAuthentication Mutation
  - completeAuthentication Mutation

#### 5.6 Subscription実装
- [ ] **未着手** `lambda/src/resolvers/subscription.rs`実装
  - userRegistered Subscription
  - リアルタイム通知機能

### Phase 6: Lambda統合・メイン実装
**期間**: 2日
**目的**: Lambda関数としての統合

#### 6.1 Lambdaエントリーポイント実装
- [ ] **未着手** `lambda/src/main.rs`完全実装
  - AWS設定初期化
  - GraphQLスキーマ作成
  - Lambda runtime統合
  - エラーハンドリング

#### 6.2 CORS・セキュリティ設定
- [ ] **未着手** CORS設定実装
- [ ] **未着手** セキュリティヘッダー設定
- [ ] **未着手** レート制限設定

### Phase 7: xtask自動化ツール実装
**期間**: 3-4日
**目的**: デプロイメント自動化

#### 7.1 CLI基盤実装
- [ ] **未着手** `xtask/src/main.rs`CLI構造実装
  - clap設定
  - サブコマンド定義

#### 7.2 AWS初期化機能
- [ ] **未着手** `xtask/src/init.rs`実装
  - DynamoDBテーブル作成
  - IAMロール作成
  - 初期設定確認

#### 7.3 デプロイ機能実装
- [ ] **未着手** `xtask/src/deploy.rs`実装
  - cargo lambda build統合
  - Lambda関数デプロイ
  - 環境変数設定

#### 7.4 API Gateway設定機能
- [ ] **未着手** `xtask/src/gateway.rs`実装
  - REST API作成
  - GraphQLエンドポイント設定
  - デプロイメント管理

#### 7.5 カスタムドメイン機能
- [ ] **未着手** `xtask/src/domain.rs`実装
  - ACM証明書作成
  - ドメイン関連付け
  - Route 53設定

### Phase 8: テスト実装
**期間**: 2-3日
**目的**: 品質保証

#### 8.1 単体テスト実装
- [ ] **未着手** shared クレートのテスト
- [ ] **未着手** lambda クレートのテスト
- [ ] **未着手** モック機能実装

#### 8.2 統合テスト実装
- [ ] **未着手** GraphQL API統合テスト
- [ ] **未着手** WebAuthnフローE2Eテスト
- [ ] **未着手** DynamoDBローカルテスト

#### 8.3 パフォーマンステスト
- [ ] **未着手** 負荷テスト実装
- [ ] **未着手** レスポンス時間測定

### Phase 9: ドキュメント・仕上げ
**期間**: 1-2日
**目的**: プロジェクト完成

#### 9.1 設定ファイル調整
- [ ] **未着手** `.gitignore` 作成
- [ ] **未着手** `README.md` 更新（必要に応じて）

#### 9.2 最終テスト・検証
- [ ] **未着手** 全機能動作確認
- [ ] **未着手** セキュリティ検証
- [ ] **未着手** パフォーマンス確認

## 実行順序と依存関係

### 実行ルール
1. **段階的進行**: Phase順序で実行し、前のPhaseが完了してから次へ
2. **単一タスク集中**: 複数タスクの同時進行は行わない
3. **エラー解決優先**: エラーが発生したら解決してから次のタスク
4. **テスト駆動**: 実装完了後は必ずテストで動作確認

### 依存関係
- Phase 2 → Phase 1完了後
- Phase 3,4 → Phase 2完了後
- Phase 5 → Phase 3,4完了後
- Phase 6 → Phase 5完了後
- Phase 7 → Phase 6完了後
- Phase 8 → Phase 7完了後
- Phase 9 → Phase 8完了後

## 優先度設定
- **高**: Phase 1-6（コア機能）
- **中**: Phase 7-8（自動化・テスト）
- **低**: Phase 9（仕上げ）

## 成功基準
各Phaseの完了基準：
- [ ] 全タスクが「完了」状態
- [ ] ビルドエラーなし
- [ ] 基本的なテストパス
- [ ] 次Phaseの前提条件満足

## 注意点
- Rust edition 2024を使用
- async/awaitパターンで実装
- セキュリティベストプラクティス遵守
- AWS Lambda制約内での実装
- エラーは適切にログ出力し、内部詳細を隠蔽

## 次ステップ
Phase 1「プロジェクト基盤構築」から開始