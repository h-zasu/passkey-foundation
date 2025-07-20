# タスク実行の4段階フロー

## 1. 要件定義
- `.claude_workflow/complete.md`が存在すれば参照
- 目的の明確化、現状把握、成功基準の設定
- `.claude_workflow/requirements.md`に文書化
- **必須確認**: 「要件定義フェーズが完了しました。設計フェーズに進んでよろしいですか？」

## 2. 設計
- **必ず`.claude_workflow/requirements.md`を読み込んでから開始**
- アプローチ検討、実施手順決定、問題点の特定
- `.claude_workflow/design.md`に文書化
- **必須確認**: 「設計フェーズが完了しました。タスク化フェーズに進んでよろしいですか？」

## 3. タスク化
- **必ず`.claude_workflow/design.md`を読み込んでから開始**
- タスクを実行可能な単位に分解、優先順位設定
- `.claude_workflow/tasks.md`に文書化
- **必須確認**: 「タスク化フェーズが完了しました。実行フェーズに進んでよろしいですか？」

## 4. 実行
- **必ず`.claude_workflow/tasks.md`を読み込んでから開始**
- タスクを順次実行、進捗を`.claude_workflow/tasks.md`に更新
- **各タスクで単体テストを実装**（TDD推奨）
- **タスクフェーズごとにブランチ作成・PR提出**
- 各タスク完了時に報告

**プロジェクト固有の情報については[README.md](./README.md)を参照してください。**
**詳細な開発プロセスについては[CONTRIBUTING.md](./CONTRIBUTING.md)を参照してください。**
