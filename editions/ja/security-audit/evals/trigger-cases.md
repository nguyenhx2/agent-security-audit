# トリガーケース - security-audit

スキルの description を変更したときは必ず再実行する。各ケースには、読み込まれるべきもの、反応してはならないもの、
結果の判定方法を記載する。実行ごとの振る舞いの期待値は `evals/evals.json` にある。

## positive-discovery

スキルが起動するべきケース。

- Request: 「リリース前にこのリポジトリを監査して。顧客のカード情報を保存していて、サポートの返信に LLM を使っている。」
- Repo state: `package-lock.json`、マイグレーション、Stripe との連携、OpenAI クライアントを持つ Node.js の API。過去の監査フォルダはない。
- Expected skills: security-audit
- Not expected: security-review（差分については尋ねられていない）、harness-bootstrap
- Success criteria: Phase 0 の質問は 1 回だけ行われる。監査フォルダはリポジトリの外に作成される。validate_findings.py が 0 で終了する。報告書に、保存データ中の機微情報、AI の構成一覧、プラットフォーム / 脅威情報、未カバー領域の各セクションがある。

## negative-discovery

近いように聞こえるが、別のスキルが担当する依頼。スキルは起動してはならない。

- Request: 「PR を出す前に、このブランチの変更のセキュリティをレビューして。」
- Repo state: 3 ファイルを変更したフィーチャーブランチ。
- Expected skills: security-review
- Not expected: security-audit
- Success criteria: 差分のみがレビューされる。監査フォルダ、スキャナの実行、報告書一式は作られない。

## edge-case

スキルが起動し、アプリケーションコードもスキャナのエンジンもない対象に対処するべきケース。

- Request: 「セキュリティ監査して。Docker は入っていない。」
- Repo state: Terraform と Kubernetes のマニフェストのみ。コンテナエンジンもネイティブのスキャナもない。JVN iPedia のフィードは停止中。
- Expected skills: security-audit
- Not expected: harness-bootstrap
- Success criteria: env_check が OS ごとの選択肢を示し、監査はコード読解のみで続行され、不足するすべてのスキャナと取得できなかったフィードが未カバー領域として明記され（問題なしとは扱われない）、報告書は日本語で英語の本文がない。

## conflict-composition

複数のスキルが関係しそうに見えるケース。振り分けを明示する必要がある。

- Request: 「このリポジトリに Claude のハーネスを導入して、導入の前後で安全か確認して。」
- Repo state: コミット済みの `.claude/settings.json` とフックを持つ既存のアプリ。
- Expected skills: セットアップは harness-bootstrap が主導する。security-audit はその前（ベースライン）と後（agent-tooling の範囲の再スキャン）に実行する
- Not expected: security-review
- Success criteria: security-audit はリポジトリもハーネスのファイルも一切編集せず、それらは harness-bootstrap が書き込む。2 回目の監査は、ハーネスが追加したエージェントの権限とフックを報告し、指摘事項は再スキャンでのみクローズする。

## execution-quality

スキルによって結果が目に見えて改善するケース。

- Request: 「今週出た PHP の緊急の勧告は、うちの PHP アプリに影響する？」
- Repo state: `FROM php:8.3.30-fpm` を含む `Dockerfile`、`"php": "^8.1"` を含む `composer.json`、`info.php` を含む `public/` フォルダ。
- Expected skills: security-audit
- Not expected: security-review
- Success criteria: platform_inventory がデプロイされる正確なバージョンを見つける。threat_intel がそれを KEV / IPA / JPCERT/CC が注意喚起した CVE と、範囲指定が許容する EOL のサイクルとに照合する。1 件のアップグレードの指摘事項がすべての CVE と指定箇所を列挙する。Web ルートの `phpinfo()` がトリアージされる。validate_findings.py が `intel:` の警告を出さない。
- Baseline (without the skill): リポジトリの指定バージョンを読まずに勧告について一般的に回答し、バージョンの比較も、Web ルートや範囲指定の確認もしない。

## efficiency

スキルが必要なものだけを読み込むケース。

- Request: 「この小さな Flask の API を手早くセキュリティチェックして。報告書は英語のみ。」
- Repo state: Python ファイル約 40 個、`requirements.txt`。モバイル、IaC、AI の構成要素はない。
- Expected skills: security-audit
- Not expected: security-review
- Success criteria: Quick の深さでレーンをインラインで実行し、サブエージェントは使わない。mobile、ai-llm-agentic、pci-dss、cloud-iac の参照資料は読まれない。回答は短い（件数、上位の指摘事項、最初の対応、未カバー領域、パス）。
