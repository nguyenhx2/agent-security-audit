# モジュール：supply-chain - CICD-SEC、SLSA v1.2、NIST SSDF v1.1、OWASP NHI Top 10 2025、SBOM、Scorecard

リポジトリに CI/CD 設定、ロックファイル、リリース自動化、またはコンテナビルドがある場合に適用する。引用：
`OWASP Top 10 CI/CD Security Risks CICD-SEC-<n>`、`SLSA v1.2 Build L<n>` / `Source L<n>`、
`NIST SSDF SP 800-218 v1.1 <practice>`（例：PS.1、PW.4、RV.1）、`OWASP Top 10:2025 A03`。

## 目次
- 2026 年の教訓：タグは固定ではない
- CICD-SEC 1-10 のチェック
- SLSA v1.2 のレベル（何を主張できるか）
- コード監査で根拠を示せる SSDF のプラクティス
- 依存関係の指摘事項：登録方法

## 2026 年の教訓：タグは固定ではない
2026 年 3 月：悪意ある Trivy v0.69.4 のリリースバイナリ/イメージが公開され、`trivy-action`
（0.0.1-0.34.2）および `setup-trivy` のタグが悪意あるコミットへ force-push された（CVE-2026-33634）。
タグで固定していた利用者はマルウェアを実行し、ダイジェスト / コミット SHA で固定していた利用者は実行しなかった。監査対象リポジトリへの
適用：GitHub Actions の `uses:` は完全なコミット SHA で固定すること。コンテナの `FROM` は
`@sha256:` で固定すべきである。インストールスクリプトはチェックサム/署名（cosign）を検証すべきである。同じルールは本スキル
自身のスキャナにも適用される（`reference/tooling/scanners.md`）。

## CICD-SEC 1-10

| ID | リスク | 検証内容 | 場所 |
|----|------|----------------|-------|
| CICD-SEC-1 | Insufficient Flow Control Mechanisms | デプロイ用ブランチにブランチ保護 / 必須レビュー。本番へ直接 push する経路がない。本番には手動承認 | ワークフローのトリガー（`push: main` -> deploy）、レビュアー付きの environments |
| CICD-SEC-2 | Inadequate Identity and Access Management | CI アイデンティティは最小権限。個人トークンを使わない。放置されたアカウントがない | `secrets.*_TOKEN` の使用箇所、`permissions:` ブロック |
| CICD-SEC-3 | Dependency Chain Abuse | ロックファイルをコミット。プライベートレジストリのスコープ設定（依存関係の混乱）。可能な箇所ではインストールスクリプトを無効化（`--ignore-scripts`）。固定されていない `npx pkg@latest` がない | ロックファイル、`.npmrc`、ハッシュなしの `pip install` |
| CICD-SEC-4 | Poisoned Pipeline Execution (PPE) | 信頼できない PR のコードを決してシークレット付きで実行しない：PR の head をチェックアウトする `pull_request_target`/`workflow_run` がない。`${{ github.event.* }}` を `run:` に埋め込まない（スクリプトインジェクション） | `.github/workflows/*.yml`（大半は zizmor が検出） |
| CICD-SEC-5 | Insufficient PBAC | ジョブ単位の `permissions:` を最小限に（既定は `contents: read`）。セルフホストランナーを信頼できないワークフローと共有しない | `permissions: write-all`、`permissions:` の欠如、公開リポジトリでの `runs-on: self-hosted` |
| CICD-SEC-6 | Insufficient Credential Hygiene | 長期有効なクラウドキーではなく OIDC フェデレーション。シークレットを出力しない。マスク済み。environment ごとにスコープを限定 | シークレット内の `AWS_ACCESS_KEY_ID`、シークレットと併用した `set -x`、キーを用いる `aws-actions/configure-aws-credentials` |
| CICD-SEC-7 | Insecure System Configuration | ランナー/ビルドイメージにパッチ適用済みで固定。成果物ストレージが非公開 | ランナーイメージ、ビルドコンテナ |
| CICD-SEC-8 | Ungoverned Usage of 3rd Party Services | サードパーティの actions/apps をレビューし SHA で固定。組織全体への書き込み権限を持つ marketplace アプリを制限 | `uses: someone/action@v1` |
| CICD-SEC-9 | Improper Artifact Integrity Validation | 成果物に署名（Sigstore/cosign）、来歴（provenance）を生成（SLSA）、デプロイ前に検証 | リリースワークフロー、`actions/attest-build-provenance` |
| CICD-SEC-10 | Insufficient Logging and Visibility | CI の監査ログを保持。デプロイイベントの実行者を特定可能 | 組織設定（通常は静的監査の範囲外 - その旨を明記） |

## OWASP Non-Human Identities Top 10 2025（サービスアカウント、CI トークン、API キー、エージェントのアイデンティティ）
`OWASP Non-Human Identities Top 10 2025 NHIx` を引用する。コード/CI/IaC で確認する：
| ID | リスク | 検証内容 |
|----|------|----------------|
| NHI1 | Improper Offboarding | 廃止済みサービス、契約終了したベンダー、古いパイプラインのキー/SA がまだ参照またはプロビジョニングされている |
| NHI2 | Secret Leakage | コミット済み / ログ出力済み / クライアントに同梱されたシークレット（gitleaks、peek.py） |
| NHI3 | Vulnerable Third-Party NHI | リポジトリやクラウドへの広範なトークンを保持するサードパーティのアプリ/actions |
| NHI4 | Insecure Authentication | OIDC/ワークロードアイデンティティが使えるのに静的な長期キーを使用 |
| NHI5 | Overprivileged NHI | ワイルドカードの IAM、組織全体の PAT、`cluster-admin` のサービスアカウント |
| NHI6 | Insecure Cloud Deployment Configurations | audience/subject の制約のない CI からクラウドへの信頼関係（OIDC `sub` のワイルドカード） |
| NHI7 | Long-Lived Secrets | キーやトークンに有効期限/ローテーションがない |
| NHI8 | Environment Isolation | dev/staging/prod で同じ認証情報を使用 |
| NHI9 | NHI Reuse | 1 つのアイデンティティを多数のサービス/エージェントで共有 - 実行者を特定できない |
| NHI10 | Human Use of NHI | 開発者がサービス用の認証情報を対話的に使用 |

## ランタイム、イメージ、製品のパッチ適用状況（ロックファイル外）
インタプリタ、サーバー、データストア、ベースイメージ、管理ツール、フレームワークは、Dockerfile、compose /
マニフェスト、バージョンファイル、CI、サーバーレスの設定で指定され、ロックファイルの SCA には決して見えない。
`platform_inventory.py` がそれらを一覧にし、`threat_intel.py` が CISA KEV、NVD、EPSS、endoflife.date、
IPA / JPCERT/CC / JVN の注意喚起と照合する。手法、精度の規則、重大度の下限：
`reference/method/threat-intel.md`。引用は `OWASP Top 10:2025 A03`（カード情報の対象範囲では + `PCI DSS v4.0.1 Req 6.3.3`）。
EOL には CWE-1104、脆弱なサードパーティ製コンポーネントには CWE-1395。

## SLSA v1.2 - 何を主張できるか
- Build L1：来歴が存在する。L2：ホスト型ビルドプラットフォーム + 署名付き来歴。L3：強化され隔離された
  ビルド。来歴をテナントが偽造できない。
- Source track（v1.2 で新設）：バージョン管理された履歴、保護されたブランチ、上位レベルでは二者レビュー。
*観測された*レベルを根拠とともに報告する（例：「来歴の生成なし -> Build L0」）。署名/検証が確認できない場合は、
設定のみからレベルを主張しない。

## コード監査で根拠を示せる SSDF のプラクティス
PO.3（ツールチェーン）、PS.1（不正な変更からコードを保護 - ブランチ保護、署名付きコミット）、
PS.2（リリースの完全性 - 署名）、PS.3（アーカイブ + 来歴）、PW.4（十分にセキュアな
コンポーネントの再利用 - 依存関係の衛生管理）、PW.7（コードレビュー/解析 - CI での SAST）、RV.1（脆弱性の
特定 - CI での SCA）。NIST SP 800-218A は GenAI 固有のプラクティスを追加している（モデルの学習/
ファインチューニングを行う場合に引用）。SSDF Rev 1（v1.2）はドラフトである - 確定版として引用しない。

## 依存関係の指摘事項：登録方法
- **根本原因 = アップグレードすべきパッケージ**であり、個々の CVE ではない。修正済みの最小バージョンを明記する
  （Trivy `Fixed Version`、OSV アドバイザリの `affected.ranges`）。「アドバイザリを参照」は是正策ではない。アップグレード作業 1 件につき指摘事項 1 件
  （`scripts/normalize_findings.py` はすでにこの単位でグループ化する）。CVE はその中に列挙する。
- 重大度：本番コード経路から到達可能で、この文脈で悪用可能 -> スキャナの重大度を維持。
  開発専用 / テスト専用 / 到達不能 -> 理由を明記して引き下げる。既知の悪意あるパッケージ
  （OSV `MAL-*`）-> P0。インストール処理が触れ得たものはすべてローテーションする。
- 推移的な脆弱性：それを取り込む直接依存関係と、最小限のアップグレードを明記する。
- SBOM：CI での CycloneDX 1.7 / SPDX 3.0.1 の生成を推奨する（PCI DSS v4.0.1 6.3.2 の一覧）。
- OpenSSF Scorecard（v5.x）で重要なサードパーティ依存関係のリポジトリ衛生を評価できる - 提案にとどめ、
  ユーザーの依頼なしにサードパーティに対して実行しない。
