# security-audit

Claude Code 用の読み取り専用セキュリティ監査スキルです。1 つ以上のリポジトリを監査し、根拠となる箇所を
明示した指摘事項と、Markdown・HTML・Excel の報告書（英語または日本語）を出力します。監査対象のコードを
編集・ビルド・実行することはありません。

使い方：Claude Code で「このリポジトリをセキュリティ監査して」と依頼します（または
`/security-audit <リポジトリのパス> [quick|standard|deep]`）。深さ、報告書の言語、重点領域、出力形式を
確認したうえで、偵察、スキャナ、レビュー、検証、報告書作成の順に進めます。手順の詳細は `SKILL.md`、
変更履歴は `CHANGELOG.md` を参照してください。

## 実行するもの・送信するもの・取得するもの

**ローカルで実行するもの**
- `scripts/` 配下の同梱 Python スクリプト（標準ライブラリのみ。Excel 出力にのみ `openpyxl` を使用）。
- 監査対象リポジトリに対する読み取り専用の git コマンド（フック、fsmonitor、リポジトリ側の設定は無効化）。
- バージョンを固定したスキャナ：Semgrep、Gitleaks、Trivy、OSV-Scanner、Checkov、zizmor、mobsfscan、
  hadolint。Docker または Podman があればコンテナで、なければネイティブ版で実行し、どちらもなければ
  未実施として報告書に明記します。コンテナイメージは実行時に公開レジストリからダイジェスト指定で取得
  します。リポジトリは読み取り専用でマウントし、ネットワーク不要のツール（Gitleaks、hadolint）は
  ネットワークを無効にして実行します。
- Excel の再計算チェック（Windows では Excel、それ以外では LibreOffice のヘッドレス実行。インストール
  されている場合のみ）。

**送信するもの（ネットワーク）**
- `threat_intel.py`：製品名とバージョンのみ（endoflife.date の製品 ID、`cpe:2.3:a:php:php:8.3.30`
  のような NVD の CPE 文字列、FIRST EPSS への CVE 番号）。リポジトリ名、パス、コード、指摘内容は送信
  しません。
- OSV-Scanner はパッケージ名とバージョンを osv.dev に送信します。Semgrep はルールを Semgrep の
  レジストリから、Trivy は脆弱性データベースを取得します（`--offline` ではキャッシュ済みのものを使用）。

**取得するもの（ネットワーク、公開情報、アカウント不要）**
- CISA KEV カタログ（cisa.gov。取得できない場合は GitHub のミラー）、NVD CVE API 2.0、FIRST EPSS API、
  endoflife.date API、IPA の重要なセキュリティ情報 RSS、JPCERT/CC の注意喚起 RSS、JVN の RSS、
  JVN iPedia の RSS。接続先は固定の許可リストに限定し、`~/.cache/security-audit/intel` にキャッシュ
  します。`--offline` ではキャッシュのみを使用します。
- フィードやリポジトリ内の文章はデータとして扱い、指示としては扱いません。

**書き込むもの**
- 監査対象リポジトリの外にある監査フォルダ（`<親フォルダ>/<プロジェクト>-security-audit/<日時>/`）、
  フィードのキャッシュ、および標準・詳細の深さでは `~/.claude/agents/security-audit/` の補助
  サブエージェント 4 つのみです。
