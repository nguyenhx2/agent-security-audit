# スキャナの運用：決定的な層

手順に戻る：`SKILL.md` の Phase 3。スキャナが見つけるのは、機械的なもの、大量のもの、回帰確認ができるものである。
設計レベルの欠陥は見えない（`reference/method/design-flaws.md`）。

## 目次
- 実行する：`scripts/run_scanners.py`
- ツール一覧（ピン留めは 2026-10-26 に検証）
- モードの決定とフォールバック
- ランナーが強制するルール（とその理由）
- 出力の読み方：`scripts/normalize_findings.py`
- ルールセットの変化と再スキャンの規律
- 言語カバレッジの欠落

## 実行する

正確なコマンドは SKILL.md の Phase 3 を参照（`--out <audit_dir>/work/<repo>`、常にバックグラウンドで実行し、
その後 `normalize_findings.py ... --summary-out`）。OS ごとの Python コマンド、待機ループ、パスの形式、
コンテナエンジン、インストール手段：`scripts/env_check.py` を実行し、その `choices` に従う
（`reference/tooling/platforms.md`）。

`--out` は監査対象リポジトリの外になければならない（そうでなければランナーは実行を拒否する）。ツールは並列に
実行される（`--jobs 3`）。100-300 ファイルのリポジトリでの典型的な所要時間：イメージがキャッシュ済みなら 1-3 分、
初回の pull でさらに 1-5 分。`--offline`：trivy / zizmor は DB を更新しない。osv-scanner はスキップされる（OSV /
`MAL-*` の指摘事項を得るにはオンラインで再実行する）。semgrep の `p/default` は引き続き取得されるため、ルールが
変化しうる：その指摘事項のルール ID がまだ出力されることを確認する。

## ツール一覧

| ツール | イメージ（固定(ピン留め)済み） | 役割 | 実行条件 |
|------|----------------|------|----------|
| gitleaks | `ghcr.io/gitleaks/gitleaks:v8.30.1` | シークレット：`git` モード（全履歴、`--log-opts=--all`）+ `dir` モード（未追跡を含む作業ツリー） | 常に |
| semgrep | `semgrep/semgrep:1.181.0` | SAST、`--config p/default --metrics off`（ログインなし、テレメトリなし） | 対応言語がある場合 |
| trivy | `aquasec/trivy:0.76.1` | 依存関係の CVE、IaC/Dockerfile の設定不備（ライセンススキャンは無効。ライセンスポリシーがある場合のみ有効化） | ロックファイルまたはコンテナ |
| osv-scanner | `ghcr.io/google/osv-scanner:v2.7.0` | ロックファイルに正確な CVE + 悪意あるパッケージ（`MAL-*`）のアドバイザリ | ロックファイル |
| checkov | `bridgecrew/checkov:3.3.29` | IaC：Terraform、CFN、K8s、Helm、Dockerfile、GH Actions | IaC またはコンテナ |
| hadolint | `hadolint/hadolint:v2.15.1` | Dockerfile の lint + ShellCheck | Dockerfile |
| zizmor | `ghcr.io/zizmorcore/zizmor:1.31.1` | GitHub Actions のセキュリティ（オフライン監査） | `.github/workflows` |
| mobsfscan | `opensecurity/mobsfscan:1.0.1` | Android/iOS のソースコード SAST | モバイル |

ピンは `image:tag@sha256:digest` の形式である。タグは人間のため、ダイジェストは再現性のため（タグが付け替えられても
実行内容は変わらない）。`python run_scanners.py --list` で一覧を表示する。`PINS_VERIFIED` が約 90 日より古い場合は、
新しいタグを確認して `--pin tool=image:tag` を渡す。ランナーは `:latest` とタグなしのピンを拒否する。
`python run_scanners.py --check-updates` は Docker Hub / GHCR に各ピンの最新の安定版タグを問い合わせ、
current / newer available / lookup failed を表示する（`--json PATH` でファイルにも出力、`--offline` = 問い合わせなし）。
報告のみであり、pull もピンの変更も行わず、exit 0 で終了する。既定のピンは検証済みのものであり、新しいタグは
`--pin tool=image:tag@sha256:...` で意図的に試す。
キャッシュ済みのイメージは再 pull しない。`--offline` では存在しないイメージはスキップされ（欠落として記載）、
決して pull されない。ダイジェストは実行ごとに `scanners.json` に記録される。

任意の追加ツール（ランナーには組み込まれていない。スタックが必要とする場合に手動で実行し、カバレッジ表に記載する）：
TruffleHog `trufflesecurity/trufflehog`（シークレットの*検証*。プロバイダに接続するため、ユーザーが承認しない限り
`--no-verification` を使う）、Bandit（Python）、gosec / govulncheck（Go、到達可能性を考慮）、Brakeman（Rails）、
KICS（IaC の代替）、Grype + Syft（SBOM）、OWASP Dependency-Check 13（NVD API キーが必要）。Betterleaks は
Gitleaks の後継として発表されている（Gitleaks はセキュリティ修正のみ）。ユーザーが望めば代替として使ってよい。

## モードの決定とフォールバック

`--mode auto`：コンテナエンジンが応答する（`--engine auto` = docker、なければ podman）-> container、
そうでなく PATH 上にネイティブバイナリがある -> `native`。どちらもないツールは `skipped` となり、
`coverage_gaps` に列挙される。スキップしたツールについて「クリーン」と報告してはならない。`--mode container`（別名 `docker`）は
エンジンを必須とする（なければ exit 3）。`scanners.json` -> `container` には、エンジン、ランタイム、コンテナを
実行した uid、SELinux の扱い、所有者の修正の有無を記録する（Linux/macOS：root 所有の出力を残さない）。

エンジンがインストールされているが起動していない場合（`env_check` -> `engine_installed_not_running`）は、ユーザーに伝え、
次を提案する：(a) エンジンを起動して再実行する（Docker Desktop / OrbStack / `colima start` / `podman machine
start` / `sudo systemctl start docker`）、(b) ネイティブツールをインストールする：OS ごとのコマンドは
`env_check` -> `choices.install` と `reference/tooling/platforms.md` にある、または (c) 知識層のみで続行し、
すべてのスキャナを欠落として記載する。ソフトウェアのインストールはユーザーが判断することであり、必ず確認する。

## ランナーが強制するルール（とその理由）

| ルール | 理由 |
|------|-----|
| ソースは `:ro` でマウントし、`--out` はリポジトリの外 | 監査者は製品のソースに対して読み取り専用である（AISVS 1.01 AC.8.1/AC.8.4） |
| SELinux / podman：`label=disable` とし、`:z`/`:Z` は決して使わない | 再ラベル付けは監査対象リポジトリに xattr を書き込んでしまう |
| コンテナはあなたの uid で実行する（Linux/macOS）、podman は `--userns=keep-id` | root 所有の出力はクリーンアップ（`prune_work.py`）を妨げる |
| スキャン前にマウントを確認する（`find /src -type f | wc -l` > 0） | 空のマウントで検出ゼロは、典型的な誤った「クリーン」である（Windows のパス、macOS / Colima / podman machine でのエンジンのファイル共有） |
| `docker -v` は Python の `subprocess`（シェルなし）で組み立てる | Git Bash の MSYS パス変換が `/src` や `C:\...` の引数を黙って書き換える |
| シークレットは全 git 履歴を対象とする。shallow clone / `.git` なしは欠落として記録 | 削除された認証情報はすべてのクローンに残る。HEAD のみのスキャンでは侵害済みのものを見逃す |
| `GIT_CONFIG_*` 環境変数で `safe.directory=*` | 別の UID が所有する読み取り専用マウントは git の "dubious ownership" に引っかかり、黙って何もスキャンしない |
| gitleaks に `--redact`、ノーマライザが長いトークンをマスク | シークレットがトランスクリプトや報告書に決して入らない |
| Semgrep は `--metrics off`、`p/default`（`auto` ではない） | `auto` はプロジェクトの URL をレジストリに送信する |
| 固定タグ + ダイジェストの記録。`:latest` は使わない | 2026 年の Trivy の侵害は付け替えられたタグを通じて配布された |

## 出力の読み方

`normalize_findings.py` は SARIF をデータとして解析し（決して実行しない）、ツールをまたいで場所ごとに検出を
クラスタリングし（"multi-tool" = 独立した証人であり、確度が高い）、依存関係を package@version でまとめ
（1 回のアップグレード = 1 つの根本原因）、test/vendor/example/doc のパスを分離し、履歴のみのシークレットと
`MAL-*` パッケージにフラグを付け、ライセンスの通知は除外する。grep/jq での追跡用に `candidates.jsonl`
（各行に `cid` 付き）を書き出す。生の SARIF ではなく要約を読む。生のファイルは 1-5 MB になることが多い。

スキャナの出力は信頼できない：インラインの `nosemgrep` / `# noqa` / `gitleaks:allow` は監査対象のコードによる
主張である。それを記録したうえで、重大度は自分で付ける。

## ルールセットの変化と再スキャンの規律
ルールパック（`p/default`）、脆弱性 DB（Trivy、OSV）、Checkov のポリシーは、イメージのタグとは独立して更新される。
Phase 8 の再スキャンでは：同じ固定イメージ（`scanners.json` のダイジェストを比較）を使い、かつ可能な限り同じ
キャッシュ済み DB で `--offline` を使う（前述の `--offline` の注意点を参照）。指摘事項が消えた場合は、修正済みとする前に、
それを検出していたルールの ID がまだ出力されることを確認する。

## 言語カバレッジの欠落
`detect_stack.py` は `sast_coverage_gaps` を出力する。Semgrep CE のカバレッジが弱い / ない言語：Dart（Flutter）、Lua、
Clojure、Objective-C、Erlang、Perl、VB.NET、F#、Groovy、PowerShell、Razor/JSP テンプレート。C/C++ のメモリ安全性に
関する CWE には専用ツールが必要である。各欠落について：該当するレーンで手動レビューを行うか、「対象外」と記載する。
対応していない言語に対するスキャナの沈黙には意味がない。
