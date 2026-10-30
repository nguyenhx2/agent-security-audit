# トラブルシューティングと FAQ

[English](../troubleshooting.md) · **日本語**

まず `env_check.py --pretty` を実行してください（[インストール](install.md)を参照）。ほとんどの問題は、その `choices` と `notes` に現れます。

## スキャナ

### `no container engine answers`（run_scanners の終了コード 3）

`run_scanners.py --mode container` が、応答する Docker や Podman のデーモンを見つけられませんでした。既定の `--mode auto` では、代わりにネイティブ版のスキャナを使います。

- `env_check.py` に `engine_installed_not_running` が出ていれば、エンジンを起動して再実行します。Windows では Docker Desktop、Podman Desktop、Rancher Desktop、macOS では Docker Desktop、OrbStack、`colima start`、`podman machine start`、Linux では `sudo systemctl start docker` です。
- または、スキャナをネイティブで入れます（`env_check.py` の `install` に、OS ごとのツール別のコマンドが出ます）。
- または、読むだけの監査として続けます。監査は動き、すべてのスキャナを未確認範囲として列挙します。

スキルはこの 3 つの選択肢を示し、何かをインストールする前に必ず確認します。

### `mount verification failed: /src resolved to 0 files`（終了コード 4）

コンテナから空のフォルダしか見えなかったため、スキャンの結果に意味がありません。スキルはそのようなスキャンを報告しません。原因と対処：

- **ファイル共有。** エンジンから見えるのは、共有しているホストのフォルダだけです。macOS の Docker Desktop は既定で `/Users`、`/Volumes`、`/private`、`/tmp` を共有します。Colima と Lima は `$HOME` をマウントするため、リポジトリと監査フォルダを `$HOME` の下に置きます。macOS の podman machine は `/Users`、`/private`、`/var/folders` を共有します。共有を追加するか、リポジトリを移動します。
- **パスの誤り。** パスが存在し、OS に合った形式になっているかを確認します（次の節）。
- **SELinux。** 実行時にすでに `label=disable` を付けています。`:z` は付けないでください。

### `no tool ran`（終了コード 5）

選んだスキャナがすべて失敗したか、省略されました。`run_scanners.py` が出力するツールごとの行と、`work/<repo>/scanners.json` の `coverage_gaps` を確認します。`--offline` では、キャッシュにないイメージは取得せずに省略します。一度オンラインで実行してイメージを取得してください。

### `--out must be OUTSIDE the audited repo`

監査しているリポジトリの中への書き込みは拒否します。リポジトリの隣にある既定の監査フォルダを使ってください。

### `pin for <tool> must carry an explicit tag (never :latest)`

`--pin` には `image:tag` または `image:tag@sha256:...` が必要です。タグは `run_scanners.py --check-updates` で探せます。[スキャナ](scanners.md)を参照してください。

### 未確認範囲：`git history unavailable (no .git or shallow clone)`

秘密情報のスキャンは作業ツリーだけが対象になりました。削除した認証情報もクローンの履歴には残るため、できれば完全なクローン（`git fetch --unshallow`）を監査してください。

### 未確認範囲：`repo scanner config may suppress results`

リポジトリに、スキルが無効化できないスキャナの設定（`.gitleaksignore`、`.checkov.yaml`、`.semgrepignore`）があります。何を抑止しているかを確認してください。報告書にも記載します。

## Windows のパスとシェル

- **スクリプトの引数には `C:/Users/...`（スラッシュ区切り）を使います。** Git Bash の `/c/Users/...` も受け付け、スクリプトが変換します（変換しないと、黙って `C:/c/Users` と解釈されてしまいます）。
- **`/tmp` は使いません。** Git Bash では、`/tmp` が Write ツールと Python とで別のフォルダを指すため、ファイルが見つからなくなります。
- **Git Bash のパス変換**は、`docker -v` に渡す `/src` や `C:\...` のような引数を書き換えることがあります。`run_scanners.py` はシェルを通さず Python でコンテナのコマンドを組み立てるため、スキャンではこれが起きません。Git Bash からそのようなパスで `docker` を手で呼ぶのは避けてください。
- **PowerShell の確認。** スキルは、スキルが事前に許可している Bash ツール（Git Bash）でスクリプトを実行します。PowerShell の呼び出しは許可を求められます。Git Bash がなければ、待機のループは PowerShell を使います。
- **WSL。** Linux の `python3` と Linux の docker CLI を、`/mnt/c/...` や `~/...` のパスで使います。WSL から Windows の `docker.exe` を呼ぶ場合は、代わりに `C:/...` のパスが必要です。`/mnt/c` の下のリポジトリはスキャンに時間がかかります。

## Python

- **`no Python >= 3.9 found`。** Python 3.9 以上を入れてください。Windows では、スキルは `py -3` ランチャーを優先し、Microsoft Store のスタブは避けるため、`py` ランチャー付きで入れてください。
- **`openpyxl missing`。** Excel の出力には `py -3 -m pip install openpyxl`（または `python3 -m pip install openpyxl`）が必要です。スキルは先に確認し、`--yes` のときは Excel を省略して、そのことを返答で伝えます。`env_check.py` は、すでに openpyxl のある Python を優先して選びます。
- **`VERIFY SKIPPED`。** Excel も LibreOffice も見つからなかったため、ブックは作成しましたが再計算はしていません。LibreOffice を入れる（`soffice` を `PATH` に置く）か、返答の注記をそのまま受け入れてください。

## 日本語の文字と cp932 のコンソール

どのスクリプトも、cp932 や cp1252 のコンソールやパイプでも、標準出力と標準エラーに UTF-8 で書き出すため、日本語の文字で異常終了することはありません。書き出すファイルもすべて UTF-8 です。日本語が文字化けして見える場合は、表示する側が UTF-8 を cp932 として解釈しています。ファイルを UTF-8 として開くか、コンソールを UTF-8 に切り替えてください（cmd では `chcp 65001`）。

## アドバイザリフィード

- **フィードが未確認範囲に載っている。** タイムアウトした、エラーページを返した、または停止しています。これは意図した動作で、フィードに問題がなかったと主張する代わりに、未確認であることを明記します。時間をおいて再実行すれば、たいてい埋まります。キャッシュがあれば、古いものと明記したうえで使います。
- **JVN iPedia がない。** このフィードは停止することがあります。JVN と JPCERT/CC でほぼ補えます。
- **脆弱性情報の照合が遅い。** NVD はキーがないとレート制限がかかります。環境変数 `NVD_API_KEY` を設定すると制限が緩みます。
- **ネットワークを使えない。** 開始時にそう伝えてください。脆弱性情報の照合は `--offline`（キャッシュのみ）で実行し、報告書に未確認範囲として明記します。
- **`named in alerts, version match unconfirmed`。** 国内の注意喚起が製品名を挙げていますが、NVD の CPE データではまだバージョンを確認できません。レーンがアドバイザリの影響を受けるバージョンを読み、指定と比べます。

[ライブ脅威情報](threat-intelligence.md)を参照してください。

## 大きなリポジトリ

- **スキャンに時間がかかる。** スキャナはバックグラウンドで動き、ツールごとのタイムアウトは 900 秒です（`--timeout`）。最初のイメージ取得でさらに 1-5 分かかります。
- **ファイル数の上限。** `detect_stack.py` は 60,000 ファイルで止まり、プロファイルに `TRUNCATED` と記します。`repo_digest.py` と `route_map.py` は 20,000、`platform_inventory.py` は 50,000 で止まります。どれも `--max-files` で上限を上げられます。
- **レーン。** 5000 ファイル以上のリポジトリでは、レーンごとに 1 つのサブエージェントを使い、レーンパックの容量も増やせます（`--budget-kb 90`）。
- **範囲を絞る。** モノレポ全体を Deep で監査するより、重要なサービスを別々のリポジトリとして 1 回の実行で監査してください（`/security-audit ../api ../web`）。

## サブエージェント

- **名前が Agent ツールの一覧にない。** `install_agents.py` がこのセッション中に `~/.claude/agents/security-audit/` を作りました。新しい agents フォルダは、Claude Code を再起動するまで認識されません。この実行では汎用サブエージェントで代用するので、次の実行の前に Claude Code を再起動してください。
- **同じ名前の、自分が書いていないファイルがあると報告された。** `install_agents.py` は、自分のものでないエージェントのファイルを上書きしません。スキルの版を使いたい場合は、そのファイルの名前を変えるか削除してください。

## 後片付け

- **`prune_work.py` が終了コード 1 で終わる。** 削除できないファイル（Linux の root 所有のスキャナ出力、Windows の読み取り専用やロック中のファイル）がありました。OS に合った修正コマンドが表示されるので、それを実行してから `prune_work.py` を再実行してください。
- **実行を拒否される。** `prune_work.py` は `reports/md/*.md` があるとき、つまり実行が終わったあとでなければ動きません。

## 実行全般

- **対象のフックや指示が有効だと警告された。** 監査するリポジトリの中で Claude Code を起動しており、そのリポジトリに `.claude/`、`.mcp.json`、`CLAUDE.md` があります。親フォルダから始め直してください。
- **無人の実行が質問で止まると困る。** `--yes`（と深さ）を付けて、Phase 0 で既定値を使うようにします。Phase 0 のあとは、スキルが質問のために止まることはありません。
- **基準の検証日が古い。** 基準の一覧の検証日から 90 日を過ぎると、スキルは引用の前に対象の行を検証し直します。新しい一覧を使うには、スキルを更新してください。

## FAQ

**コードを変更しますか。** しません。監査対象のコードを編集、整形、コミット、ビルド、実行することはありません。出力はすべてリポジトリの隣のフォルダに置きます。

**コードをどこかに送りますか。** 送りません。アドバイザリフィードに送るのは製品名とバージョンだけで、OSV-Scanner はパッケージ名とバージョンを osv.dev に送ります。[セキュリティとプライバシー](security-and-privacy.md)を参照してください。

**複数のリポジトリをまとめて監査できますか。** できます：`/security-audit ../api ../web ../infra`。監査フォルダも報告書も 1 つで、リポジトリ横断の指摘は第 5 章に載ります。

**英語版で日本語の報告書を作れますか。** 作れます。英語版は英語、日本語、またはその両方で報告書を書きます。日本語版で変わるのは、スキル自体の手順書の言語だけです。

**指摘に `needs-runtime-check` と書かれているのはなぜですか。** 本番でポートが公開されているかどうかなど、静的な監査では見えないことに依存しているためです。検証の節に、その事実と確認できる人を書いています。

**`perf-quality` が実行されなかったのはなぜですか。** Standard と Deep だけで実行し、Quick では未確認範囲として記載します。

**報告書は証明書ですか。** 違います。人が判断するための根拠です。検証役、検証スクリプト、未確認範囲の表は見逃しや判断の誤りを減らしますが、なくしはしません。

## 関連ページ

- [インストール](install.md)
- [スキャナ](scanners.md)
- [`platforms.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/reference/tooling/platforms.md)
- [コントリビュート](contributing.md)：不具合の報告
