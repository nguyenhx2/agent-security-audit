# プラットフォーム - Windows、macOS、Linux（WSL を含む）

まず `env_check.py` を実行し、その `choices` を使う。数秒でホストを調べ（インストールもネットワーク接続もしない）、
この OS 向けの Python コマンド、スキャナの方式、待機ループ、パスの形式、Excel の検証方法、
ツールごとのインストール手段を出力する。下表は、調査結果がはっきりしない場合のフォールバックである。

## 判断表

| | Windows | macOS | Linux / WSL |
|---|---|---|---|
| スクリプト用の Python | `py -3`（ランチャー）、なければ `python`。MS Store のスタブは決して使わない | `python3` | `python3` |
| シェル | Bash ツール（Git Bash）- 事前承認済み。PowerShell は確認を求められる | bash / zsh | bash / sh |
| `scanners.json` の待機（バックグラウンド） | Git Bash：`until [ -f "<f>" ]; do sleep 5; done`。PowerShell のみの場合：`while (-not (Test-Path "<f>")) { Start-Sleep 5 }` | `until [ -f "<f>" ]; do sleep 5; done` | 同左 |
| スクリプトのパス引数 | `C:/Users/...`（スラッシュ区切り）。Git Bash の `/c/Users/...` はスクリプトが変換するが、`/tmp` は決して使わない（Write ツールと Python で解決先が異なる） | `/Users/...` | `/home/...`。WSL：Windows のドライブは `/mnt/c/...` |
| コンテナエンジン | Docker Desktop、Podman Desktop、Rancher Desktop | Docker Desktop、OrbStack、Colima、Podman machine、Rancher Desktop | Docker Engine（rootful / rootless）、Podman。WSL：Docker Desktop の WSL 統合、または WSL 内のエンジン |
| Excel の検証 | `excel-com`（`render_xlsx.py --verify`） | `libreoffice` | `libreoffice` |
| git | Git for Windows | Xcode CLT の `git` または `brew install git` | ディストリビューションの `git` |

スクリプトのプレフィックスは厳密に `<python> "${CLAUDE_SKILL_DIR}/scripts/<script>.py"` のままにする - 事前承認された
`allowed-tools` のパターンはこの形に一致する。スクリプトは `__pycache__` を自分で無効化する（`-B` は不要）。

## コンテナエンジンの注意点

- 選択：`run_scanners.py --engine auto` = docker のデーモンが応答すれば docker、なければ podman（実体が podman である
  `docker` は podman として扱う）。強制するには `--engine docker|podman`。Exit 3 = 応答するエンジンがない：
  どれがインストール済みで停止中かをユーザーに伝える（`env_check` -> `engine_installed_not_running`）。
- ファイル共有：エンジンから見えるのは共有されたホストのフォルダのみ。Docker Desktop（macOS）は既定で `/Users`、
  `/Volumes`、`/private`、`/tmp` を共有する。Colima と Lima は `$HOME`（と `/tmp/colima`）をマウントする - リポジトリと
  `--out` は `$HOME` 配下に置く。OrbStack は Mac のファイルシステム全体を共有する。podman machine（macOS）は `/Users`、`/private`、`/var/folders` を共有する。
  共有の不足は exit 4（マウントの検証：0 ファイル）として現れる - 共有を修正し、そのスキャン結果は決して信用しない。
- root 所有の出力（Linux の rootful Docker）：run_scanners はすべてのコンテナを `HOME=/tmp` 付きで自分の `uid:gid` で
  実行し、trivy のキャッシュボリュームを 1 回だけ chown し、終了後はまだ他者所有のまま残っているものを
  ピン留め済みのイメージで chown して戻す。rootless Docker：コンテナの root は自分自身（`--user` なし）。Podman rootless：
  `--userns=keep-id`。判断内容は `scanners.json` -> `container` に記録される。
- SELinux が enforcing（Fedora、RHEL、podman machine）：`--security-opt label=disable`。`:z` / `:Z` は決して使わない -
  再ラベル付けは監査対象リポジトリに xattr を書き込む。
- WSL：Linux の `python3` と Linux の docker CLI を、`/mnt/c/...` または `~/...` のパスで使う。WSL から呼び出す Windows の
  `docker.exe` には、代わりに `C:/...` のパスが必要。`/mnt/c` 上のリポジトリはスキャンが遅い。
- Windows：変更なし - Docker Desktop が所有者を対応付ける。`--user` なし。

## ネイティブのスキャナのインストール（ユーザーが同意した場合のみ - インストールするかどうかはユーザーが決める）

| ツール | Windows | macOS | Linux |
|---|---|---|---|
| gitleaks | `winget install Gitleaks.Gitleaks` / scoop / choco | `brew install gitleaks` | pacman、brew、`go install github.com/zricethezav/gitleaks/v8@v8.30.1`、リリースバイナリ |
| semgrep | コンテナまたは WSL（ネイティブはベータ版：`pipx install semgrep==1.182.1`） | `brew install semgrep` / pipx | `pipx install semgrep==1.182.1` |
| trivy | `winget install AquaSecurity.Trivy` / scoop / choco | `brew install trivy` | aquasecurity の apt / rpm リポジトリ、pacman、リリースバイナリ |
| osv-scanner | `winget install Google.OSVScanner` / scoop | `brew install osv-scanner` | `go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.0`、リリースバイナリ |
| checkov | `pipx install checkov==3.3.30` | brew / pipx | pipx |
| zizmor | `pipx install zizmor==1.31.1` | brew / pipx | pipx、pacman、cargo |
| mobsfscan | `pipx install mobsfscan==1.0.1` | pipx | pipx |
| hadolint | scoop / リリースバイナリ | `brew install hadolint` | リリースバイナリ、brew |

pipx 自体：`py -m pip install --user pipx`（Windows）、`brew install pipx`、`apt install pipx` /
`dnf install pipx`。リリースバイナリ：プロジェクトの GitHub releases からダウンロードし、チェックサムを検証する。

## Excel の検証の代替手段

1. `excel-com`（Windows + Excel）：`render_xlsx.py <report.md> --verify` - 実際の Excel による再計算。
2. `libreoffice`（PATH 上の `soffice`、または `/Applications/LibreOffice.app/Contents/MacOS/soffice`）：
   `--verify` が自動的に選ぶ（または `--verify-with libreoffice`）。使い捨てのプロファイル（常に再計算）でヘッドレス実行し、
   その後、数式エラー、合計、4 つのグラフを確認する。
3. `none`：`--verify` なしでレンダリングし（`VERIFY SKIPPED` を出力、exit 0）、回答で「ワークブックは
   再計算していない」と伝える。openpyxl がない場合：`<python> -m pip install openpyxl`（先に確認する）。
