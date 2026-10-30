# インストール

[English](../install.md) · **日本語**

インストールの方法は 2 つあります。Claude Code のプラグインとして入れる方法と、リリースの zip から入れる方法です。どちらも `security-audit` という名前の同じスキルになります。

## 必要なもの

| 必要なもの | 詳細 |
|---|---|
| Claude Code | スキルは Claude Code の機能（`when_to_use`、`argument-hint`、`effort` と `omitClaudeMd` を持つ名前付きサブエージェント）を使います。古いバージョンは後の 2 つを無視します。 |
| Python 3.9 以上 | 標準ライブラリのみを使います。Windows では `py -3`、macOS と Linux では `python3` です。 |
| `openpyxl` | Excel の報告書にだけ必要です：`python -m pip install openpyxl`（Windows では `py -3 -m pip install openpyxl`）。 |
| git | Windows では Git for Windows、macOS では Xcode のコマンドラインツールまたは `brew install git`、Linux ではディストリビューションのパッケージです。 |
| コンテナエンジン（任意） | Docker または Podman で固定したスキャナを実行します。なければネイティブ版のスキャナでも動き、どちらもなければコードを読むだけの監査になり、すべてのスキャナを未確認範囲として明記します。 |
| Excel または LibreOffice（任意） | ブックを再計算する `render_xlsx.py --verify` にだけ必要です。 |

### OS ごとの違い

| | Windows | macOS | Linux と WSL |
|---|---|---|---|
| Python のコマンド | `py -3`（ランチャー）、なければ `python`。Microsoft Store のスタブは使いません | `python3` | `python3` |
| スキルが使うシェル | Bash ツール（Git Bash）。PowerShell の呼び出しは許可を求められます | bash または zsh | bash または sh |
| スクリプトに渡すパス | `C:/Users/...`（スラッシュ区切り）。Git Bash の `/c/Users/...` も受け付けます。`/tmp` は使いません | `/Users/...` | `/home/...`。WSL では Windows のドライブは `/mnt/c/...` |
| コンテナエンジン | Docker Desktop、Podman Desktop、Rancher Desktop | Docker Desktop、OrbStack、Colima、Podman machine、Rancher Desktop | Docker Engine（rootful または rootless）、Podman。WSL では Docker Desktop の WSL 連携か、WSL 内のエンジン |
| Excel の検証 | COM 経由の Excel | LibreOffice | LibreOffice |

コンテナエンジンの注意点を含む完全な表は [`platforms.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/reference/tooling/platforms.md) にあります。

## 方法 1：Claude Code のプラグイン

Claude Code で次のように入力します。

```text
/plugin marketplace add nguyenhx2/agent-security-audit
/plugin install security-audit@agent-security-audit
```

プラグインは英語版です。あとから更新するときは `/plugin update` を実行します。

## 方法 2：リリースの zip

[最新リリース](https://github.com/nguyenhx2/agent-security-audit/releases/latest)から zip を入手し、スキルのフォルダに展開します。どのリリースにもバージョン番号のない zip の複製があるため、次の固定リンクは常に最新版を指します。

- 英語版：`https://github.com/nguyenhx2/agent-security-audit/releases/latest/download/security-audit.zip`
- 日本語版：`https://github.com/nguyenhx2/agent-security-audit/releases/latest/download/security-audit-ja.zip`

macOS、Linux、WSL、Git Bash の場合：

```bash
unzip security-audit-X.Y.Z.zip -d ~/.claude/skills/
```

Windows PowerShell の場合：

```powershell
Expand-Archive security-audit-X.Y.Z.zip -DestinationPath $HOME\.claude\skills\
```

`X.Y.Z` は入手したバージョンに置き換えてください。zip の中身は `security-audit/` フォルダ 1 つだけで、その中の `VERSION` ファイルを見れば、どのリリースを入れたかがいつでも分かります。

### どちらの zip を選ぶか

| zip | 選ぶ場面 |
|---|---|
| `security-audit-X.Y.Z.zip`（英語版） | 推奨です。報告書は英語、日本語、またはその両方で書けます。 |
| `security-audit-ja-X.Y.Z.zip`（日本語版） | スキル自体の手順書と参照資料を日本語で読み、保守したいチーム向けです。 |

両エディションのコードは同じで、同じセルフテストに合格します。どちらも `security-audit` としてインストールされるため、入れるのはどちらか一方だけです。日本語の報告書が必要なだけなら、英語版で十分です。

### ダウンロードを検証する

どのリリースにも `SHA256SUMS` があり、すべての zip（バージョン付きと、バージョンなしの複製）の SHA-256 が載っています。zip と同じ場所にダウンロードしてから、次を実行します。

```bash
# Linux、WSL、Git Bash
sha256sum -c SHA256SUMS --ignore-missing

# macOS
shasum -a 256 security-audit-X.Y.Z.zip     # SHA256SUMS の該当行と比べる
```

```powershell
# Windows PowerShell
Get-FileHash security-audit-X.Y.Z.zip -Algorithm SHA256   # SHA256SUMS の該当行と比べる
```

GitHub CLI を使えば、両方を一度に取得できます：`gh release download vX.Y.Z -R nguyenhx2/agent-security-audit -p "security-audit-X.Y.Z.zip" -p SHA256SUMS`。

## env_check.py で環境を確認する

スキルはどの監査でも、最初に `env_check.py` を実行します。自分で実行すれば、スキルが何を見つけるかを事前に確認できます。zip でインストールした場合：

```bash
py -3 ~/.claude/skills/security-audit/scripts/env_check.py --pretty      # Windows
python3 ~/.claude/skills/security-audit/scripts/env_check.py --pretty    # macOS、Linux、WSL
```

数秒でホストを調べ、何もインストールせず、ネットワークも使いません。出力の JSON の最後に `choices` ブロックがあります。

| 項目 | 分かること |
|---|---|
| `scanner_mode` | `container`（エンジンが応答する）、`native`（スキャナが `PATH` にある）、`reading-only`（どちらもない）。エンジンが入っているのに動いていなければ、`engine_installed_not_running` にその名前が出ます。 |
| `script_prefix` | スキルが使う Python のコマンド（例：`py -3`）。 |
| `wait_loop` | このシェルでバックグラウンドのスキャナを待つ方法。 |
| `path_format` | スクリプトの引数に使うパスの形式。 |
| `excel_verify` | Excel のブックを再計算する方法：Excel、LibreOffice、または再計算なし。 |
| `install` | エンジンがないときの、足りないスキャナのツールごとのインストールコマンド。 |
| `notes` | 警告（例：`openpyxl missing`、`SELinux enforcing`）。 |

### コンテナエンジン、ネイティブ版、読むだけの監査

- **コンテナエンジン（推奨）。** Docker または Podman が、ダイジェストで固定したイメージから各スキャナを実行し、リポジトリは読み取り専用でマウントします。ほかに入れるものはありません。
- **ネイティブ版のスキャナ。** エンジンがなければ、`PATH` にあるスキャナを使います。OS ごとのインストールコマンドは `env_check.py` の `install` と [`platforms.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/reference/tooling/platforms.md) にあります。ソフトウェアを入れるかどうかは利用者が決めることなので、スキルは必ず先に確認します。
- **読むだけの監査。** どちらもなくても監査は動きます。モデルがコードを読み、プラットフォーム一覧と脅威情報もそのまま使え、すべてのスキャナを未確認範囲として列挙します。実行しなかったスキャナを「問題なし」と報告することはありません。

詳しくは[スキャナ](scanners.md)を参照してください。

## サブエージェントを入れる

Standard と Deep では、4 つの名前付きサブエージェント（`security-audit-recon-mapper`、`security-audit-lane-reviewer`、`security-audit-finding-verifier`、`security-audit-report-translator`）を使います。スキルは Phase 0 で `install_agents.py` を実行して自分で入れます。書き込むのは `~/.claude/agents/security-audit/*.md` だけで、そのことを 1 行で伝えます。

手動で入れる、または確認する場合（zip でインストールした場合のパス）：

```bash
py -3 ~/.claude/skills/security-audit/scripts/install_agents.py --check   # 0 = 最新が入っている、1 = ない、または古い
py -3 ~/.claude/skills/security-audit/scripts/install_agents.py           # インストールまたは更新（何度実行しても同じ結果）
```

既存の agents フォルダの変更は、Claude Code が数秒で読み込みます。セッション中にフォルダを新しく作った場合は、再起動するまで新しい名前は現れません。それまでの間、スキルは同じ指示書を使う汎用サブエージェントで代用します。結果は同じで、トークンが多めにかかります。

`install_agents.py` は自分が書いたファイル（どれにも `installed-by: security-audit` の印があります）だけを書き換えます。同じ名前でも自分が書いていないファイルには手を付けず、そのことを報告します。

## 更新する

- **プラグイン：** `/plugin update`。
- **zip：** 新しい zip を入手し、古い `~/.claude/skills/security-audit/` フォルダを削除してから展開します。そのあと `install_agents.py` を一度実行して（または次の Standard か Deep の監査に任せて）、サブエージェントを新しいバージョンに合わせます。

修正が入るのは最新のリリースだけです（[SECURITY.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/SECURITY.md)）。

## アンインストールする

1. サブエージェントを削除します：`py -3 <skill_dir>/scripts/install_agents.py --uninstall`（スキルを削除する前に実行します）。
2. スキルを削除します。プラグインなら `/plugin uninstall security-audit@agent-security-audit`、zip なら `~/.claude/skills/security-audit/` を削除します。
3. 必要なら、アドバイザリフィードのキャッシュ `~/.cache/security-audit/intel` も削除します。

監査フォルダ（監査した各リポジトリの隣にある `<project>-security-audit/`）は利用者のものです。不要になったら削除してください。

## 関連ページ

- [初めての監査](first-audit.md)
- [トラブルシューティングと FAQ](troubleshooting.md)
- [リリースの手順](https://github.com/nguyenhx2/agent-security-audit/blob/main/docs/RELEASING.ja.md)：リリースに含まれるもの
