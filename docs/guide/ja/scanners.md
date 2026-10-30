# スキャナ

[English](../scanners.md) · **日本語**

スキャナが得意なのは、機械的に見つかるもの、数の多いもの、回帰を確認できるものです。設計上の欠陥は見えないため、それはレビューレーンが担当します。スキャナの検出は、モデルがコードを読んで確認するまで手がかりにすぎません。

## 固定したスキャナ

スキルはバージョンを固定した <!--n:scanners-->8<!--/n--> 種のスキャナを実行します。どれを各リポジトリに使うかは `detect_stack.py` が決めます。

| スキャナ | イメージ | 対象 | 実行する条件 |
|---|---|---|---|
| Gitleaks | `ghcr.io/gitleaks/gitleaks` | 秘密情報：git の全履歴（すべての参照）と、追跡していないファイルを含む作業ツリー | 常に |
| Semgrep | `semgrep/semgrep` | コードのパターン（SAST）。ルールパックは `p/default`、メトリクス送信はオフ | 対応する言語があるとき |
| Trivy | `aquasec/trivy` | 依存関係の CVE、イメージ、IaC と Dockerfile の設定ミス | ロックファイルまたはコンテナがあるとき |
| OSV-Scanner | `ghcr.io/google/osv-scanner` | ロックファイルに基づく正確な CVE と、悪意のあるパッケージ（`MAL-*`）の勧告 | ロックファイルがあるとき |
| Checkov | `bridgecrew/checkov` | Terraform、CloudFormation、Kubernetes、Helm、Dockerfile、GitHub Actions | IaC またはコンテナがあるとき |
| hadolint | `hadolint/hadolint` | Dockerfile の静的検査と ShellCheck | Dockerfile があるとき |
| zizmor | `ghcr.io/zizmorcore/zizmor` | GitHub Actions のワークフローのセキュリティ | `.github/workflows` があるとき |
| mobsfscan | `opensecurity/mobsfscan` | Android と iOS のソース | モバイルアプリのとき |

バージョンはピンの更新のたびに変わるため、このガイドには載せていません。現在のバージョンは [README のスキャナの表](https://github.com/nguyenhx2/agent-security-audit/blob/main/README.ja.md#最新に追従するツール)にあり、`run_scanners.py --list` を実行すると、インストールしたスキルが使う `image:tag@sha256:digest` の正確なピンと、その検証日が表示されます。

`detect_stack.py` は言語ごとの SAST の未対応範囲も報告します。Semgrep CE は Dart（Flutter）、Lua、Clojure、Objective-C、Erlang、Perl、VB.NET、F#、Groovy、PowerShell、Razor や JSP のテンプレートにはほとんど、またはまったく対応していません。これらは該当するレーンで手作業でレビューするか、「対象外」と明記します。対応していない言語についてスキャナが何も言わないことには、何の意味もありません。

## コンテナ、ネイティブ、なし

`run_scanners.py --mode auto`（既定）は次の順でモードを選びます。

1. **コンテナ。** コンテナエンジンが応答すれば（`--engine auto` は Docker、次に Podman を試します）、各スキャナを固定したイメージから実行し、リポジトリは読み取り専用でマウントします。
2. **ネイティブ。** そうでなければ、`PATH` にあるスキャナをそのまま実行します。
3. **なし。** どちらもないスキャナは `skipped` となり、未確認範囲に列挙します。実行しなかったスキャナを「問題なし」と報告することはありません。

`--mode container` はエンジンを必須とし、応答するエンジンがなければ終了コード 3 で終わります。`--engine docker|podman` でエンジンを指定できます。

実行時に強制する規則：

| 規則 | 理由 |
|---|---|
| ソースは読み取り専用でマウントし、`--out` はリポジトリの外でなければならない | 監査する側は製品のソースに対して読み取り専用であるため |
| スキャンの前にマウントを確認する（ファイル数が 0 より多いこと） | 空のマウントで検出 0 件というのは、典型的な誤った「問題なし」であるため |
| SELinux と Podman では `label=disable` を使い、`:z` や `:Z` は使わない | ラベルの付け替えは、監査対象リポジトリに拡張属性を書き込むことになるため |
| Linux と macOS ではコンテナを現在のユーザーとして実行し、rootless の Podman では `--userns=keep-id` を使う | 後片付けを妨げる root 所有の出力を残さないため |
| Gitleaks と hadolint はネットワークなしで実行する | ネットワークが不要なため |
| リポジトリ自身のスキャナ設定は使わない（Gitleaks の許可リスト、`nosem` コメント、zizmor の設定、osv-scanner の設定） | リポジトリが自分のスキャナを黙らせることはできないようにするため。無効化できないもの（`.gitleaksignore`、`.checkov.yaml`、`.semgrepignore`）は未確認範囲に列挙します |
| Semgrep は `--metrics off` と `p/default` で実行し、`auto` は使わない | `auto` はプロジェクトの URL をレジストリに送るため |
| Gitleaks は `--redact` で実行し、正規化した出力では長いトークンをマスクする | 秘密情報をやり取りの記録にも報告書にも入れないため |
| タグに加えてダイジェストを記録し、`:latest` は拒否する | タグの付け替えで実行内容が変わらないようにするため |
| コンテナのコマンドは、シェルを通さず Python の `subprocess` で組み立てる | Git Bash のパス変換でマウントするパスが書き換えられないようにするため |

実行結果は `work/<repo>/raw/<tool>.(sarif|json)` と `work/<repo>/scanners.json` に書き出します。`scanners.json` には、モード、エンジン、イメージのダイジェストまたはネイティブ版のバージョン、監査したコミット、未確認範囲が記録されます。そのあと `normalize_findings.py` がすべてを `candidates.jsonl` と `summary.md` にまとめます。

## ピンをダイジェストにする理由

各ピンは `image:tag@sha256:digest` の形で、タグは人が読むため、ダイジェストは再現性のためにあります。ルールパックや脆弱性データベースは独自に更新されますが、スキャナの本体と組み込みのルールは 2 回の実行の間で変わりません。これが最も効くのが [Phase 8](rescan.md) です。再スキャンは同じダイジェスト（`scanners.json` にある `--pin tool=<image:tag@sha256>`）を使うため、修正は欠陥を見つけたのと同じルールで判定され、指摘が閉じるのは、再現しなくなり、かつその検出ルールがまだ有効なときだけです。

## 新しいスキャナを確認する

```bash
py -3 <skill_dir>/scripts/run_scanners.py --check-updates [--json PATH] [--offline]
```

Docker Hub と GHCR に、固定した各イメージの最新の安定タグを問い合わせ、スキャナごとに「最新」「新しいバージョンあり」「問い合わせ失敗」を表示します。報告するだけで、イメージを取得することも、ピンを変えることもなく、終了コードは 0 です。Phase 0 でスキャナのピンが 90 日より古い場合、スキルはこれを実行し、新しいタグがあるスキャナを 1 行で伝えることがあります。監査そのものは検証済みのピンで行います。

新しいバージョンを意図的に、その実行だけで試すには次のようにします。

```bash
py -3 <skill_dir>/scripts/run_scanners.py <repo> --out <work>/<repo> --pin trivy=aquasec/trivy:<tag>@sha256:<digest>
```

`:latest` やタグのないピンは拒否します。

## 毎週の update-pins ワークフロー

ピンが動くのは、リポジトリ上で、メンテナがレビューするプルリクエストを通したときだけです。`update-pins` ワークフローが、毎週月曜 02:17 UTC にそのプルリクエストを準備します。

![スキャナの更新：毎週確認し、検証し、レビューを経て取り込む。毎週月曜 02:17 UTC または手動実行で起動し、update_pins.py --check がスキャナごとに最新の安定タグを取得する。公開から 7 日待ち、ダウングレードはしない。smoke_scanners.py が各候補イメージを、欠陥を 1 つ仕込んだフィクスチャで実行し、今も検出できることを確かめる。update_pins.py --write が両エディションのピンを更新し、ゲートを実行する。ブランチ bot/scanner-pins にラベル scanner-pins のプルリクエストを 1 件作り、メンテナがレビューして手でマージする。自動マージは一切しない。その後 z リリース。失敗すれば Issue「update-pins failed」を 1 件作る。監査の実行中にピンが勝手に動くことはない。](../../assets/scanner-update-flow.ja.svg)

1. **確認。** `update_pins.py --check` が各レジストリに新しい安定タグを問い合わせます。タグを提案するのは、公開から 7 日たってから（クールダウン）です。レジストリに置かれた不正なイメージは、たいてい数日のうちに見つかって削除されるため、クールダウンでその期間を避けます。リリース候補、ベータ、`latest`、ダウングレードは提案しません。レジストリへの問い合わせが失敗すると実行全体が失敗するため、障害が「すべて最新」と誤って読まれることはありません。
2. **スモークテスト。** `smoke_scanners.py` が各候補イメージを、そのスキャナ用に欠陥を仕込んだフィクスチャで実行します。新しいバージョンがその欠陥を見つけられない、またはクラッシュした場合は、そこで止まります。
3. **書き込みとゲート。** `update_pins.py --write` が両エディションのピンを更新し、その結果に対して両方のセルフテスト、オフライン評価、エディションの一致の確認、プラグインのマニフェストの確認、数値の確認、リリースの検証を実行します。
4. **プルリクエスト。** 変更をブランチ `bot/scanner-pins` に置き、ラベル `scanner-pins` のプルリクエストを 1 件作ります（開いているものがあれば更新します）。タイトルには各スキャナの変更（例：`scanner pins: trivy <old> -> <new>, ...`）を並べ、本文にはリリースノートへのリンク、CHANGELOG の下書き、スモークテストの結果表を載せます。**自動でマージすることはありません。**
5. **失敗時の Issue。** どこかの段階で失敗すると、失敗した段階、実行へのリンク、次にすべきことを書いた Issue `update-pins failed`（ラベル `scanner-pins`）を 1 件作ります。以後の失敗はその Issue にコメントで追記し、次に成功した実行がそれを閉じます。どちらの場合も、マージは行いません。

マージしたピンの更新は `z` のバージョンとしてリリースされ、新しいピンが利用者に届くのはそのリリースからです。ワークフローを手動で実行する方法、手元で実行するコマンド、終了コードは[スキャナのピン更新](https://github.com/nguyenhx2/agent-security-audit/blob/main/docs/RELEASING.ja.md#スキャナのピン更新)にあります。

## 任意の追加ツール

実行の仕組みには組み込んでいません。技術スタックに応じて必要なときに自分で実行し、監査する側が網羅性の表に明記します。TruffleHog（秘密情報の有効性の確認。提供者に接続するため、承認がない限り `--no-verification` を使います）、Bandit（Python）、gosec と govulncheck（Go）、Brakeman（Rails）、KICS（IaC）、Grype と Syft（SBOM）、OWASP Dependency-Check（NVD の API キーが必要）です。

## 関連ページ

- [`scanners.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/reference/tooling/scanners.md)：ツールの一覧と実行時の規則
- [`platforms.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/reference/tooling/platforms.md)：OS ごとのエンジンとネイティブ版のインストール
- [再スキャンと修正の確認](rescan.md)
- [トラブルシューティングと FAQ](troubleshooting.md)
