# 指摘事項と報告書

[English](../reports.md) · **日本語**

監査は、根本原因の欠陥ごとに 1 つのファイルと、言語ごとに 1 組の報告書を作ります。指摘事項ファイルと Markdown の報告書が正本で、HTML と Excel はそこから描画します。

## 指摘事項ファイル

パスは `<audit_dir>/findings/<lang>/<repo>/find-<repo>-NNN.md` で、フロントマターの ID は `FIND-<REPO>-NNN` です。ファイル名は ID を小文字にしたものです。ID とアンカーはどの言語でも同じです。

指摘事項 1 件は根本原因 1 つで、是正策ごとに重複を除きます。パッケージ 1 つの更新（1 つのパッケージにある 20 件の CVE は 1 件）、N 個のコントローラで繰り返される同じ確認漏れ（すべての箇所を列挙）、ランタイムのバージョンの CVE をすべて解消する Dockerfile の変更 1 つ、といった単位です。スキャナの検出は根本原因に添える根拠であって、別々の指摘事項にはしません。

### フロントマター

```yaml
---
id: FIND-SHOPAPI-001
repo: shop-api
severity: P1
confidence: confirmed
kind: security
standard: OWASP Top 10
standard_version: "2025"
requirement_id: A01
also_maps_to: "OWASP ASVS 5.0.0 V8.2; CWE-639"
cwe: CWE-639
confirmed_by: manual review
status: open
found: 2026-10-30
verified: n/a
---
```

| 項目 | 値 |
|---|---|
| `id` | `FIND-<REPO>-NNN`。監査の中で一意で、変わりません |
| `repo` | リポジトリのフォルダ名、または `cross-repo` |
| `severity` | `P0`、`P1`、`P2`、`Info` |
| `confidence` | `confirmed`、`likely`、`needs-runtime-check` |
| `kind` | `security`、`sensitive-data-at-rest`、`secret`、`supply-chain`、`configuration`、`privacy`、`performance`、`quality` |
| `standard`、`standard_version`、`requirement_id` | 基準の正式名称、版、要件。[基準と業種](standards-and-sectors.md)の引用の規則を参照してください。 |
| `also_maps_to` | 任意。追加の引用で、それぞれに版を付けます |
| `cwe` | `CWE-NNN` または `n/a` |
| `shares_anchor_with` | 任意。同じ行を別の根本原因で引用する他の指摘事項の ID |
| `confirmed_by` | スキャナとルール、`manual review`、またはその両方（例：`semgrep <rule-id> + manual review`）。値は監査の言語で書きます |
| `status` | `open`（既定）、`in-progress`、`closed`、`accepted-risk`、`false-positive` |
| `found` | 見つけた日 |
| `verified` | 再スキャンで修正を確認した日（[Phase 8](rescan.md)）。未確認なら `n/a` |

フロントマターの値は常に英語のコードで、報告書では報告書の言語で表示します（例：`open` は「未対応」、`confirmed` は「確認済」、`needs-runtime-check` は「実行時確認要」）。

### 重大度

重大度は、悪用されたときの影響と到達可能性で決め、スキャナの表現には左右されません。

| 重大度 | 意味 |
|---|---|
| **P0 / 致命的** | 今すぐ到達できる直接的かつ重大な侵害。カード会員データや要配慮情報の漏えい、認証情報の侵害、機微データや管理機能への認証なしのアクセス、RCE、資金の窃取。リリースを止めるべきもの。 |
| **P1 / 重大** | 現実的な条件（認証済みの攻撃者、前提条件 1 つ）で悪用できる深刻な弱点、または機能していると思われているのに機能していない制御。 |
| **P2 / 軽微** | 影響範囲が限られる、または前提条件が起こりにくい実在の欠陥。多層防御の不足。 |
| **情報（Info）** | 直接のセキュリティ上の影響はないもの。堅牢化、衛生、網羅性についての注記。 |

交渉の余地のない下限が決まっている条件もあります。たとえば、承認後に保存した CVV や PIN は暗号化されていても P0、平文のカード番号の保存は P0、クライアントの成果物に含まれた有効な認証情報は P0、インストールされた悪意のある依存関係（`MAL-*`）は P0、機能していないセキュリティ制御や失敗時に許可してしまう認可の処理は少なくとも P1 です。P0 から P2 の指摘はすべて、誰が何を得るかを `主体 -> 越える制御 -> 影響を受ける資源` の形で示します。一覧の全体は [`triage.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/reference/method/triage.md) にあります。

### 確度

| 確度 | 意味 |
|---|---|
| `confirmed`（確認済） | コードの経路を最初から最後まで読んだ。ソースからシンクまで、有効な制御がない |
| `likely`（可能性高） | パターンがあり、到達できる可能性が高い。1 つのつながりが未証明で、指摘事項にはそれがどこかを書く |
| `needs-runtime-check`（実行時確認要） | 静的な監査では見えないデプロイや実行時の状態に依存する。検証の節に、判断の決め手になる事実と、それを確認できる人を書く |

### 本文

本文は 6 つの節で、見出しは言語に合わせます。

| 英語 | 日本語 | 内容 |
|---|---|---|
| Location | 該当箇所 | リポジトリからの相対パスの `path:line` アンカーと、その役割（ソース、シンク、欠けている制御、列）。データそのものは書きません。 |
| What it is | 内容 | 根本原因。多くの呼び出し箇所が共有する場合は、そのすべての箇所 |
| Why it matters | 影響 | 影響、悪用できる人、到達されるもの |
| Evidence | 根拠 | エントリポイントからシンクまでの経路、スキャナの検出、`likely` の場合は未証明のつながり |
| Remedy | 是正策 | この技術スタックに合わせた具体的な修正。監査する側は修正しません。 |
| Verification | 検証 | 指摘を閉じる方法。修正を証明する再スキャンまたは読み直し |

コミットされた秘密情報の是正策は、提供者側でのローテーションで、必要なら履歴の削除がその後に続きます。ファイルを削除しても何も直りません。指摘事項は欠陥と是正策の水準で書き、攻撃コードは書きません。

## Markdown の報告書

`reports/md/security-audit-report_<project>_<ts>[_<lang>].md` は `build_report.py` が組み立てます。表と件数は指摘事項ファイルから作り、モデルが書くのは説明文（エグゼクティブサマリー、対応事項、リポジトリ横断の注記）だけです。章の構成：

1. エグゼクティブサマリー
2. 対象範囲と未カバー領域（「AI・エージェントの構成一覧」と「プラットフォームのバージョンと脅威情報」：コンポーネント、勧告 ID、確認したフィード、取得できなかったフィード、フィードの日付を含む）
3. 指摘事項（重大度別。理由付きの「否定された候補（誤検知）」を含む）
4. 保存データの機微情報（必須。何も見つからなくても記載）
5. リポジトリ横断の指摘
6. 性能とコード品質
7. 利用者が実施すべき対応（順序と前提関係）
8. 手法と限界（必須）

冒頭には、スキルのバージョン、基準の検証日、日時、リポジトリごとに監査したコミットを記録します。これらは最初の組み立て時に固定するため、再生成や翻訳でずれることはありません。

## 検証スクリプト

描画の前に、`validate_findings.py` が終了コード 0 で終わる必要があります。確認する内容：

- どの指摘事項ファイルもフロントマターが揃い、値が許された集合の中にある
- ID だけの引用がない：`standard_version` があり、プレースホルダではない。正式名称でない基準名には警告を出す
- すべての `path:line` アンカーが、実在するファイルとその範囲内の行を指す（履歴にだけある秘密情報は `history:<commit>` で示す）
- `{{placeholders}}` がどこにも残っていない
- 指摘事項にも報告書にも、カード番号らしき値（Luhn 検査に合う 13-19 桁）や秘密情報がない
- 報告書に必須の章があり、重大度の件数と表が指摘事項ファイルと一致する
- ID の重複や、（file:line、要件）の組の重複がない
- 日本語（中国語、韓国語も同じ）の一式では、指摘事項に英語の文章があるとエラーになる
- 脆弱性情報の照合で見つかった、悪用が確認された CVE やサポート終了の deploy コンポーネントが、どの指摘事項にもなく、理由付きの反証にもない場合は警告を出す

スキルはすべての ERROR を直し、合格するまで再実行します。WARN は直すか、問題ない理由を説明します。

## HTML の報告書

`render_html.py` は `reports/html/` にオフラインで開ける 1 つのファイルを書き出します。重大度のカード（クリックで絞り込み）、指摘事項の本文まで対象にする全文検索、重大度・リポジトリ・種類・確度・状態による絞り込み、並べ替えできる列、展開できる行、`#FIND-ID` のリンク、絞り込んだ結果の CSV 出力、目次付きの報告書全文を備えています。ライトとダークの表示に対応し、印刷にも向いています。監査から得た内容はすべて HTML としてエスケープし、外部のリソースは読み込まず、厳格なコンテンツセキュリティポリシーを適用します。

![HTML 報告書：重大度のカード、絞り込み、指摘事項の表](../../assets/screens/html-report.png)

![HTML 報告書：展開した指摘事項](../../assets/screens/html-finding.png)

## Excel のブック

`render_xlsx.py` は `reports/xlsx/` に 4 つのシートを持つブックを書き出します。

| シート | 内容 |
|---|---|
| Summary | プロジェクトの情報、統計（COUNTIFS の数式なので、編集に追従します）、グラフ 4 種：重大度別、リポジトリ × 重大度、種類別、状態別 |
| Findings | 指摘事項 1 件につき 1 行。重大度、確度、状態、種類、リポジトリ、基準のドロップダウン。進捗管理用の担当者・期限・メモの列。フィルタと固定した見出し行 |
| Coverage | リポジトリごとのスキャナ（状態、イメージ、ダイジェスト、秒数）、未確認範囲、スイープの統計 |
| Master | すべてのドロップダウンの元になる値の一覧（名前付き範囲） |

文字列はマスクし、`=`、`+`、`-`、`@` で始まるセルは数式ではなく文字列として保存します。`--verify` は Excel（Windows）または LibreOffice でブックを再計算し、数式のエラーや指摘事項ファイルと合わない合計があれば失敗します。どちらもなければ `VERIFY SKIPPED` と表示し、返答で「再計算していない」と伝えます。`openpyxl` が必要です。

![Excel のブック：グラフ 4 種付きの Summary シート](../../assets/screens/excel-summary.png)

画面例は、ベンチマークで練習用に意図的に脆弱にしたアプリ DVWA を実際に Quick で監査した結果で、報告書の言語は英語です。

## 翻訳

指摘事項は `work/findings.json` と `work/narrative.json` として、1 つの正本の言語で一度だけ書きます。正本の言語は、Standard と Deep では英語です（報告書の言語を 1 つだけ選んだ場合はその言語）。選んだ他の言語は、正本の言語の報告書を作るのと並行して、`report-translator` サブエージェントがこの 2 つのファイルから作ります。`new_finding.py --source` がコード、ID、`path:line` をすべて正本から写すため、変わるのは文章だけです。そのあと言語ごとに組み立て、検証し、描画します。報告書の言語が 1 つだけなら、検証役が最初からその言語で下書きし、翻訳は行いません。

## work/ の整理

`prune_work.py` は、選んだすべての言語と形式を作って検証し終えたあと、最後に実行します。既定では、実行後に誰も読まない中間ファイル（スキャナの生の出力、レーンパック、レーンのメモ、ダイジェスト、ルートマップ、偵察のメモ）を削除し、再生成、後からの翻訳、[Phase 8 の再スキャン](rescan.md)に必要なもの（`findings*.json`、`narrative*.json`、`report-settings.json`、`profile.md`、`scanners.json`、`sweep.json`、`platform.json`、`intel.json`、`lanes/candidates.md`、`lanes/verifier.md`）を残します。通常 3 MB が 0.4 MB 程度になります。知らないファイルには手を付けません。

| スイッチ | 効果 |
|---|---|
| `--keep-work` | すべて残す（調査やスキルのデバッグ用） |
| `--purge-work` | `work/` フォルダ全体を削除する。報告書の再生成や翻訳はできなくなり、Phase 8 は新しい監査になります。 |
| `--dry-run` | 削除するものを一覧にするだけ |

`/security-audit` のコマンドラインに `--keep-work` または `--purge-work` を付けると選べます。

## 関連ページ

- [基準と業種](standards-and-sectors.md)
- [再スキャンと修正の確認](rescan.md)
- [`finding.md.template`](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/templates/finding.md.template) と [`audit-report.md.template`](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/templates/audit-report.md.template)
