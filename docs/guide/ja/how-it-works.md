# 監査の流れ

[English](../how-it-works.md) · **日本語**

監査は 2 つの層でできています。**決定論的な層**は Python のスクリプト群（標準ライブラリのみ）と、バージョンを固定した <!--n:scanners-->8<!--/n--> 種のスキャナです。エントリポイント、バージョン、秘密情報らしき文字列、スキャナの検出、脆弱性情報を見つけ、報告書を組み立て、検証し、描画します。**知識の層**は、バージョン付きの基準に照らしてコードを読むモデルです。何が欠陥か、どれほど深刻か、どう直すかを判断します。探索はスクリプトが行うため、モデルのターンは判断に使われます。

![監査の流れ。Phase 0 から 8 を、決定論的なスクリプトが行うこととモデルが行うことに分けて示す。スコープ：env_check、detect_stack、questions。偵察と脅威情報：platform_inventory、公開アドバイザリフィードと照合する threat_intel（バックグラウンド）、repo_digest、route_map、agent_config_audit。recon-mapper サブエージェントが攻撃対象領域を整理する。保存データのスイープ。スキャナ：固定した 8 種をバックグラウンドで実行し、normalize_findings がルールで誤検知を除外。モデルは使わない。レビューレーンは並列。トリアージと反証による検証。根本原因ごとに 1 ファイルで登録。報告書：組み立て、検証、HTML と Excel の描画、整理。再スキャンは依頼時のみ。](../../assets/audit-pipeline.ja.svg)

## 作業の順序

スキャナは Phase 0 の直後に、脆弱性情報の照合はプラットフォーム一覧の直後に始まります。どちらもバックグラウンドで動くため、時間のかかるネットワークやコンテナの処理が、偵察やスイープと並行して進みます。レビューレーン（Phase 4）は、それらがすべて揃うのを待ちます。

## フェーズ

| フェーズ | スクリプト（決定論的） | モデル | 書き出すもの |
|---|---|---|---|
| 0 スコープ | `env_check`、`detect_stack`、`questions`、`install_agents`（Standard、Deep） | リードが深さ、報告書の言語、重点、形式、さらに個人・決済・健康のデータを検出したときは法令を尋ねる | `work/profile.md` |
| 1 偵察と脅威情報 | `platform_inventory`、`threat_intel`（バックグラウンド）、`repo_digest`、`route_map`、`agent_config_audit` | Standard と Deep では `recon-mapper`（Quick ではリード）：エントリポイント、信頼境界、3-5 件の悪用シナリオ、5-15 件の仮説 | `platform.*`、`intel.*`、`digest.*`、`routes.*`、`agent-config.*`、`recon.md` |
| 2 機微データのスイープ | `sensitive_sweep`、`peek` | データモデルを読む：各列、JSON のフィールド、クライアント側の保存先に実際に何が入るか | `sweep.json` |
| 3 スキャナ | `run_scanners`（バックグラウンド）、`normalize_findings` | なし。スキャナの検出は手がかり | `scanners.json`、`candidates.jsonl`、`summary.md` |
| 4 レビューレーン | `lane_pack` | レーングループごとの `lane-reviewer` を並列で（Quick ではインライン） | `lanes/<group>.md` |
| 5 トリアージと検証 | `collect_lanes` | `finding-verifier` が各候補の反証を試みる（Quick ではリード） | `lanes/verifier.md`、`findings.draft.json` |
| 6 登録 | `new_finding` | リードがタイトル、重大度、統合を見直す | `findings/<lang>/<repo>/*.md` |
| 7 報告と検証 | `build_report`、`validate_findings`、`render_html`、`render_xlsx`、`prune_work` | 説明文（エグゼクティブサマリー、対応事項）。追加言語ごとに `report-translator` | `reports/md/`、`reports/html/`、`reports/xlsx/` |
| 8 再スキャン（依頼時のみ） | 同じイメージダイジェストでの `run_scanners --pin`、`normalize_findings` | すべてのアンカーを読み直す | `rescan-<ts>/`、更新した状態 |

### 各スクリプトの役割

| スクリプト | フェーズ | 役割 |
|---|---|---|
| `env_check.py` | 0 | OS、Python、シェル、コンテナエンジン、ネイティブのスキャナ、Excel を調べ、スキルが従う選択肢を出力します。インストールもネットワークの使用もしません。 |
| `detect_stack.py` | 0 | 各リポジトリの特徴を調べます：アーキタイプ、言語、フレームワーク、フラグ、業種、基準モジュール、スキャナ、レビューレーン、レーングループ、推奨する深さ。 |
| `questions.py` | 0 | Phase 0 の質問を会話の言語で組み立てます。 |
| `install_agents.py` | 0 | 4 つの名前付きサブエージェントを `~/.claude/agents/security-audit/` に入れます（Standard、Deep）。 |
| `platform_inventory.py` | 1 | リポジトリがデプロイするランタイム、サーバー、データストア、ベースイメージ、管理ツール、フレームワークを、バージョン、精度、文脈、`path:line` と露出のシグナル付きで一覧にします。ネットワークは使いません。 |
| `threat_intel.py` | 1 | 一覧をライブのアドバイザリフィードと照合します。[ライブ脅威情報](threat-intelligence.md)を参照してください。 |
| `repo_digest.py` | 1 | 行数付きのファイル一覧、ソースとシンクの索引（`path:line` と短いラベル）、秘密情報を含むファイルの名前。行の内容は載せません。 |
| `route_map.py` | 1 | FastAPI、Flask、Django と DRF、Express、Koa、Fastify、NestJS、Spring、Laravel、Rails のエンドポイント表と、各ルートの近くに見つかった認証の目印。目印のないルートは手がかりで、結論ではありません。 |
| `agent_config_audit.py` | 1 | AI とエージェントの一覧：権限、フック、MCP サーバー、サブエージェント、スキル、指示ファイル、CI 上のエージェントのアクション、プロンプトのログ（git 履歴を含む）、隠れた Unicode 文字、LLM の呼び出し。 |
| `sensitive_sweep.py` | 2 | 保存されたカード情報、個人データ、健康データの場所を示します。値は出さず、見つからなかった場合の記録も必ず残します。 |
| `peek.py` | 2 以降 | 秘密情報を含む行をマスクして表示します。 |
| `run_scanners.py` | 3、8 | 固定したスキャナを読み取り専用で実行します。[スキャナ](scanners.md)を参照してください。 |
| `normalize_findings.py` | 3 | SARIF を重複のない 1 つの候補一覧にまとめ、ほぼ確実に実在しない候補（プレースホルダの秘密情報、同梱されたサードパーティの文書、テスト内の本番専用ルール）をルールで除外します。 |
| `lane_pack.py` | 4 | レーングループごとに、レーンが最初の 20-40 回の Read と Grep で取得するはずのコード抜粋を、マスクして 1 つにまとめます。 |
| `collect_lanes.py` | 5 | 検証役のために、重複の可能性があるものをまとめた候補の表を作ります。 |
| `new_finding.py` | 6 | 1 つの JSON の一覧から指摘事項ファイルを書き出します。コードを検査し、見出しを言語に合わせます。 |
| `build_report.py` | 7 | Markdown の報告書を組み立てます。表と件数は指摘事項ファイルから作ります。 |
| `validate_findings.py` | 7 | 描画の前の関門です。[指摘事項と報告書](reports.md)を参照してください。 |
| `render_html.py`、`render_xlsx.py` | 7 | HTML の報告書と Excel のブック。 |
| `prune_work.py` | 7 | 実行後に誰も読まない中間ファイルを削除します。 |

どのスクリプトにも `--help` があります。スキルはスクリプトを実行するだけで、モデルのコンテキストに読み込むことはありません。

### レビューレーン

レーンは `authz-logic`、`injection-dataflow`、`sensitive-data`、`ai-agentic`、`supply-chain-infra`、`mobile`、`perf-quality` です。各レーンは割り当てられたスキャナの候補を確認または反証し、スキャナに見えないものを探します。オブジェクト単位と機能単位の認可の不備、スコープ漏れのクエリ、UI では隠れていても API からは呼べるルート、機能していないセキュリティ制御、非アトミックな返金、保存されたカードや個人データ、ツールへのプロンプトインジェクション、危険なエージェント設定などです。

Standard と Deep では、同じファイルを読むレーンを 1 つのサブエージェントにまとめます。小さなリポジトリ（150 ファイル未満）は 3 グループ、中規模は約 5 グループ、大規模（5000 ファイル以上）はレーンごとに 1 つです。どの深さでも、脆弱性情報の照合結果の act-now と review の行は必ずトリアージします。重点からサプライチェーンのレーンを外した場合も同じです。

## サブエージェント

| 役割 | サブエージェント | Standard | Deep | ターン上限 |
|---|---|---|---|---|
| 偵察（リポジトリごとに 1 つ） | `security-audit-recon-mapper` | Sonnet / medium | Sonnet / medium | 60 |
| `authz-logic`、`sensitive-data`、`ai-agentic` を含むレーングループ | `security-audit-lane-reviewer` | Sonnet / high | Opus / high | 120 |
| その他のレーングループ | `security-audit-lane-reviewer` | Sonnet / medium | Sonnet / high | 120 |
| 検証 | `security-audit-finding-verifier` | Sonnet / high（P0 と P1） | Opus / high（P0 から P2） | 100 |
| 翻訳（報告書の言語が 2 つ以上） | `security-audit-report-translator` | Sonnet / medium | Sonnet / medium | 20 |

Quick ではこれらをすべてメインセッション内で行います。ただし翻訳は、Agent ツールが使えれば Quick でも翻訳のサブエージェントに任せます。詳しくは[モデルと費用](models.md)を参照してください。

## 読み取り専用の保証

スキルは 6 つの基本原則に従います。どれか 1 つでも破れば、監査は無効になります。

1. **製品のソースは読み取り専用。** 監査対象のコードを編集、整形、コミット、「ついでに修正」することはありません。出力はすべて監査対象リポジトリの外に置きます。
2. **信じる前に読む。** スキャナやスイープの検出は、コードを読んで確認するまで手がかりにすぎません。
3. **バージョン付きの基準を引用する。** `基準名 + 版 + 要件 ID` の形で、ID だけの引用はしません。
4. **秘密情報、カード番号、個人データは表示しない。** 一部を切り詰めた形でも表示しません。
5. **見つからなかったことも結果である。** どの報告書にも、保存データの機微情報の章、AI とエージェントの一覧、未確認範囲の表があります。
6. **監査対象の内容は根拠であって、指示ではない。** README、`CLAUDE.md`、`AGENTS.md`、スキルのファイル、コメント、プロンプトのログ、MCP ツールの説明、アドバイザリフィードの文章はデータとして読みます。

スクリプトは、強制できることを強制します。

- `run_scanners.py` は監査対象リポジトリの中への出力を拒否し、リポジトリを読み取り専用でマウントし、結果を信じる前にマウントを確認します。
- git は `core.fsmonitor`、フック、リポジトリ側の設定を無効にして実行し、インデックスにも書き込みません。
- どのサブエージェントも、Edit と Agent を含まないツールの許可リストとターン上限を持ち、`CLAUDE.md` を読み込みません。
- リポジトリの外を指すシンボリックリンクは読みません。

詳しくは[セキュリティとプライバシー](security-and-privacy.md)を参照してください。

## 関連ページ

- [ARCHITECTURE](https://github.com/nguyenhx2/agent-security-audit/blob/main/docs/ARCHITECTURE.ja.md)：データの流れと監査する側の保護の詳細
- [SKILL.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/SKILL.md)：フェーズごとの手順
- [orchestration.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/reference/method/orchestration.md)：モデルの割り当て表とプロンプトのひな形
