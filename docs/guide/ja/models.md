# モデルと費用

[English](../models.md) · **日本語**

スキルは、タスクごとに必要なモデルを割り当てます。探索はモデルを使わない決定論的なスクリプトが行い、モデルは判断（コードを読む、候補の反証を試みる、指摘事項を書く）に使います。

![深さごとのモデル割り当て。偵察：Quick はリードがインライン、Standard と Deep は recon-mapper（Sonnet、medium）。設計系レーン（authz-logic、sensitive-data、ai-agentic）：Quick はリード、Standard は Sonnet high、Deep は Opus high。その他のレーン：Quick はリード、Standard は Sonnet medium、Deep は Sonnet high。検証：Quick はリードが P0 と P1 を再確認、Standard は Sonnet high で P0 と P1、Deep は Opus high で P0 から P2。翻訳（報告書の言語が 2 つ以上のときのみ）：Sonnet medium。下段に、モデルを使わずに探索するスクリプトと、すべてのサブエージェントに適用される規則。](../../assets/model-allocation.ja.svg)

## 深さごとのモデルと effort

| 役割 | Quick | Standard | Deep（既定） |
|---|---|---|---|
| 偵察 | リードがインラインで実行 | `recon-mapper`：Sonnet / medium | `recon-mapper`：Sonnet / medium |
| 設計系レーン（`authz-logic`、`sensitive-data`、`ai-agentic`） | リードがインラインで実行（レーンは合計で最大 3 つ） | `lane-reviewer`：Sonnet / high | `lane-reviewer`：**Opus / high** |
| その他のレーン（`injection-dataflow`、`mobile`、`supply-chain-infra`、`perf-quality`） | リードがインラインで実行 | `lane-reviewer`：Sonnet / medium | `lane-reviewer`：Sonnet / high |
| 検証 | リードが P0 と P1 を再確認 | `finding-verifier`：Sonnet / high、P0 と P1 が対象 | `finding-verifier`：**Opus / high**、P0 から P2 が対象 |
| 翻訳（報告書の言語が 2 つ以上） | Agent ツールが使えれば `report-translator`、使えなければインライン | `report-translator`：Sonnet / medium | `report-translator`：Sonnet / medium |

「リード」とは、Claude Code のメインセッションのことで、起動したときのモデルで動きます。設計系レーンを含むレーングループは、設計系レーンの設定で実行します。

この割り当ての理由：設計上の欠陥を探すレーンには複数ファイルにまたがる推論が必要で、Deep では Opus が効果を発揮します。スキャナの結果を手がかりにするレーンや設定を見るレーンは範囲がはっきりしているため、Sonnet で十分です。Haiku はセキュリティの判断には使いません。

## サブエージェント

| サブエージェント | ツール | ターン上限 | 役割 |
|---|---|---|---|
| `security-audit-recon-mapper` | Read、Grep、Glob、Bash、Write | 60 | 攻撃対象領域の整理：エントリポイント、信頼境界、悪用シナリオ、仮説 |
| `security-audit-lane-reviewer` | Read、Grep、Glob、Bash、Write | 120 | 1 つのレーンまたはレーングループ：スキャナの候補の確認や反証と、スキャナに見えないものの探索 |
| `security-audit-finding-verifier` | Read、Grep、Glob、Bash、Write | 100 | 各候補の反証を試み、重複をまとめ、指摘事項の下書きを作る |
| `security-audit-report-translator` | Read、Write、Bash | 20 | `findings.json` と `narrative.json` を別の 1 言語に翻訳する |

どのサブエージェントも Edit、NotebookEdit、Agent を禁止され、`maxTurns` の上限と `omitClaudeMd` を持つため、利用者の `CLAUDE.md` は読み込まれません。サブエージェントが利用者と直接やり取りすることはなく、範囲に関する決定はすべてプロンプトで渡します。スキルは呼び出しのたびに `model` と `effort` を明示します。`CLAUDE_CODE_EFFORT_LEVEL` のような環境変数による上書きがあればそれが優先され、報告書には実際に動いたモデルを記録します。

名前付きサブエージェントがまだ入っていない場合や、セッション中に作ったフォルダに入れた場合は、同じ指示書を使う汎用サブエージェントで代用します。結果は同じで、トークンが多めにかかります。[インストール](install.md)を参照してください。

## トークンを節約する仕組み

- **探索の結果はスクリプトが渡す。** 各レーンには、リポジトリのダイジェスト、ルートマップ、プラットフォーム一覧、脆弱性情報の照合結果、マスク済みのコード抜粋（レーンパック）を渡し、最初の 20-40 回分の Read と Grep を省きます。サブエージェントはターンごとにコンテキスト全体を送り直すため、省いたターンが節約の大部分になります。
- **レーングループ。** 小さなリポジトリではどのレーンも同じファイルを読むため、サブエージェントを共有します。小規模（150 ファイル未満）は 3 グループ、中規模は約 5 グループ、大規模（5000 ファイル以上）はレーンごとに 1 つです。
- **ルールによる自動除外。** `normalize_findings.py` は、ほぼ確実に実在しないスキャナの候補（プレースホルダの秘密情報、同梱されたサードパーティの文書、テストファイル内の本番専用ルール）に印を付けます。レーンはこれらにターンを使わず、報告書では否定された候補として記載します。
- **検証役は 1 つの表を読む。** `collect_lanes.py` がすべてのレーンのファイルを `lanes/candidates.md` にまとめます。サイズは約 5 分の 1 です。

## 実測した費用と時間

リポジトリのライブのベンチマークは、特定のコミットに固定した意図的に脆弱な 3 つのプロジェクト（DVWA、NodeGoat、OWASP Juice Shop）を、ヘッドレスの Claude Code で実際に監査します。深さは Quick で、プロジェクトとバージョンごとに 3 回実行します。現在のバージョンの、監査 1 回あたりの測定値は次のとおりです。

| 指標 | 値 |
|---|---|
| プロジェクトごとに文書化された 10 種類の脆弱性に対する再現率 | <!--n:bench_recall_pct-->97<!--/n-->% |
| 平均費用 | US$<!--n:bench_cost_usd-->2.52<!--/n--> |
| 平均所要時間 | <!--n:bench_minutes-->8<!--/n--> 分 |
| 実行回数 | <!--n:bench_runs-->9<!--/n--> |

再現率はモデルではなくスクリプトで採点しています。適合率は測定していません。これらのプロジェクトには文書化されている以上の不具合があるため、10 種類以外の指摘が誤検知とは限らないからです。プロジェクト 3 つ、各条件 3 回は小さな標本です。Standard と Deep のベンチマークは取っていません。

実行ごとの数値、前のバージョンとの比較、ベンチマークの経緯は [benchmark/RESULTS.ja.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/benchmark/RESULTS.ja.md) に、方法と再現の手順は [benchmark/README.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/benchmark/README.md) にあります。ベンチマークには費用がかかるため、CI では実行しません。

## 関連ページ

- [監査の流れ](how-it-works.md)
- [orchestration.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/reference/method/orchestration.md)：割り当て表、レーングループ、プロンプトのひな形
- [初めての監査](first-audit.md)
