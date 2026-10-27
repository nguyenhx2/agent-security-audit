# オーケストレーション：標準・詳細の深さにおけるサブエージェント

詳細（既定）または標準の深さで読む。クイックは翻訳を除くすべてをインラインで実行する（後述の「翻訳」を参照）。手順の文脈：
`SKILL.md` の Phase 0、1、4、5、7。`<skill_dir>` は、SKILL.md 内で `${CLAUDE_SKILL_DIR}` が展開された
絶対パスである（Windows ではスラッシュ区切り）。

## ルール
- **名前付きエージェントを優先する。** `scripts/install_agents.py` は `agents/` 内の 4 つのブリーフを
  `security-audit-recon-mapper`、`-lane-reviewer`、`-finding-verifier`、`-report-translator`
  （`~/.claude/agents/security-audit/`）としてインストールする。Agent ツールの一覧に表示されていれば、
  これらを `subagent_type` として使う。各エージェントは固有のツール許可リスト（Agent なし、Edit なし）、
  `maxTurns`、`omitClaudeMd`（CLAUDE.md を各サブエージェントに読み込まない）を持ち、ブリーフがすでに
  システムプロンプトになっているため、委任プロンプトはパラメータのみを渡す。**フォールバック**（未インストール、
  または開始時に存在しなかったフォルダへ当セッション中にインストールした場合）：`general-purpose` を使い、
  先頭に "Read `<skill_dir>/agents/<brief>.md` and follow it." を付ける。結果は同じだが、トークンが増える。
- 独立したサブエージェントは 1 つのメッセージでまとめて起動し、並列実行させる。各サブエージェントは結果ファイルを
  書き出し、5 行以内で返す。ポーリングや sleep はしない。完了は通知で届くので、その間は別の作業
  （スイープ結果の確認、データモデルの読解、所見文のメモ）を進める。
- サブエージェントはユーザーに質問できない（AskUserQuestion は利用不可）。スコープに関する決定
  （深さ、重点、適用法域、形式）はすべて委任プロンプトに含める。
- すべての Agent 呼び出しで、下表に従い `model` と `effort` を渡す。このスキルはこれらの effort レベルを
  明示的に要求しており、呼び出し側の指定がエージェントファイルの既定値より優先される（ただし
`CLAUDE_CODE_EFFORT_LEVEL` などの環境による上書きがさらに優先される。実際に動作したモデルを報告書のレーン行に記録する）。
- すべてのレーンおよび偵察のプロンプトにダイジェストのパス（`<audit_dir>/work/<repo>/digest.md`）、ルートマップ
  （`routes.md`）、プラットフォーム一覧（`platform.md`）を渡し、レーンには勧告の照合結果（`work/intel.md`）も渡す。
  各レーングループにはそのレーンパック（`packs/<group>.md`）も渡す。これらにより、各
  サブエージェントが自前で Glob/Grep により探索する必要がなくなる：サブエージェントの各ターンはコンテキスト全体を再送するため、
  節約したターンがトークン節約の大部分になる（レーンは詳細の監査のトークンの約 60% を占める）。
- Agent ツールが使えない場合（このスキル自体がサブエージェント内で動作している場合）は、クイックの順序
  （authz-logic、アーキタイプの主レーン、injection-dataflow、その後に残り）でレーンをインラインで実行し、
  検証エージェントの手順も自分で行い、報告書に "lanes run inline" と記載する。

## レーングループ（トークン予算）
小規模リポジトリではレーン同士が同じファイルを読むため、detect_stack の `lane_groups` はリポジトリ規模に応じて
レーンをまとめる：小規模（< 150 ファイル）-> サブエージェント 3 つ（`authz-logic+injection-dataflow`、
`sensitive-data+supply-chain-infra`、`ai-agentic|mobile+perf-quality`）。中規模 -> 設計系レーンごとに 1 つ
＋ `supply-chain-infra+perf-quality`。大規模（>= 5000 ファイル）-> レーンごとに 1 つ。36 ファイルの
エージェント系リポジトリでの実測：6 レーン x 140-170k トークン -> 同じファイルを 6 回読んでいた。ユーザーが
最大限の分離を求めた場合にのみ上書きする。

## モデル / effort の対応表

| 役割 | subagent_type（フォールバック：general-purpose） | 標準（model / effort） | 詳細（model / effort） |
|------|-------------------------------------------|---------------------------|-----------------------|
| 偵察（標準/詳細ではすべてのリポジトリ） | `security-audit-recon-mapper` | sonnet / medium | sonnet / medium |
| authz-logic、sensitive-data、ai-agentic のいずれかを含むレーングループ | `security-audit-lane-reviewer` | sonnet / high | opus / high |
| その他のレーングループ（injection-dataflow、mobile、supply-chain-infra、perf-quality） | `security-audit-lane-reviewer` | sonnet / medium | sonnet / high |
| 検証エージェント | `security-audit-finding-verifier` | sonnet / high | opus / high |
| 翻訳（追加の報告書言語ごとに 1 つ、2 言語以上の場合のみ） | `security-audit-report-translator` | sonnet / medium | sonnet / medium |

理由：設計レベルのレーンは複数ファイルにまたがる推論を要する（詳細では Opus が効果を発揮する）。SAST 支援型や
設定系のレーンは範囲が明確である（Sonnet）。Haiku はセキュリティ判断には使わない。決定的な処理はすでに
スクリプトが担っている（テストでは Haiku もクイックの IaC 監査を完了できたため、スキルは穏当に劣化するが、
レーンの判断力は弱くなる）。

## プロンプトテンプレート（名前付きエージェント用。フォールバックでは先頭に "Read <skill_dir>/agents/<brief>.md and follow it." を付ける）
偵察：
```
repo=<repo_path> profile=<audit_dir>/work/profile.md digest=<audit_dir>/work/<repo>/digest.md
routes=<audit_dir>/work/<repo>/routes.md platform=<audit_dir>/work/<repo>/platform.md
skill_dir=<skill_dir> out=<audit_dir>/work/<repo>/recon.md
```
レーンを起動する前に（偵察が戻った後）、リードはレーングループごとに 1 回、すべてを 1 回の Bash 呼び出しで実行する：
```
python <skill_dir>/scripts/lane_pack.py <repo_path> --digest-json <audit_dir>/work/<repo>/digest.json --routes <audit_dir>/work/<repo>/routes.json --lane <group> --out <audit_dir>/work/<repo>/packs/<group>.md
```
（Windows では `py -3`。既定の予算は 60 KB。大規模リポジトリで単一レーンのグループには `--budget-kb 90`。）リードは
パックを Read しない。

レーングループ（`lane_groups` の各エントリにつき 1 つ、すべて 1 つのメッセージで）：
```
repo=<repo_path> lane=<group, e.g. authz-logic+injection-dataflow> skill_dir=<skill_dir>
ai_scope=<detect ai_scope, for a group containing ai-agentic>
digest=<audit_dir>/work/<repo>/digest.md recon=<audit_dir>/work/<repo>/recon.md
pack=<audit_dir>/work/<repo>/packs/<group>.md routes=<audit_dir>/work/<repo>/routes.md
agent_config=<audit_dir>/work/<repo>/agent-config.md (group with ai-agentic)
platform=<audit_dir>/work/<repo>/platform.md intel=<audit_dir>/work/intel.md (every group; the
supply-chain-infra group owns the findings, others only follow pointers)
candidates=<audit_dir>/work/<repo>/candidates.jsonl (assigned: <categories / cids>)
sweep=<audit_dir>/work/<repo>/sweep.json standards=<module files in scope>
scope=<depth, focus, jurisdiction> out=<audit_dir>/work/<repo>/lanes/<group>.md
scratch=<audit_dir>/work/<repo>/scratch/<group>
```
検証エージェント（すべてのレーンが戻り、`collect_lanes.py` が `lanes/candidates.md` を書き出した後）：
```
repo=<repo_path> repo_name=<repo> skill_dir=<skill_dir> candidates=<audit_dir>/work/<repo>/lanes/candidates.md
lanes_dir=<audit_dir>/work/<repo>/lanes min=<P2 Deep | P1 Standard>
lang=<source language: en, or the one report language when exactly one was chosen>
out=<audit_dir>/work/<repo>/lanes/verifier.md draft=<audit_dir>/work/<repo>/findings.draft.json
scratch=<audit_dir>/work/<repo>/scratch/verifier
```
翻訳（報告書の言語が 2 つ以上選ばれた場合のみ。ソース言語以外の言語ごとに 1 つ。`<work>/narrative.json` が
存在し次第、すべて 1 つのメッセージで起動する（SKILL.md の Phase 7 手順 2b）。その実行中にソース言語のセットを作成する。
報告書の言語が 1 つの場合は検証エージェントがその言語でドラフトを書き、翻訳は実行しない。クイックでも、Agent ツールが
使える場合は翻訳に翻訳サブエージェントを使い、使えない場合に限りインラインで行う）：
```
work=<audit_dir>/work source=<source lang> lang=<L>
out_findings=<audit_dir>/work/findings_<L>.json out_narrative=<audit_dir>/work/narrative_<L>.json
```
（`findings.json` / `narrative.json` が正本である。ソース言語のセットはこれらから直接作成し、翻訳はしない。）

スキャナの候補は `category` で割り当てる（secret -> sensitive-data、dependency/config ->
supply-chain-infra、code -> mobsfscan なら `mobile`、それ以外はルールに応じて authz-logic または injection-dataflow、
エージェント / LLM 設定の検出 -> ai-agentic）。これにより担当のない候補を
なくす。グループ単位の場合は、メンバーの候補の和集合をそのグループに渡す。`auto_refuted` が付いた候補は
割り当てない（ルールにより反証済みであり、検証エージェントの Refuted の一覧を経由して報告書に載る）。

## harness-bootstrap のコントロールプレーン内で実行する場合（任意）
ワークスペースに監査用コントロールプレーン（読み取り専用の監査エージェント、指摘事項ツリー、`protect-repos`
フック）が既にある場合は、指摘事項をそのツリーに書き込み、そのタスクループに従う。それ以外は同じである。
フックが監査を保護している場合は、信頼する前に両側からテストする：ブロックすべきケースが非ゼロで終了し、かつ
通過すべきケースがゼロで終了すること。すべてをブロックするフックも、何もブロックしないフックも、片側だけの
テストには合格してしまう。
