# モジュール: ai-llm-agentic - LLM Top 10 2026、Agentic Top 10 2026、MCP Top 10 (beta)、AISVS 1.01

コードが LLM を呼び出す、プロンプトを組み立てる、RAG/埋め込みを行う、エージェント/ツールを実行する、MCP
サーバー/クライアントを提供する、またはリポジトリが AIコーディングエージェントのツール設定をコミットしている場合に適用する（detect の `ai_scope`: `llm-app`、
`agentic-app`、`mcp`、`agent-tooling` - 列挙されたスコープはすべて対象とする）。引用形式は `OWASP Top 10 for LLM Applications 2026 LLM0x`、`OWASP Top 10 for Agentic
Applications 2026 ASI0x`、`OWASP MCP Top 10 (beta) MCP0x`（公式の ID 表記は `MCPxx:2025`）、
`OWASP AISVS 1.01 C<n>`。バージョンは
`reference/standards/index.md` に従う。ほぼすべての行は **手動（Manual）**: SAST は API 呼び出しを捉えるが、信頼のフローは捉えない。

## 目次
- 手法: 信頼できないコンテンツの経路をたどる
- LLM Top 10 2026
- Agentic Top 10 2026
- MCP Top 10 (beta)
- リポジトリ内の AIコーディングエージェントのツール設定（`agent-tooling` スコープ）
- AISVS 1.01 章ルーター
- 重大度の目安

## 手法: 信頼できないコンテンツの経路をたどる
1. **モデル呼び出しの棚卸し:** `chat.completions`、`messages.create`、`generateContent`、
   `invoke(`、`ChatOpenAI`、`Anthropic(`、`streamText`、`generateText`、`run_agent`、`Agent(` を grep する。
2. **呼び出しごとに入力を列挙:** システムプロンプトの出所、ユーザー入力、取得文書（RAG）、ツール
   結果、Web ページ、メール/ファイル。開発者が書いたもの以外はすべて信頼できない。
3. **出力で何ができるかを列挙:** HTML/Markdown として描画されるか、実行されるか（コード、SQL、シェル）、
   ツールに渡されるか、メモリ/DB に書き込まれるか、認可や金銭の判断に使われるか。
4. **脆弱性とは経路である:** 信頼できない入力からゲート（許可リスト、人間による承認、サンドボックス、出力エンコーディング、
   スコープを限定した資格情報）なしに特権シンクへ至る経路。
5. **認可はプロンプトの外に置かなければならない。** 「現在のユーザーのデータだけを表示する」がシステム
   プロンプトの一文としてのみ存在し、ツールは任意の `user_id` を受け付ける場合、それはオブジェクトレベル認可の不備である
   （P0/P1、LLM01 + ASI03 + API1）。ID はツール内でセッションから束縛し、モデルの引数からは決して取らない。
6. **プロバイダーへのデータの流れ:** どのプロバイダー / リージョンがプロンプトを受け取るか（プライバシーモジュールでいう越境移転）、
   API キーはサーバー側のみ、保持期間 / 学習へのオプトアウトが設定済み、プロンプトと
   補完結果が個人データやシークレットとともにログ記録されていない（LLM02）。

明示的に確認すべきエージェントループのパターン:
- **ReAct / テキストプロトコル型エージェント**（モデルのテキストから `Thought:` / `Action:` / `Observation:` を解析する）:
  それらのマーカーを含むユーザー入力やツール出力が、エージェント自身のスクラッチパッドを偽造できる（偽の
  `Observation:` や `Action:` 行）。文字列連結で組み立てたトランスクリプトや正規表現によるアクション解析を探す。
  是正策は構造化されたツール呼び出し API である。
- **ツール引数の信頼:** モデルが選んだ引数が SQL/シェル/パス/URL に流れる箇所はインジェクションの
  シンクである（LLM10 Improper Output Handling） - リクエストパラメータと同じルールを適用する。
- **自動承認ループ:** 書き込み/金銭的な操作について、ステップ上限、予算、人間によるゲートなしにツールを
  ディスパッチする `while` ループ（ASI08、LLM03、LLM06）。探すべき上限: `max_iterations`、
  `max_execution_time`、LangGraph の `recursion_limit`、`max_tokens`、クライアントのタイムアウト、リトライ上限、
  ユーザーごとの予算。
- **致命的な三要素（lethal trifecta）:** 1 つのエージェントまたはツール群が、プライベートデータ + 信頼できないコンテンツ + 
  持ち出し経路（HTTP フェッチ、メール、Markdown 画像、Webhook）を併せ持つもの。悪用経路を追跡できていなくても対象とする
  （下限：`reference/method/triage.md`）。

## Top 10 の表以外の LLM アプリケーションのチェック（`llm-app` / `agentic-app`）
`agent-config.md`（llm-code 行）が呼び出しとスイッチを列挙している。それぞれをコードを読んで確認する。
| チェック | 探すもの | 引用 |
|-------|------------------|------|
| 危険なフレームワークのスイッチ（到達可能なら P0/P1 が下限） | `allow_dangerous_code/requests/deserialization=True`、`PythonREPLTool`、`LLMMathChain`、`PALChain`、読み書きロールでの `create_sql_agent` / `SQLDatabaseChain`、`load_tools(["terminal"])`、`PandasQueryEngine`、`trust_remote_code=True`、`weights_only=True` なしの `torch.load`、信頼できない JSON に対する `langchain.load(s)` | LLM10, LLM04, ASI05; CWE-94/502 |
| プロンプトテンプレートインジェクション | ユーザー入力から組み立てた `PromptTemplate(template_format="jinja2")` や f-string テンプレート（SSTI -> RCE）、ユーザーが制御できる `base_url` / `api_base`（キーが攻撃者に送られる）や `model`（コストの増大） | LLM01, LLM06; CWE-1336 |
| クライアント側のキーとオープンプロキシ | `dangerouslyAllowBrowser: true`、`NEXT_PUBLIC_*` / `VITE_*` のプロバイダーキー、ユーザーごとの認証とクォータなしにプロバイダーへ転送するサーバープロキシ | LLM02, LLM06; API4 |
| 認証のないモデル / UI サーバー | Ollama `0.0.0.0:11434`、vLLM / TGI / LM Studio のポート、Gradio `share=True`、認証のない Streamlit / Chainlit | LLM06; API2; A01 |
| ユーザー間で共有される状態 | モジュールレベルのメモリ（`ConversationBufferMemory`、Streamlit / Gradio のグローバル変数）、ユーザーをキーに含まないセマンティック / プロンプトキャッシュ、クライアントから受け取る LangGraph `thread_id`、チャット履歴や共有リンクの IDOR | LLM02, ASI06; API1 |
| RAG 固有事項 | ACL がクエリ時にソースシステムから適用される（取り込み時のコピーではない）、削除 / 失効がチャンク、埋め込み、キャッシュにまで及ぶ（GDPR の消去権。埋め込みは個人データである）、ローダーの SSRF（`WebBaseLoader`、169.254.169.254 への URL ローダー）、隠しテキスト、PDF、画像によるインジェクション源 | LLM09, LLM02, LLM01; A01 SSRF |
| 制御としてのガードレール | モデレーション / Llama Guard / NeMo / コンテンツセーフティの呼び出しが例外やタイムアウト時に**フェイルクローズ**し、ツール出力と RAG 出力にも適用される - そうでなければ無効化された制御（P1 が下限） | LLM01, LLM10; A10 |
| 生成コードのサンドボックス | docker ソケットなし、外向き通信なし、サンドボックス環境にプロバイダーやクラウドのキーなし。`exec` の globals を制限してもサンドボックスにはならない | ASI05; CWE-94 |
| 可観測性のデータフロー | LangSmith / Langfuse / Helicone / OpenTelemetry のトレースが完全なプロンプトと個人情報を第三者に送る（処理者、移転、保持期間）、本番での `verbose=True` / `set_debug(True)` | LLM02; privacy module |
| 承認の完全性 | 承認が正確なツール引数に束縛されている（承認と実行の間に TOCTOU がない）、UI がモデルの要約ではなく生の引数を表示する | ASI09 |
| モデルの固定 | 挙動が重要な箇所では浮動エイリアスではなく日付付きのモデルスナップショットを使う、ローカルの重みはハッシュで固定し `safetensors` を使う | LLM04 |
| 規制 | EU AI Act Art. 50 の透明性義務とリスク分類、GDPR Art. 22 の自動化された意思決定 - `reference/standards/privacy.md` に回す | EU AI Act; GDPR |
| テスト | CI でのプロンプトインジェクション / ジェイルブレイクのテスト（promptfoo、garak、PyRIT） - ない場合は記録する（Info） | AISVS 1.01 C11 |
プロンプトインジェクションの指摘事項は、経路を静的に端から端まで追跡できた場合を除き `needs-runtime-check` とする。

## LLM Top 10 2026
2026 年最終版（2026-08 に github.com/GenAI-Security-Project/GenAI-LLM-Top10 の `2026/final` で公開。
genai.owasp.org のページはまだ 2025 年のスラッグを表示している場合がある）。ID は振り直されている - 2025 年の ID を決して再利用しない。

| ID | リスク | 検証すること | 確認箇所 / grep のヒント |
|----|------|----------------|--------------------|
| LLM01 | Prompt Injection（プロンプトインジェクション、直接 + 間接） | 信頼できないコンテンツ（ユーザー、RAG 文書、Web、メール、ツール出力）が特権操作をゲートする指示を変更できない。特権操作にはモデルの外での決定論的なチェックが必要 | `user_input`/`context`/`docs` を連結するプロンプトテンプレート、Web を閲覧したり受信箱を読んだりするエージェント |
| LLM02 | Sensitive Information Disclosure（機微情報の漏洩） | プロンプトやコンテキストにシークレット/個人情報/他テナントのデータがない、ユーザーごとの取得フィルタ、出力のスクラブ | キーを含むシステムプロンプト、テナントフィルタのない RAG クエリ、個人情報を含むプロンプト/レスポンスのログ記録 |
| LLM03 | Excessive Agency（過剰な権限委譲） | ツールは最小権限（可能な限り読み取り専用）、スコープを限定した資格情報、破壊的/金銭的な操作には人間の承認 | DB/FS/HTTP/シェルへの広範なアクセスを持つツール定義、`auto_approve`、管理者トークンを保持するエージェント |
| LLM04 | Supply Chain（サプライチェーン） | モデル/データセット/アダプターは信頼できる出所からのもので、ハッシュで固定。信頼できないリポジトリに `trust_remote_code=True` を使わない。pickle 形式の重みを使わない | `from_pretrained(`、`trust_remote_code`、`.pt`/`.pkl` の読み込み、ハブからの取得 |
| LLM05 | Data and Model Poisoning（データとモデルのポイズニング） | ファインチューニング/RAG の取り込みを検証し、来歴を追跡。ユーザーが書き込めるソースが共有インデックスを汚染できない | 取り込みパイプライン、学習/RAG ストアに書き込むフィードバックループ |
| LLM06 | Unbounded Consumption（無制限な消費） | ユーザーごとのトークン/リクエストのクォータ、`max_tokens`、タイムアウト、入力サイズ制限、コストアラート | 認証やスロットリングのないルートでの LLM 呼び出し、モデルを呼び出すループ |
| LLM07 | Misinformation（誤情報） | 意思決定を左右する出力は根拠付き/出典付きで検証済み、UI が不確実性を示す | 金融/医療/法務のフローで自動適用されるモデルの判断 |
| LLM08 | Hidden Context Exposure（隠しコンテキストの露出。旧 System Prompt Leakage で、現在はユーザーに見せないあらゆるコンテキストが対象） | システムプロンプト、ツールスキーマ、取得コンテキスト、メモリにシークレットや認可ロジックが含まれず、漏洩しても何の権限も得られない | プロンプト文字列内のシークレット/ロールのルール、デバッグ出力で返される隠しコンテキスト |
| LLM09 | Vector and Embedding Weaknesses（ベクトルと埋め込みの弱点） | テナント/ユーザーごとのベクトルストアのアクセス制御、テナント間の取得がない | メタデータフィルタのないベクトルクエリ、共有された名前空間 |
| LLM10 | Improper Output Handling（不適切な出力処理） | モデル出力を信頼できないものとして扱う: HTML 描画前にエンコードし、検証なしに `eval`/`exec`/SQL/シェルに決して渡さない | `innerHTML = completion`、`dangerouslySetInnerHTML`、`exec(response)`、`cursor.execute(llm_sql)`、生の HTML/画像を許可する Markdown レンダラー（持ち出し） |

## Agentic Top 10 2026

| ID | リスク | 検証すること |
|----|------|----------------|
| ASI01 | Agent Goal Hijack（エージェントの目標乗っ取り） | エージェントが読むコンテンツによって目標/計画を書き換えられない。特権経路での計画変更には再認可が必要 |
| ASI02 | Tool Misuse (and Exploitation)（ツールの誤用と悪用） | ツール引数をサーバー側で検証。ツールを連鎖させて意図しない能力を作れない（ファイル読み込み -> HTTP POST = 持ち出し） |
| ASI03 | Identity and Privilege Abuse（ID と権限の悪用） | エージェントは共有の強力な資格情報ではなく、*ユーザー*のスコープ付き ID で動作する。ユーザー間の confused deputy がない |
| ASI04 | Agentic Supply Chain Vulnerabilities（エージェントのサプライチェーンの脆弱性） | サードパーティのツール、MCP サーバー、プロンプト、プラグインが固定・検証されている。動的なツール読み込みが制限されている |
| ASI05 | Unexpected Code Execution（予期しないコード実行） | 生成コードはサンドボックス内でのみ実行（ホストの FS/ネットワーク/資格情報なし）。モデル出力をプロセス内で `exec` しない |
| ASI06 | Memory and Context Poisoning（メモリとコンテキストのポイズニング） | 長期メモリへの書き込みは検証され、帰属が追跡できる。メモリはユーザーごとにスコープ化。汚染されたメモリが指示を永続化できない |
| ASI07 | Insecure Inter-Agent Communication（安全でないエージェント間通信） | エージェント間メッセージは認証され、完全性が保護され、信頼できない入力として扱われる |
| ASI08 | Cascading Failures（連鎖的な障害） | サーキットブレーカー、ステップ/反復の上限、予算上限。1 つのエージェントの障害が無制限に波及しない |
| ASI09 | Human-Agent Trust Exploitation（人間とエージェント間の信頼の悪用） | 承認プロンプトが実際の操作とその影響を表示する。形だけの承認がない。影響の大きい操作には明示的な確認が必要 |
| ASI10 | Rogue Agents（暴走エージェント） | 監視とキルスイッチ。エージェントの操作が ID 付きでログ記録される。挙動のドリフトを検知できる |

確認箇所: エージェントループ（`while` + ツールディスパッチ）、ツールレジストリ、承認/HITL のコード、サンドボックス
設定（コンテナ、`subprocess`、E2B/Firecracker）、メモリストア、オーケストレーショングラフ（LangGraph、
CrewAI、Agents SDK）、ツール用の資格情報の受け渡し。

## MCP Top 10 (beta、随時更新される文書 - `OWASP MCP Top 10 (beta) MCP0x` として引用。公式の ID 表記は `MCPxx:2025`)

| ID | リスク | MCP サーバー/クライアントで検証すること |
|----|------|----------------------------------------|
| MCP01 | Token Mismanagement and Secret Exposure（トークンの不適切な管理とシークレットの露出） | トークンをログに記録しない、ツールに素通しで渡さない、設定に平文で保存しない。上流 API へのトークンのパススルーがない |
| MCP02 | Privilege Escalation via Scope Creep（スコープの拡大による権限昇格） | サーバーは最小限のスコープを要求する。ツールが宣言された能力を超えない |
| MCP03 | Tool Poisoning（ツールポイズニング） | ツールの説明/メタデータに隠し指示を含められない。説明は固定されレビュー済み。変更（「rug pull」）を検知する |
| MCP04 | Software Supply Chain Attacks and Dependency Tampering（ソフトウェアサプライチェーン攻撃と依存関係の改ざん） | サーバーパッケージが固定されている。`npx -y some-server@latest` 形式の起動を指摘する |
| MCP05 | Command Injection and Execution（コマンドインジェクションと実行） | ツール引数をシェル/SQL/パスに決して連結しない。stdio サーバーは固定の argv で起動する |
| MCP06 | Prompt Injection via Contextual Payloads（コンテキストペイロード経由のプロンプトインジェクション） | リソース/ツールの出力をクライアントが信頼できないデータとして扱う |
| MCP07 | Insufficient Authentication and Authorization（不十分な認証と認可） | リモート（HTTP）サーバーは認証を要求し（仕様に従い OAuth 2.1）、audience を検証し、ユーザーごとの認可を強制する |
| MCP08 | Lack of Audit and Telemetry（監査とテレメトリの欠如） | ツール呼び出しが呼び出し元の ID と引数（シークレットを除く）とともにログ記録される |
| MCP09 | Shadow MCP Servers（シャドー MCP サーバー） | 設定済みサーバーの棚卸し。共有設定（`.mcp.json`、`claude_desktop_config.json`）に未承認のサーバーがない |
| MCP10 | Context Injection and Over-Sharing（コンテキストインジェクションと過剰共有） | サーバーは最小限のデータを返す。セッション間/ユーザー間のコンテキスト漏れがない |

Grep: `@modelcontextprotocol/sdk`、`FastMCP`、`server.tool(`、`@mcp.tool`、`.mcp.json`、`mcpServers`。

## リポジトリ内の AIコーディングエージェントのツール設定（`agent-tooling` スコープ）
AIコーディングエージェント（Claude Code、Codex / AGENTS.md、Cursor、Copilot、Windsurf、Gemini CLI）が
開発者のマシンや CI でコマンドを実行できるようにする設定をコミットするリポジトリが増えている。これは
**実行可能な設定であり、かつサプライチェーン**として扱う: これらのファイルを変更できる者は、エージェントが
開発者の資格情報で何を実行するかを操れる。棚卸しは detect の `agent_tooling` カウントと
ダイジェストの `agent-permissions` インデックスから得る。プロンプトだけのルール（CLAUDE.md の「main に push しない」）は
ガイダンスであって制御ではない - それに依存する指摘事項は未緩和とみなす。

| 対象面 | ファイル | 検証すること | 主な引用 |
|---------|-------|----------------|------------------|
| 権限 | `.claude/settings.json`（`permissions.allow/deny/ask`、`defaultMode`）、`.codex/config.toml`、`.gemini/settings.json` | 書き込み、公開、マージ、デプロイ、持ち出しを行う操作に対する広範な許可（`Bash(*)`、`Bash(git:*)`、`Bash(python *)`、`Bash(curl:*)`、任意のホストへの `WebFetch`）がない。全員向けに `defaultMode: bypassPermissions` / `acceptEdits` がコミットされていない。`enableAllProjectMcpServers` がオフ。deny ルールは前方一致なのでバイパスを試す（`git -C . push`、`env git push`、`sh -c "..."`、`bash -lc`、エイリアス） | ASI02, ASI03; LLM03 |
| ローカル設定のコミット | `.claude/settings.local.json`、`*.local.*` | 個人用の上書きや許可リストが追跡されていない（`git ls-files` で確認）。トークンや個人のパスを含まない | ASI03; LLM02 |
| フック | `.claude/hooks/*`、settings 内の `hooks` ブロック | フックの入力（モデルからのツール JSON）がクォートなしでシェルに渡らない（`eval`/`bash -c` 内の `$(jq -r .tool_input.command)`）。ブロッキングフックは**フェイルクローズ**する（Claude Code: exit 2 でブロック、それ以外の非ゼロは警告のみ）。チームが使うすべてのプラットフォームで動作する（bash のない Windows 上の `.sh` フック、macOS 上の `powershell` = 無効化された制御）。リポジトリのデータを伴うネットワーク呼び出しがない。フックスクリプトは作業ツリーから読まれるため、ブランチで実行前に変更できる | ASI02, ASI05; CWE-78, CWE-636 |
| サブエージェント | `.claude/agents/*.md` | `tools` が役割に合っている（「reviewer」や「read-only」のエージェントは Bash/Write/Edit を持たない）。信頼できないコンテンツ（Issue、MR の本文、Web、文書）を読むエージェントは書き込み/実行/公開のツールを持たない。`permissionMode` が引き上げられていない | ASI03, LLM03 |
| スキル / コマンド | `.claude/skills/*/SKILL.md`、`.claude/commands/*.md`、`.agents/skills/*`、その他の `SKILL.md` | `allowed-tools` が正確なコマンドに限定されている（スコープなしの `Bash`、`Agent`、`Skill` = すべてを事前承認）。スキルが実行するスクリプトはプロダクトコードと同様にレビューする。スキルの本文に隠し指示がない（ゼロ幅 / bidi / タグの Unicode、HTML コメント） | ASI04, LLM01 |
| ベンダリングされたサードパーティのスキル / プラグイン | このリポジトリで書かれていないスキル（他の作者の LICENSE、マーケットプレイスからコピーした `.agents/skills/<name>`） | 出所、バージョン、コミットが記録されている。固定されている（「最新をコピー」ではない）。スクリプトがレビュー済み。更新プロセスがある。ライセンスが適合している | ASI04, LLM04; OWASP Top 10 2025 A03 |
| MCP サーバー | `.mcp.json`、`.cursor/mcp.json`、`.vscode/mcp.json`、`claude_desktop_config.json` | すべてのサーバーが把握・承認されている。固定して起動している（`npx -y pkg@latest` / 固定なしの `uvx` = MCP04）。トークンをインラインで書かない（env 参照のみ）。リモートサーバーは HTTPS + 認証を使う | MCP04, MCP09, MCP01 |
| 指示ファイル | `CLAUDE.md`、`AGENTS.md`、`GEMINI.md`、`.cursorrules`、`.cursor/rules/*`、`.github/copilot-instructions.md`、`.claude/rules/*` | シークレット、内部ホスト名、顧客名、資格情報がない。安全策を無効化する指示（「テストを飛ばす」「--no-verify を使う」「自動承認」）がない。重要なセキュリティルールは制御（フック、CI、ブランチ保護）でも強制されている | LLM02, LLM08; ASI09 |
| プロンプト / トランスクリプトのログ | `prompt_history*`、`*transcript*`、`.specstory/`、`.claude/projects/**/*.jsonl`、チャットのエクスポート | コミットされていない。コミットされている場合は、シークレット、個人データ、顧客のコンテンツ、内部 URL がないか確認する（漏洩の指摘事項は sensitive-data レーンが担当。gitleaks はトークンの形式しか検出しない） | LLM02; privacy module; CWE-532 |
| AI 支援の開発ワークフロー | git 履歴、CI、ブランチルール、エージェントの許可リスト | エージェントが自身の出力を承認 / マージ / デプロイできない。AI が作成したコミットは別の人間がレビューする。エージェントとの共著コミットは MR を通じて取り込まれる（デフォルトブランチで `git log --first-parent`） | AISVS 1.01 AC.4.1, AC.8.1, AC.8.4; CICD-SEC-1 |
| 実行またはリダイレクトを行う設定 | `statusLine.command`、`apiKeyHelper`、`awsAuthRefresh`、`awsCredentialExport`、`otelHeadersHelper`。`*_BASE_URL` を含む `env`（トランスクリプト全体 + キーがプロキシに送られる）、`HTTPS_PROXY`、`NODE_OPTIONS`、`NODE_TLS_REJECT_UNAUTHORIZED=0`。`additionalDirectories`、`Read(~/.ssh/**)`。`sandbox.enabled:false`、`allowUnsandboxedCommands`。`disableAllHooks`。`enabledPlugins` / `extraKnownMarketplaces`（チーム全員に適用されるサードパーティプラグイン） | コマンドはコードと同様にレビューする。モデルの通信をリダイレクトしない。外向き通信を許可する場合は常にシークレットのパスを拒否する（`Read(.env*)`、`~/.ssh`、`~/.aws`） | ASI02, ASI04, LLM02 |
| 動的コンテキストとメモリ | SKILL.md / コマンド内の `` !`cmd` `` 行は読み込み時に実行される。スキル / エージェントの frontmatter 内のフックや MCP サーバー。エージェントの `memory:`。`disable-model-invocation` のないデプロイ / 公開スキル。無関係な依頼を拾ったりユーザーのスキルを覆い隠したりする広すぎるスキルの説明 | すべての `!` コマンドをレビューする。永続メモリはスコープ化する。デプロイスキルは手動実行のみ | ASI04, ASI06, LLM01 |
| フックイベント | ネットワークから取得またはネットワークへ送信する `SessionStart` / `UserPromptSubmit` / `Stop` フック（リポジトリを開くだけで発動 - 持ち出す場合は P0）。`PostToolUse` での自動コミット / push | フック内でネットワークを使わない。自動公開しない | ASI02, ASI05 |
| CI で実行されるエージェント | `anthropics/claude-code-action`、`openai/codex-action`、Copilot coding agent（`copilot-setup-steps.yml`）、CodeRabbit / BugBot、パイプライン内の `claude -p` | `issue_comment` / `pull_request_target` / `issues` トリガーが `${{ github.event.*.body }}` を `contents: write` やシークレットを持つエージェントに渡す = CICD-SEC-4 + ASI01（P1、デプロイシークレットがあれば P0）。`allowed_tools` がスコープ化されている。書き込み権限のないユーザーはトリガーできない | CICD-SEC-4, ASI01, ASI03 |
| 危険な CLI フラグ | スクリプト、Makefile、package.json、CI、ドキュメント: `--dangerously-skip-permissions`、`bypassPermissions`、`--yolo`、`--full-auto`、`danger-full-access`、`approval_policy="never"`、`--trust-all-tools`、Aider の `yes-always`、Gemini の `autoAccept`（2025 年の Nx「s1ngularity」マルウェアは、インストール済みのエージェントをこうしたフラグで操った） | 隔離されたサンドボックスの外では一切使わない | ASI02, ASI03 |
| IDE とその他のエージェントの対象面 | `.vscode/tasks.json`（`runOn: folderOpen`）、`.vscode/settings.json`（`chat.tools.autoApprove`）、`.devcontainer/devcontainer.json`（`initializeCommand` はホスト上で実行される、マウント）、`.continue/config.*`、`.aider.conf.yml`、`.clinerules`、`.roomodes`、`.github/prompts/`、`.github/instructions/`、`CLAUDE.local.md` | 開いただけで何も実行されない。自動承認がない | ASI02, ASI04 |
| ルールを変更できるのは誰か | `.claude/**`、`CLAUDE.md`、`AGENTS.md`、ワークフローをカバーする CODEOWNERS / ブランチ保護。指示ファイル内のリモートインクルード（「https://... からルールを取得」）や `@~/` インポート | エージェント設定の変更にはオーナーのレビューが必要 | CICD-SEC-1; SLSA v1.2 Source |
| MCP の深掘り | ローカル stdio サーバー: ツールの説明を読む（ポイズニング、MCP03）。静的な `headers` のベアラートークン。環境全体を `env` でパススルー。`/` や `~` をルートとするファイルシステムサーバー。本番の接続文字列を持つ DB サーバー。ブラウザサーバー（インジェクション + 持ち出し）。レビューしていないリモートサーバー = 欠落として明記 | MCP03, MCP01, MCP02, MCP10 |
| 隠し Unicode | 指示ファイル、スキル、コード内のゼロ幅、bidi（Trojan Source）、タグ文字（U+E0000-E007F） - `agent_config_audit.py`（`hidden-unicode`）が列挙する | 指示ファイルでの検出は 1 件でも P1 の手がかり | LLM01; CWE-1007 |
| 履歴内のログ | HEAD では削除されているが git 履歴に残っているプロンプトログ（`agent_config_audit.py` が列挙する） | 履歴を書き換えるか、漏洩したものすべてをローテーションした上で受容する | LLM02; CWE-532 |

ツール設定の重大度: 事前承認された書き込み / 実行 / 公開操作に到達する信頼できないコンテンツ、
フェイルオープンするブロッキングフックや deny ルール、シークレットや個人データを含むコミット済みプロンプトログ
（下限：`reference/method/triage.md`）。信頼できない入力の経路がない広範な許可リスト、
固定されていないベンダリング済みスキル、固定されていない MCP の起動 = P2。来歴の記録の欠如 = Info。

## AISVS 1.01 章ルーター（検証可能な要件として引用）
最新の安定版: **1.01**（OWASP/AISVS README）。1.0 は 2026-06 にリリース。章: C1 Training Data、C2 Input
Validation、C3 Model Lifecycle、C4 Infrastructure、C5 Access Control、C6 Model Supply Chain、C7 Model
Behavior/Output、C8 Memory/Vector DB、C9 Orchestration and Agentic、C10 MCP Security、C11 Adversarial
Robustness、C12 Monitoring/Logging。引用前に公開テキストでサブ要件 ID を確認する。
**Appendix C = AI-Assisted Secure Coding（AI 支援によるセキュアコーディング）。** その職務分離の制御 - AC.4.1（AI が生成した
コードを別の人間がレビューする）、AC.8.1（エージェントは自身の出力を承認/マージ/デプロイできない）、
AC.8.4（生成、レビュー、承認、デプロイを別々の主体が行う） - は、本スキルが監査対象に対して読み取り専用である理由であり、
AI エージェントがコードをコミットするリポジトリではそれ自体が監査チェック項目となる。

## どの基準を主とするか
LLM 固有の弱点（プロンプトインジェクション、過剰な権限委譲、出力処理、無制限な消費、
エージェントの ID） -> 主は `OWASP Top 10 for LLM Applications 2026` / `Agentic 2026` とし、Web の
カテゴリを `also_maps_to` に入れる。モデルが単に到達するだけの古典的な Web のバグ（ツール引数経由の SQL インジェクション、
ツール内の IDOR） -> 主は `OWASP Top 10 2025` / `API Security Top 10 2023` とし、LLM
または Agentic の ID を `also_maps_to` に入れる。いずれの場合も両方の ID を記載する。

## 重大度の目安
- 書き込み/金銭/持ち出しの能力を持つツールに到達する間接プロンプトインジェクション -> P0/P1。
- モデル出力が `eval`/シェル/SQL に渡る -> インジェクションとして扱う（到達可能性に応じて P0/P1）。
- 公開 LLM エンドポイントでのクォータの欠如 -> コストが発生する場合は P1（LLM06 + API4）。
- システムプロンプト内のシークレット -> P1（プロンプトがクライアント側にある場合は P0）。
- 1 つのエージェントにプライベートデータ + 信頼できないコンテンツ + 持ち出し経路（「致命的な三要素（lethal trifecta）」）（下限：
  `reference/method/triage.md`）。
- フェイルオープンするガードレール -> 無効化された制御、P1 が下限。
