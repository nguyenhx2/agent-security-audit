# 変更履歴 - security-audit

## バージョン管理ルール

バージョン = `1.y.z`。メジャー番号は **1** で固定。

| 部分 | 上げる条件 | 例 |
|------|-----------|----|
| `y`（大きな更新） | 利用者が気付く新機能、出力形式、ワークフローの変更 | 新しい報告書形式、新しい言語、深さモード、サブエージェントのオーケストレーション |
| `z`（小さな変更） | 修正、改善、文言、基準・スキャナデータの更新、既存機能内の新しいチェック | 秘匿化の修正、新しいスイープパターン、基準バージョンの再検証、新しいセルフテストケース |

`y` を上げたら `z` は 0 に戻す。リリースごとに日付付きの項目をここに追加し、新しいものを先頭に置く。見出しは
`## [X.Y.Z] - YYYY-MM-DD`（Keep a Changelog 形式）とし、同じ小見出し（追加 / 変更 / 修正 / 削除 - 空の見出しは
省略）を使う。リリース時は次の 3 つをまとめて更新する：
このファイル、`SKILL.md` の `metadata.version`、`SKILL.md` 冒頭の "Skill v..." の行。
基準またはスキャナのピンを再検証した場合は、`metadata.standards-verified` /
`scanner-pins-verified`、`reference/standards/index.md` の表、`scripts/run_scanners.py` の
`PINS_VERIFIED` も更新する。これは `z` の更新とする（モジュールの追加・削除がある場合は `y`）。

## [1.15.1] - 2026-10-30

実際の監査で見つかった修正。補助スクリプトがレーンに誤った、または空の出発点を渡していた 5 か所を直した。

### 修正
- IPA のガイド（または日本の基準）を引用する日本語の報告書が、検証で「English prose in a ja report」に
  なって不合格になることはなくなった。ja 報告書の基準の表では日本の基準を日本語名で示し、英語の文章の
  チェックは正規の基準名を数えない。
- OpenAI v3 SDK（`OpenAIApi`、`createChatCompletion`、`createCompletion`、旧来の `function_call`）を使う
  アプリについて、AI・エージェントの構成一覧が「AI コンポーネントは見つからなかった」と示すことはなくなった。
  `package.json`、`requirements*.txt`、`pyproject.toml` にある LLM / エージェント SDK への直接の依存も一覧に載る。
- 小規模な EC のバックエンド（注文、クーポン、配送、決済ゲートウェイ）は、ショップの用語が 1-2 ファイルに
  しかなくても業種 `ecommerce` として検出する。カード決済と返金だけでリポジトリを `finance` と判定することは
  なくなった。`finance` には銀行、証券、元帳のシグナルが必要。
- ルートマップは、隣のルート、コメント、文字列の中のミドルウェア名を理由に Express のルートを認証済みと
  示すことはなくなった。マーカーはそのルート呼び出し自身の引数からだけ取るので、認証のないエンドポイントが
  authz レーンから隠れない。
- `fetch(request, env)` のハンドラ（Cloudflare Workers、Deno、Bun）を「ルート 0、ギャップ 0」と報告することは
  なくなった。リテラルのルート（パスの `Map` やオブジェクト、`pathname ===`、`case "/x":`、
  `pathname.startsWith`）を一覧にし、振り分けを読み取れないハンドラは明示的なギャップとする。

## [1.15.0] - 2026-10-26

業種と日本の基準、基準ベースラインの全面的な再検証、最新のスキャナのピン。

### 追加
- `detect_stack.py` の業種の検出：依存関係（FHIR / HL7、Plaid、全銀、ウォレットとチェーンのライブラリ、EC
  プラットフォーム、LTI、MQTT / IoT の SDK、Modbus / OPC UA / S7 / BACnet、CAN / UDS）とキーワードを含むファイル
  （`karte`、`monshin`、`kanja`、`zengin`、`furikomi`、`kouza` などの日本語のローマ字の識別子を含む）から
  `sectors`（medical、finance、crypto、ecommerce、government、education、iot、ot、automotive）を判定する。
  各業種は基準モジュールを 1 つ追加し、プロファイルに表示され、重点の質問（en / ja）で名前が示され、業種を検出すると
  法域の質問が出る。閾値は既知の誤検知を避ける（`sku` / `coupon` 単独は使わない：クラウド SDK は SKU を使う）。
- 業種別モジュール。それぞれにコードから根拠を示せる確認項目、重大度、引用の注記がある：
  - `reference/standards/medical.md`（M01-M07）：医療情報システムの安全管理に関するガイドライン 第7.0版
    （`MHLW Medical Information Security Guidelines`、2026-06-29。新設の保守委託機関編を含む 5 編構成）と、医療情報を
    取り扱う情報システム・サービスの提供事業者における安全管理ガイドライン 第2.0版
    （`MIC/METI Medical Service Provider Guidelines`、2025-03-28）。項番は公開本文と照合済み（システム運用編
    14.1.1、14.2、13.1-13.3、7.2、12.2、17.1、総務省・経産省 5.1.4、5.1.5、別紙2）。HIPAA、GDPR Art. 9、PDPL への
    参照。あらゆる医療システム向けに記述し、アプリ固有の名前は例にすぎない。
  - `reference/standards/finance.md`（F01-F10、C01-C06）：金融機関等コンピュータシステムの安全対策基準・解説書
    第14版（`FISC Security Guidelines`、2026-03。区分 統制 / 実務 / 設備 / 監査基準 で引用し、本文が有償のため項番は
    未検証）、金融分野におけるサイバーセキュリティに関するガイドライン（`FSA Cybersecurity Guidelines`、2024-10-04、
    項目は別紙18 による）、暗号資産の管理（ホット / コールドの分離、単独の署名者を置かない、鍵の保管、出金の管理、
    2024 年の DMM Bitcoin の事案の教訓）、GLBA Safeguards Rule、NYDFS 23 NYCRR 500、Vietnam Circulars 09/2020 と
    50/2024。
  - `reference/standards/ecommerce.md`（E01-E11）：クレジットカード・セキュリティガイドライン 6.1版
    （`Japan Credit Card Security Guidelines`、2026-03-11）：カード情報の非保持化、決済画面のスクリプトの完全性、
    EC サイトの 5 つの脆弱性対策、カード不正利用の制限、EMV 3-D セキュア、会員登録 / ログイン / 属性変更時の
    ログイン不正対策。ベトナムの E-commerce Law 122/2025 + Decree 248/2026。
  - `reference/standards/public-sector.md`（G01-G08）：政府機関等のサイバーセキュリティ対策のための統一基準群
    令和7年度版（`Japan Government Unified Standards`、パッチ管理の改定 2026-06-12）、ISMAP / ISMAP-LIU、
    サイバー対処能力強化法（`Japan Active Cyber Defense Act`、報告義務は 2026-10-01 から、二次情報）、
    Vietnam Decree 85/2016（根拠法が置き換えられたことの注記付き）と Cybersecurity Law 116/2025。
  - `reference/standards/education.md`（D01-D08）：教育情報セキュリティポリシーに関するガイドライン
    （`MEXT Education Information Security Guidelines`、2025-03）、FERPA、COPPA（2025 年改正、遵守義務は
    2026-04-22 から）。
  - `reference/standards/iot-ot.md`（T01-T11）：JC-STAR、ETSI EN 303 645 V3.1.3、EU CRA、IEC 62443
    （3-3、4-1、4-2）、UN R155 / R156。
- `owasp-web.md` Part E：IPA の 安全なウェブサイトの作り方（`IPA How to Secure Your Web Site`、改訂第7版 第4刷、
  2021-03-31）の項目 1.1-1.11 を OWASP Top 10:2025、ASVS 5.0.0、CWE に対応付けた。根本的解決と保険的対策の区別。
- `privacy.md`：個人情報保護法（Japan APPI）の条文の対応表（第20条第2項 要配慮個人情報の取得の同意、第23条
  安全管理措置、第24条-第25条 監督、第26条 漏えい等の報告と施行規則 第8条の期限、「概ね3～5日以内」については
  個人情報保護委員会のガイドライン 3-5-3-3、第27条-第28条 第三者提供と外国にある第三者への提供）。番号法
  （`Japan My Number Act`）。電気通信事業法の外部送信規律（2023-06-16）。
- 基準の正規名（バリデータ、報告書）：Japan My Number Act、IPA How to Secure Your Web Site、
  MHLW Medical Information Security Guidelines、MIC/METI Medical Service Provider Guidelines、FISC
  Security Guidelines、Japan Credit Card Security Guidelines、FSA Cybersecurity Guidelines、Japan
  Government Unified Standards、ISMAP、Japan Active Cyber Defense Act、MEXT Education Information
  Security Guidelines、JC-STAR、Japan Telecommunications Business Act、ETSI EN 303 645、IEC 62443、
  UN R155、UN R156、FERPA、COPPA、GLBA Safeguards Rule、NYDFS 23 NYCRR 500、Vietnam Decree 85/2016、
  Vietnam Circulars 09/2020 と 50/2024、Vietnam E-commerce Law。日本語の別名と一般的な別名
  （3省2ガイドライン、安全なウェブサイトの作り方、FISC Safety Standards、個人情報保護法、番号法 など）。
- カバレッジチェックリスト：「業種」の確認。lane-reviewer：各レーンがカバーする業種の行。
- 評価 18（日本のクリニック向け API）と 19（日本のオンラインショップ）。業種の検出、業種とモジュールファイルの
  対応、日本の基準の正規名、重点の質問のセルフテスト。

### 変更
- 基準ベースラインを 2026-10-26 に再検証（全行）：OWASP Top 10:2025 は確定版（RC 表記は 2025-12-24 に削除）。
  ASVS 5.0.0 の日付は 2025-05-30。MASVS 2.1.0 の日付は 2024-01-18（2026-06 と記載していた）、MASTG 2.0.0 は
  2026-06-30、MASWE 1.0.0 を追加（2026-08-17）。AISVS 1.01 は 2026-10-16 にリリース。LLM Top 10 2026 の日付は
  2026-08-03。PCI DSS v4.0.1 に 2026 年の意見募集についての注記。SSDF v1.2 はまだドラフト。日本と業種の行を
  追加。`standards-verified` は 2026-10-26。
- スキャナのピンを 2026-10-26 に検証：semgrep 1.181.0、trivy 0.76.1（eMudhra の CA 鍵侵害に対するセキュリティ
  修正。公開から 5 日しか経っていないが採用）、checkov 3.3.29、zizmor 1.31.1（`issue_comment` を危険なトリガーとして
  検出するようになった。1.31.0 は見送り）。gitleaks、osv-scanner、hadolint、mobsfscan は変更なし（ダイジェストは
  再確認済み）。`env_check.py` と `platforms.md` のネイティブインストールのピンもこれに合わせた。
- SKILL.md の description に業種の検出と業種別の規則を記載（英語版は 1016 文字、日本語版は 639 文字）。
- SKILL.md、CHANGELOG、README から作成者の行を削除。作成者と AGPL-3.0-only のライセンスはリポジトリ
  （github.com/nguyenhx2/agent-security-audit）とプラグインのマニフェストに記載する。
- CHANGELOG の見出しを Keep a Changelog 形式 `## [X.Y.Z] - YYYY-MM-DD` に統一。

### 修正
- FISC は第14版（2026-03）として、区分までで引用する。確認できない項番では引用しない。
- 厚労省の第7.0版を、新設の保守委託機関編を含む 5 編構成として記載。
- APPI の安全管理措置は第23条として引用する（第20条は適正な取得）。
- `privacy.md` の検証に関する注記（二次情報、Vietnam Decree 85、HIPAA の規則案）は残し、実際に再確認した行
  にだけ新しい検証日を付けた。
- `ipa` 単独の別名は置かない：IPA の注意喚起は根拠であり、IPA のウェブサイト向けガイドラインではない。
- IPA の表でクリックジャッキングを Top 10:2025 A02（設定ミス）に対応付けた。
- `detect_stack.py` のキーワード信号で `_` を語の区切りとして扱うように修正。`\b...\b` のパターンでは
  `patient_id`、`kanja_id`、`bank_account_id` のようなスネークケースの識別子を検出できなかった。IoT の信号は
  `firmware_version` や `secure_boot`（サーバーの資産情報やクラウド VM の設定）では検出しないようにし、
  ファームウェア更新・イメージの語、RTOS、MQTT、CoAP、IoT SDK を条件とした。いずれもオフライン評価で発見。
- SKILL.md に「最後まで実行する」を追加：Phase 0 の後は確認のために止まらず Phase 7 まで進める。ライブ
  ベンチマークで、ヘッドレスのクイック実行が指摘事項を書く前に止まり、報告書が残らなかった例を発見した。

## [1.14.0] - 2026-10-26

最新の脅威情報と、インシデントを起点としたカバレッジ：リポジトリがデプロイするもの（ランタイム、サーバー、
データストア、ベースイメージ、管理ツール、フレームワーク）を、監査時に取得した海外と国内の公開勧告フィードと照合し、
最近のインシデント報告の背景にある露出と侵害時の影響範囲のクラスを、誰かがインシデント名を挙げるのを待たずに探す。

### 追加
- `scripts/platform_inventory.py`（Phase 1、すべての深さ、ネットワーク不要）：Dockerfile（`ARG` の既定値と
  マルチステージビルドを含む）、compose / Kubernetes / Helm のファイル、バージョンファイル（`.tool-versions`、
  `.nvmrc`、`.php-version` など）、`composer.json` / `package.json` / `pyproject.toml` のバージョン制約、CI の
  セットアップ手順、サーバーレスのランタイム、フレームワークのロックファイルの項目で指定されたバージョンを、精度
  （exact / minor / range / floating / distro / managed）と context（deploy / build / ci / dev / declared）とともに
  一覧にする。露出とハードニングのシグナル：Web ルート配下の機微なファイル、`phpinfo()`、ディレクトリ一覧表示、
  危険な `php.ini` 設定、管理 / BI ツールのイメージ、公開されたデータストアのポート、actuator と Tomcat manager の
  露出、root で動くコンテナ、実行イメージ内のダウンロードツール、リモートの `ADD`、固定されていないベースイメージ、
  NetworkPolicy なし、セキュリティグループの全宛先への egress、ベースイメージの自動更新なし。
- `scripts/threat_intel.py`（バックグラウンド、監査ごとに 1 回）：一覧を CISA KEV（取得できなければ GitHub の
  ミラー）、NVD CVE API 2.0（CPE + バージョン）、FIRST EPSS、endoflife.date、IPA・JPCERT/CC・JVN・JVN iPedia の
  RSS フィードと照合する。送信するのは製品名とバージョンのみ。ホストの許可リスト、外部ホストへのリダイレクト拒否、
  サイズと時間の上限を設ける。フィードの文章は無害化（制御文字、双方向制御文字、ゼロ幅文字を除去）してデータとして
  扱う。応答はフィードごとの TTL でキャッシュし、フィードが停止しているときは再利用する。`--offline` はキャッシュのみを
  使う。取得できない、または停止中のフィードは未カバー領域として明記する。優先度：act-now（指定バージョンに KEV または
  国内の注意喚起の対象 CVE がある）、review（EOL、バージョンが一致しない注意喚起、深刻な CVE）、update（最新パッチより
  古い）。
- `reference/method/threat-intel.md`：フィードの一覧、バージョン精度の規則（タグ追従、ディストリビューションの
  バックポート、マネージドランタイム、範囲指定）、重大度の下限、勧告を必要としない予防的な確認（緊急パッチへの備え、
  露出、侵害時の影響範囲、検知、データの最小化）。
- 報告書の第2節「プラットフォームのバージョンと脅威情報」（en / ja）を `intel.json` から作成：サポートまたは勧告上の
  問題がある構成要素、勧告の ID、確認したフィードとその日付、取得できなかったフィード。
- `validate_findings.py` は、KEV または国内の注意喚起の対象 CVE、あるいはサポート終了のデプロイ済み構成要素が、
  どの指摘にも含まれず Refuted にも記載されていない場合に警告する。
- カバレッジチェックリスト：新しいセクション「露出、パッチ適用状況、侵害時の影響範囲」（パッチ適用状況、EOL、緊急パッチ
  への備え、Web ルートのファイル、管理プレーン、管理 / BI ツール、アップロードからの実行、ビルドコンテキスト、侵害時の
  影響範囲、フォレンジックへの備え）と、次の新しい行：トークンの有効性オラクル、レート制限のキーと適用範囲、
  クライアント IP ヘッダーの信頼、長期間有効なトークン、偽装可能なゲートウェイの ID、安全でない設定のフォールバック、
  アカウント連携、MFA の迂回、SAML、スコープを迂回するデータアクセス、署名付き URL、検索インデックス、失効、
  参照されない特権ルート、NoSQL 演算子インジェクション、エクスポート / インポートの範囲、キューのコンシューマー、
  解凍爆弾、認証前のコスト、共有キャッシュからの漏洩、リクエストスマグリング、ブラウザのメッセージング、
  CI キャッシュの汚染、ネイティブコード。
- 評価 16-17（最新の勧告のトリアージ、Standard での国内注意喚起の確認）。

### 変更
- トリアージ：KEV / 国内注意喚起の対象となるランタイムの CVE、および露出した管理ツールと Web ルートのシークレットに
  重大度の下限を設定。P0-P2 のすべての候補に境界の行（主体 -> 突破される制御 -> 影響を受けるリソース）を必須とし、
  書けなければハードニングの注記（Info）とする。`needs-runtime-check` は判定を決めるデプロイ上の事実を明記する。
  P0/P1 の後に派生パターンを洗い出す。同じ効果に至る最も弱い経路を指摘とする。依存関係の優先順位に国内の注意喚起を追加。
- レーンに `platform=` と `intel=` を渡す。ランタイムと露出の指摘は supply-chain-infra グループが受け持つ（そのレーンを
  実施しない場合はリード）。レーンのブロックは `boundary:` を持ち、レーンは `## Hardening` と `## Reviewed` を列挙する。
  途中で打ち切られたレーンでも最も危険な領域を確認済みになるよう作業順を決める。偵察はルートとクライアントの呼び出しを
  突き合わせ、デバッグ用スイッチとセキュリティ関連の TODO を文字列で一通り探す。
- `collect_lanes.py`：boundary 列と Hardening セクション。検証エージェントは境界が成り立たない候補を格下げし、
  ハードニングの注記を一覧にする。
- 基準モジュール：管理 / デバッグのプレーン、Web ルートの露出、設定のフォールバック、ランタイムのパッチ適用状況、
  NoSQL 演算子インジェクション、フォレンジックへの備え（owasp-web）。レート制限のキーと適用範囲（owasp-api）。
  露出、侵害時の影響範囲、イメージのパッチ適用状況（cloud-iac）。ロックファイル外のランタイムと製品のパッチ適用状況
  （supply-chain）。5 つの設計上の欠陥の探し方（隠れたルート、スコープのない 1 つのクエリ、信頼された ID ヘッダー、
  最も弱い経路、失効）。
- `prune_work.py` は `platform.md` と `work/intel.md` も削除する。`platform.json` と `intel.json` は残す
  （報告書と検証スクリプトが読む）。
- SKILL.md の description に勧告フィードを明記し（日本語版は 669 文字）、対象外のものを記載。

## [1.13.0] - 2026-10-14

監査 1 回あたりの AI のターン数とトークンを削減：サブエージェントが以前は Read/Grep で見つけていたものをスクリプトが
渡すようになり、スキャナの誤検知はルールで反証され、言語が 1 つの監査ではその言語で直接ドラフトを書く。

### 追加
- `scripts/route_map.py` - 静的なエンドポイントマップ（FastAPI、Flask、Django/DRF、Express/Koa/Fastify、
  NestJS、Spring、Laravel、Rails）：メソッド、ルーターのプレフィックスを適用した完全なパス、ハンドラの `file:line`、認証
  マーカー、グローバルな認証、認証マーカーのないルート（手がかり）、解析しなかったフレームワーク（欠落として）。
  `routes.md` + `routes.json` を書き出し、偵察と authz レーンはこれを起点にする。
- `scripts/lane_pack.py` - レーングループごとに、バイト予算内でマスク済みのコード抜粋パックを 1 つ作成する
  （シークレットを含むファイルは名前のみ、"Left out" の一覧付き）。レーンはこれを最初に読み、そこに欠けているものだけを
  Read/Grep する。
- `repo_digest.py --json` - lane_pack 用に、ダイジェストの索引を JSON で出力する。
- `normalize_findings.py` でのルールによる自動反証：プレースホルダーのシークレット値、ベンダリングされたドキュメント、
  テストファイル内の本番専用 SAST ルールに `auto_refuted` を付け、summary（"auto-refuted N"）と
  `lanes/candidates.md` に列挙し、レーンには割り当てない。検証エージェントはそれらを Refuted に写す。履歴のみの検出、
  実際の鍵形式、高エントロピーの値には決して適用しない（`reference/method/triage.md`）。実際の監査で調整済み：反証された候補
  37 件中 33 件が自動反証され、登録済みの指摘事項 38 件中の影響は 0 件。
- `validate_findings.py --lang <code>` - ja（zh、ko）の一式に対する英語本文のチェックを `--report` なしで
  実行できる。検証エージェントの自己チェックはこれを渡す。

### 変更
- 報告書の言語が 1 つの場合：検証エージェントが指摘事項をその言語で直接ドラフトし（`lang=`）、そのドラフトが
  正本となり、翻訳は実行しない。翻訳は報告書の言語が 2 つ以上の場合にのみ実行する。
- `prune_work.py` は `packs/`、`digest.json`、`routes.md`、`routes.json` も削除する（報告書は
  これらを読まない）。
- 基準を 2026-10-13 に再検証（すべて最新）。評価の引用を LLM Top 10 2026 に更新。

## [1.12.0] - 2026-10-01

スキル全体の全面的な再監査（コード、指示、基準）と、クロスプラットフォーム対応。
本版は日本語版である：スキル全体（SKILL.md、サブエージェント定義、参照資料、テンプレート、評価、スクリプトのコメント・ヘルプ・メッセージ）を日本語化し、リリース前にスキル全体を全面的に再監査した。

### 追加
- `scripts/env_check.py` - すべての OS での Phase 0 の最初の手順：Windows / macOS / Linux / WSL、
  使用する Python コマンド（`py -3`、`python3`、`python`。>= 3.9 と openpyxl の有無を確認）、シェル、
  Docker または Podman とそれが応答するか、SELinux、ネイティブのスキャナ、Excel の検証方法、git を検出し、
  `choices`（スクリプトのプレフィックス、スキャナの方式、待機ループ、パスの形式、OS ごとのインストール手段）を出力する。
- `reference/tooling/platforms.md` - スキルが使うすべてのツールについての OS ごとの代替手段。
- `run_scanners.py --engine auto|docker|podman`。Linux / macOS ではコンテナを現在のユーザーで実行し
  （root 所有の出力を作らない）、Podman では `--userns=keep-id`、SELinux のホストでは `label=disable` を使う（`:z` は
  決して使わない - 再ラベル付けは監査対象リポジトリに書き込むため）。残った root 所有のファイルは所有者を戻す。
- Excel がない環境向けに、`render_xlsx.py --verify` で LibreOffice をヘッドレス実行（使い捨てのプロファイル）。
  `--verify-with excel|libreoffice`。どちらもない場合は "VERIFY SKIPPED"（exit 0）。
- `scripts/safegit.py` - すべてのスクリプトが使う、読み取り専用の git ヘルパー 1 つ。
- `scanners.json` に、スキャン時点の監査対象コミット、エンジン / ユーザー / SELinux の判断、
  スキャナの結果を抑制し得るリポジトリ内のファイル（`repo_scanner_configs`）を記録する。

### 修正
- 監査人自身のセキュリティ：git が監査対象リポジトリの `.git/config` にある `core.fsmonitor` のコマンドを実行し、
  `git status` がそのインデックスを書き換えていた - すべての git 呼び出しで fsmonitor とオプションのロックを無効化し、
  一切書き込まないようにした。gitleaks の履歴スキャンでリポジトリの textconv / 外部 diff ドライバを実行しなくなった
  （`--no-textconv --no-ext-diff`）。gitleaks と hadolint のコンテナは `--network none` で実行する。
- リポジトリが用意したスキャナ設定で結果を抑制できなくなった：gitleaks は実行時の既定設定を使い
  リポジトリの許可リストを無視し、zizmor は `--no-config`、semgrep は `--disable-nosem`、osv-scanner は空の
  設定を使い、ネイティブのツールはリポジトリの外で実行する。無効化できないもの（`.gitleaksignore`、
  `.checkov.yaml`、`.semgrepignore`）はカバレッジの欠落として列挙する。
- マスキング：CLI のシークレット（`--password=`、`-pSecret`、`-u user:pass`、`--token`）、`*_KEY` / `*_PIN` の
  値、YAML / CSV / properties 内の引用符なしの個人データ（生年月日、カナ氏名、日本の
  住所）、YAML のブロックスカラーをマスクする。納品前のゲートも同じ形を検査する。根拠
  （パス、`path:line`、コード、型）は読める状態のまま残す。
- 監査対象リポジトリの外を指すシンボリックリンクはスキップして件数を数える（ホストのファイルは読まない）。
- すべてのコンソールとパイプ（cp932 / cp1252）で UTF-8 を出力する。BOM 付き、UTF-16、JSONC の設定ファイルを
  黙って取りこぼさずに解析する（`bypassPermissions` の設定を見逃していた）。解析できないファイルは
  手動レビュー用に列挙する。
- 報告書を再ビルドしても、監査時のスキルバージョン、基準の日付、タイムスタンプ、コミットを維持する
  （`report-settings.json`。再導出は `--refresh-meta`）。報告書の該当箇所の列は
  Location セクションのみを読む。タイトル中の `|` で表が崩れなくなった。空白を含むパスをどこでも受け付ける。
- リポジトリにコミットされたデータファイルがある場合でも、スイープの要約で手がかりの件数が隠れなくなった。
- 履歴から削除されたプロンプトログを、名前が非 ASCII の場合でも検出する。
- サフィックスのない報告書について、Excel と HTML が同じ指摘事項の言語を選ぶ。日本語の報告書では
  カバレッジの欠落の文言と Excel の入力規則のメッセージをローカライズする。
- `prune_work.py` は削除できないファイル（例：root 所有）を修正コマンド付きで報告し、
  エージェントの `scratch/` フォルダを削除する。
- 指示：翻訳の開始（Phase 7 の手順 2b）、ソース言語が選ばれていない場合のビルド、
  `--lang-suffix`、`--force --fill` による再ビルド、Phase 8 の再スキャン手順（ステータスの更新先、
  `--offline` の制限）、Standard/Deep での偵察の委任、scratch フォルダ、参照資料・
  テンプレート・評価内の古いパス、指摘事項テンプレートの frontmatter の順序、評価 14 のパスのエスケープ。

### 変更
- `allowed-tools`：PowerShell のルールを削除（Claude Code では置換されないため。スクリプトは
  Bash ツールで実行する）。Podman の読み取り専用コマンドを追加。`compatibility` に Claude Code 専用であることと
  対応 OS を記載。description を短縮（英語版で 992 文字）。
- 日本語版：英語が必要な箇所（コード、コマンド、パス、規格名・ID、スクリプトが照合する文字列、英語レポート用の文言）を除き全文を日本語化

## [1.11.0] - 2026-09-30

### 追加
- `scripts/prune_work.py` - Phase 7 で報告書一式の生成と検証の後に `work/` を整理する。
  既定：実行後に誰も読まない中間ファイル（`raw/`、`candidates.jsonl`、レーンノート、
  `findings.draft.json`、ダイジェスト、偵察、スキャナ要約）のみを削除し、再生成、後からの
  翻訳、Phase 8 の再スキャンに必要なものは残す。中規模リポジトリで約 3 MB -> 0.4 MB。`--keep-work`
  はすべて残し、`--purge-work` は `work/` を削除する。報告書が存在する前には実行を拒否し、不明な
  ファイルには一切触れない。
- `SKILL.md` のメタデータとこのファイルに作成者を追加。

### 修正
- `build_report.py`：報告書の日付を監査のタイムスタンプから取るようにしたため、数日後に再生成しても
  監査日が維持される。`<ts>_2` フォルダ（1 分以内に 2 回実行）は報告書名にそのタイムスタンプを保持する。

### 変更
- 基準とスキャナのピンを 2026-09-30 に検証。

## [1.10.0] - 2026-09-29

### 変更
- 出力レイアウト：監査フォルダの最上位には `reports/`、`findings/`、`work/` のみを置く。
  成果物は `reports/md|html|xlsx/` へ、指摘事項ファイルは `findings/<lang>/<repo>/` へ、
  中間ファイルすべて（プロファイル、正準 JSON、翻訳、設定、リポジトリ単位のスキャナ / レーン
  出力）は `work/` へ置く。ルールは `scripts/layout.py` が保持する：build_report は `reports/md/` に書き込み、
  render_html / render_xlsx は `reports/html|xlsx/` に書き込み、`--out` / `--findings` なしで
  `findings/<lang>/` を特定する。`work/` のないフォルダは従来のフラットなレイアウトとして引き続き読み込む。

## [1.9.0] - 2026-09-27

### 追加
- AI とエージェントの対象範囲を独立した領域として扱う：
  - `detect_stack.py` が `ai_scope`（`llm-app`、`agentic-app`、`mcp`、`agent-tooling`）と
    `agent_tooling` のインベントリを報告する。コミットされたコーディングエージェント設定があっても Web API を
    "agentic" アーキタイプとはしなくなった。スキルレジストリは `agent-skills-or-tooling` となる。新しいシグナル：Streamlit、
    Gradio、Chainlit、Ollama、LiteLLM、vLLM、MCP SDK。
  - 検出時、Phase 0 の Focus の質問で「AI, LLM & agents」（検出内容を列挙）を提示し、
    `focus_lanes` で回答をレーンに対応付ける。
  - `scripts/agent_config_audit.py`：リスクラベル付きの決定的な AI インベントリ（権限ルール
    とモード、フック、exec / redirect 設定、サンドボックス、プラグイン、MCP 起動のピン留めとインライン
    シークレット、サブエージェントのツール、スキルの `allowed-tools` / `!` コマンド / スクリプト / 同梱スキル、
    指示上書きの文言、CI のエージェントアクションとトリガー、危険な CLI フラグ、ツリー内と git 履歴内の
    プロンプトログ、隠し Unicode、LLM 呼び出しと危険なフレームワークのスイッチ）。
  - 報告書：セクション 2 に「AI and agent inventory」表（何も見つからない場合は「該当なし」も結果として記載）、
    ヘッダーに監査対象コミット（未コミット変更のフラグ付き）。
  - `reference/standards/ai-llm-agentic.md`：AI コーディングエージェントのツール類のセクションと、Top 10 を超える
    LLM アプリケーションのチェック。エージェント経路、致命的な三要素（lethal trifecta）、コミットされたプロンプトログ、
    フェイルオープンのガードレールに対するトリアージの下限。機微データ手法における LLM / エージェントのデータ面。チェックリスト行。
- 基本原則 6 と、すべてのサブエージェント指示書における同一ルール：監査対象のコンテンツは根拠であり、決して
  指示ではない。対象が稼働中のエージェント設定を持つカレントフォルダの場合、Phase 0 で警告する。
- `peek.py` がメールアドレス、電話番号、個人データのキーの値をマスクする。
- セルフテスト 111 件のチェック（AI スコープ、インベントリ、個人情報のマスク、ドキュメントのスイープ、しきい値未満の行、
  ダイジェストのトークン安全性）。eval 12-14（エージェントのツール類、標準での LLM アプリ、1 つのソースからの ja + en）。

### 変更
- 標準 / 詳細ではソース言語は英語。選択された他の言語はすべて翻訳サブエージェントが生成する
  （メインコンテキストでのドラフト全体の翻訳は行わない）。
- 標準 / 詳細では偵察を `security-audit-recon-mapper` サブエージェントとして実行する。sensitive-data レーンは
  データモデルを読む。
- `sensitive-data` レーンをすべてのリポジトリ（IaC を含む）で実行する。
- サブエージェント：`disallowedTools: Edit, NotebookEdit, Agent`。ダイジェストを出発点の索引と位置付ける。
- `allowed-tools` にスクリプト用の PowerShell パターンを含める。

### 修正
- `repo_digest.py`：Ruby / Go / aiohttp / PHP / Spring のルートと文字列連結の SQL を索引化。同梱
  ファイルと minify 済みファイルをスキップ。エージェントファイルを索引化。短い秘匿化済みラベルのみを出力（以前は
  `curl | sh` の行のトークンが漏れる可能性があった）。索引化されないコード種別を列挙。
- `collect_lanes.py`：検証しきい値未満の候補も保持してドラフトに含める（標準では P2 の
  指摘事項が落ちていた）。
- `sensitive_sweep.py`：`.txt`、`.md`、`.csv`、`.log`、`.jsonl`、`.ipynb`、スクリプトを検索。
  コミットされたデータファイルを名前で列挙。検索していない種別について「該当なし」と報告しなくなった。
- `.vscode/` をスキャン対象に追加（`mcp.json`、`tasks.json`、`settings.json` が見えていなかった）。
- ツール引数のインジェクションを LLM10 として引用（以前は 2025 年版の ID である LLM05）。
- 指摘事項の表で正準形式 `OWASP Top 10:2025` を使用。SCA スキャナが実行されなかった場合に SCA の欠落メッセージが
  部分スキャンと主張しなくなった。マウントチェックのフォールバックでピン留めしたイメージを使用。
- コミットされたエージェントのツール類を持つ FastAPI リポジトリでの実運用で発見：
  - `validate_findings.py` がディレクトリであるアンカー（シンボリックリンクされた同梱スキル）でクラッシュしていた - 現在は
    WARN。読み取れないファイルも WARN。
  - `new_finding.py --source <findings.json>`：翻訳ファイルはすべてのコードフィールドとアンカーを
    正準ソースから取得するため、翻訳後のソース編集で差異が生じない。
  - 日本語の報告書では AI インベントリの対象面とリスクラベルをローカライズ（ja 出力に英語を含めない）。
  - スイープの手がかり：プロンプトログと製品コードを優先し、同梱スキルのドキュメントとルールは最後。
  - `agent_config_audit.py` が exec、ネットワーク、書き込みのコマンド（`curl:*`、`docker compose:*`、`sed:*`）を
    事前承認するコマンド / スキルを検出する。
  - 検証エージェントの指示書：ドラフトに対して `validate_findings.py --repo` を実行する（リポジトリ相対の完全なアンカー）。

## [1.8.0] - 2026-09-25

### 追加
- `scripts/repo_digest.py`：監査ごとに共有されるリポジトリマップ 1 つ（行数付きインベントリ、`path:line` + トークン形式の
  sink/source 索引、シークレットを含むファイル名。行の内容は決して含めない）。偵察とすべてのレーンは
  Glob/Grep でリポジトリを再探索する代わりにこれから開始する。
- `scripts/collect_lanes.py`：すべてのレーンファイルを `lanes/candidates.md` に統合する（候補ごとに 1 行、
  レーン横断の重複グループ、レーンの反証 / 未解決の質問）。検証エージェントはすべてのレーンファイルの代わりに
  これを読む（最初の実運用ではレーンファイルの約 1/5 のサイズ）。
- `scripts/install_agents.py`：指示書を名前付きサブエージェントとして
  `~/.claude/agents/security-audit/` にインストールする（`security-audit-recon-mapper`、`-lane-reviewer`、
  `-finding-verifier`、`-report-translator`）。それぞれ独自のツールリスト、`maxTurns`、`omitClaudeMd` を持つ。
  `--check` / `--uninstall`。自身が書き込んでいないファイルは決して上書きしない。汎用エージェントへのフォールバックは維持。
- `agents/report-translator.md`（翻訳エージェントの指示書。以前はインラインのプロンプト）。
- `tests/package.py`：セルフテストの後、`tests/` やキャッシュを含まないリリース zip を作成。

### 変更
- レーンのサブエージェントをリポジトリのサイズでグループ化する（`detect_stack.py` の `lane_groups`）：小規模リポジトリは 3
  サブエージェント、中規模は約 5、大規模はレーンごとに 1 つ。同じファイルを読むレーンは 1 つのサブエージェントを共有する。
- 検証エージェントは `verifier.md` の隣に `findings.draft.json`（new_finding.py のスキーマ、検証済み）を書き込む。
  Phase 6 ではメインコンテキストですべての指摘事項を書き直す代わりにドラフトを編集する。
- レーンの指示書：ダイジェストを最初に読む。欠陥ごとに 1 ブロックとし、是正策を担当するレーンに記載する（重複ではなく
  レーン横断の参照）。主アンカー = sink。レーンノートは英語。
- `tests/` は開発専用であり、リリース zip には含めない。

## [1.7.2] - 2026-09-24

### 修正
- 報告書の言語に関する質問文（en / ja）で、指摘事項が最初の言語で作成されると記載しなくなった。
  1 つの正準ソースによるフローに合わせた（選択されたすべての言語で完全な一式が生成され、指摘事項は
  同一）。

## [1.7.1] - 2026-09-23

### 変更
- 多言語フローでは、ソース言語（レーンノートの言語、または唯一の報告書言語）で書かれた 1 つの正準 `findings.json` +
  `narrative.json` を使用する。他の言語はすべてそこから並行して翻訳する。
  作成してから逆翻訳する往復は行わない。
- `build_report.py` が指摘事項フォルダごとに深さ / プロジェクト / 言語 / サフィックスを記憶する
  （`report-settings.json`）ため、`--force --fill` での再生成時にフラグを繰り返す必要がない。

### 削除
- ベトナム語のローカライズ。報告書とインターフェースの言語は **英語と日本語**。他の
  言語は引き続き "Other" で利用可能（その言語の本文、英語のラベル）。Vietnam PDPL は適用法域として
  プライバシーモジュールに残り、ベトナム語の個人情報キーワードは機微データのスイープに残る。

### 修正
- レーンの指示書で P0 / P1 / P2 / Info 以外の重大度を禁止（レーンが "P3" を作り出していた）。
- 検証スクリプトが報告書名の `_<lang>` サフィックスを受け付ける。

## [1.7.0] - 2026-09-21

### 追加
- 報告書の言語に関する質問（multiSelect：English / Japanese / Other）。言語ごとに報告書一式を 1 つ生成
  （`findings-<lang>/`、`..._<ts>_<lang>.*`）し、翻訳サブエージェントの役割を設ける。
- `build_report.py --findings-dir / --lang-suffix`。不明な言語コードは英語のラベルにフォールバックする。
- 会話言語の自動検出（`scripts/questions.py`）：Phase 0 の質問はユーザーのメッセージから判定した
  ユーザーの言語で生成する。ユーザー指示（CLAUDE.md）は `--lang` で上書きする。

### 変更
- 既定の深さは **詳細（Deep）**（質問の既定値と `--yes` の既定値）。`detect_stack.py` はより浅い深さを選ぶ代わりに
  リポジトリの `size` のヒントを報告する。
- 質問は 4 つ（Depth、Language、Focus、Formats）を 1 回の呼び出しで行い、個人 / 決済 / 健康 / 金融データが
  検出された場合のみ Jurisdiction について 2 回目の呼び出しを行う。

## [1.6.1] - 2026-09-19

### 修正
- 機微データのスイープ：クライアントの認証情報保存（SharedPreferences / UserDefaults / localStorage）、
  URL に埋め込まれた認証情報、シードされたユーザー（`INSERT [OR IGNORE] INTO users`）、Terraform / 設定ファイルの
  種別。UUID（例：`yor_trace`）をカード番号として検出しなくなった。"fingerprint" を生体情報として扱わなくなった。
- `peek.py` が Terraform / HCL のシークレット変数の既定値をマスクしつつ、名前は読める状態に保つ。
- オフライン時の OSV-Scanner を誤った「クリーン」ではなく、明示された欠落として報告する。
- `detect_stack.py`：`.claude/agents|hooks|skills`、`SKILL.md`、MCP 設定によりリポジトリを agentic と判定。
  `httprouter` / chi を認識。fixture / sample フォルダ内のマニフェストを無視。
- 正規化スクリプトがテスト / vendor / ログのノイズを 1 行にまとめる。実際のシークレットの形状のみを秘匿化する。
- 検証スクリプト：ロックファイルのアンカーは重複排除の候補としない。読みやすいシークレットのラベル。誤検知の削減。

### 変更
- `SKILL.md`：複数リポジトリの命名ルール、`<ts>` の衝突ルール、冒頭に Windows の `py -3` に関する注記、
  バックグラウンドスキャンの待機、「シークレットを含むファイルを決して cat しない」、リポジトリごとのクイックレーン、
  是正アクションごとに 1 つの指摘事項、ロックファイル内の依存関係アンカー、LLM 経由で到達するバグに対する主基準ルール。

## [1.6.0] - 2026-09-18

### 追加
- `scripts/new_finding.py`：1 つの JSON リストから指摘事項を生成する。コードと正準の基準名をチェックし、
  ローカライズされた見出しを書き込み、ID でファイル名を付け、履歴のみに存在するシークレットのアンカーに対応する。
- 名前付きプレースホルダー（`{{key: hint}}`）による `build_report.py --fill` / `--list-placeholders`。
- 検証スクリプトの古い表のチェック：報告書の行は指摘事項ファイル（重大度とアンカー）と一致しなければならない。
- `tests/selftest.py`：すべてのスクリプトのオフラインセルフテスト。スクリプトは `sys.dont_write_bytecode` を設定するため、
  インストールされたスキルに `__pycache__` が生成されない。

## [1.5.1] - 2026-09-17

### 修正
- Excel：Master のリストを動的な名前付き範囲（OFFSET / COUNTA）とした。リストの下に入力した値は
  すべてのドロップダウンに加わる。空の行には事前に罫線を引かない（条件付き罫線により内容が入った時点で行に罫線を引く）ため、
  改ページプレビューには実際の内容のみが表示される。
- Excel のシート名、ドロップダウンの値、Coverage のテキストをローカライズ。HTML の列の折り返し。

## [1.5.0] - 2026-09-16

### 追加
- 報告書の骨組み、HTML インターフェース、Excel のラベル、表示されるステータス / 確度 / 種別、
  指摘事項のセクション見出しに対する共通のローカライズ（`scripts/i18n.py`）。
- 検証スクリプトの言語一貫性ゲート（日本語の監査内に英語の本文があると不合格）。
- 正準の基準名を検証スクリプトで強制。

## [1.4.0] - 2026-09-14

### 追加
- Excel 出力（`scripts/render_xlsx.py`）：Summary（COUNTIFS による統計 + グラフ 4 つ）、Master シートから供給される
  ドロップダウン付きの Findings 台帳、是正の追跡用の Owner / Due date / Notes、Coverage、
  Master。ビジネス文書のレイアウト（Meiryo、罫線付きの表、縞模様なし、余白列、改ページプレビュー）、
  ロゴなし。`--verify` は実際の Excel で再計算し、合計と数式エラーをチェックする。
- 報告書の形式は multiSelect の質問（HTML、Excel）。Markdown は常に生成する。
- 指摘事項のステータス `in-progress`。

## [1.3.1] - 2026-09-12

### 修正
- HTML：データ JSON で `<` / `>` をエスケープ、CSP で sha256 のスクリプトハッシュを使用（インラインスクリプトの許可なし）、
  CSV の数式インジェクション対策、プロトコル相対リンクを拒否。

## [1.3.0] - 2026-09-11

### 追加
- インタラクティブな HTML 報告書（`scripts/render_html.py`）：重大度カード、全文検索、フィルタ、
  並べ替え可能な列、展開可能な指摘事項、ディープリンク、CSV エクスポート、目次。
- `scripts/build_report.py`：指摘事項ファイル、`scanners.json`、`sweep.json` から埋める報告書の骨組み。

### 変更
- ファイル命名：小文字、タイムスタンプ付き（`security-audit-report_<project>_<ts>.*`、`find-<repo>-NNN.md`）。
  テンプレート名を小文字に変更。

## [1.2.1] - 2026-09-09

### 修正
- シークレットの秘匿化を `scripts/peek.py` に統一。スイープが `sweep.json` にシークレットを漏らさなくなった。
  正規化スクリプトと検証スクリプトが同じ検出を使用。サブエージェントの指示書は `peek.py` の使用を必須とする。
- `allowed-tools` のパターンが引用符付きの `python "${CLAUDE_SKILL_DIR}/..."` コマンドに一致する。
- スキャナのピンに `@sha256` ダイジェストを付与。キャッシュ済みイメージは再取得しない。`--offline` では決して取得しない。

### 変更
- 独立したレビューを受けて基準を訂正：OWASP Top 10 for LLM Applications 2026（ID を
  振り直し）、AISVS 1.01 とその職務分離の引用（Appendix C AC.4.1 / AC.8.1 / AC.8.4）、
  MCP Top 10 (beta)、OWASP Non-Human Identities Top 10 2025、CIS EKS / AKS / GKE、PCI DSS 3.3.1.x /
  6.3.3 / 6.4.1-2 / 8.4.2 / 8.6.2 の範囲、RFC 9700 / RFC 8725 / WebAuthn、GraphQL / WebSocket / gRPC。
- 手法：偵察に悪用シナリオのステップを追加、依存関係の優先順位付け（MAL > KEV > EPSS > CVSS v4、到達可能性、
  最小の修正済みバージョン）、クライアント成果物の強制ルールを認証情報に限定。
- `reference/` を `standards/`、`method/`、`tooling/` に再編。サブエージェントのオーケストレーションを
  `reference/method/orchestration.md` に移動。

## [1.2.0] - 2026-09-07

### 追加
- 深さモード（クイック / 標準 / 詳細）とサブエージェントの指示書（`agents/recon-mapper.md`、
  `lane-reviewer.md`、`finding-verifier.md`）、およびモデル / effort のマトリクス。
- AskUserQuestion による範囲設定（深さ、重点、形式、適用法域）と `--yes` による省略。
- 反証を試みる指摘事項の検証エージェントと確度の軸（確認済 / 可能性高 / 実行時確認要）。
- プロジェクト種別をまたぐシナリオ eval を含む `evals/evals.json`。

## [1.1.1] - 2026-09-05

### 修正
- Windows の Python で Git-Bash の `/c/...` パスが誤って解決されていた。すべてのスクリプトでこれを正規化し、
  `--repo` が存在しない場合は明示的にエラーとする。
- スイープが単純な `password TEXT` 列とインラインの `CREATE TABLE` スキーマを検出する。
- 検証スクリプトが拡張子なしのアンカー（`Dockerfile:1`）を解決する。
- バージョンと検証日を `SKILL.md` の本文に表示（frontmatter は実行時に見えない）。
- バックグラウンドスキャンにツールの `run_in_background` を使用（シェルの `&` ジョブは強制終了されていた）。

## [1.1.0] - 2026-09-03

### 追加
- 決定的なスクリプト層：`detect_stack.py`（リポジトリのフィンガープリント -> 基準モジュール、スキャナ、
  レーン、欠落）、`sensitive_sweep.py`（該当箇所のみの手がかり + 「該当なし」の結果記録）、
  `run_scanners.py`（ネイティブへのフォールバック付きのピン留めした Docker スキャナ、読み取り専用マウント、マウントチェック、
  ダイジェスト、ツールの並列実行）、`normalize_findings.py`（SARIF -> 重複排除済みの候補）、
  `validate_findings.py`（納品ゲート）。
- 要件レベルのチェックを含むモジュール別の基準リファレンス。

### 変更
- 基準のベースラインを再検証：OWASP Top 10 2025、ASVS 5.0.0、SLSA v1.2、CIS AWS v7.1.0（+ Azure
  v6.0.0、GCP v5.0.0）、Agentic Top 10 2026、OWASP K8s Top 10 2025、Mobile Top 10 2024、CWE Top 25 2025、
  NIST SP 800-63-4、プライバシーおよび業種別法令の更新。
- スキャナのピンを更新（Semgrep 1.180.0、Gitleaks 8.30.1 `git` / `dir`、Trivy 0.75.0、OSV-Scanner
  v2.7.0、Checkov 3.3.28、zizmor 1.30.1、hadolint 2.15.1、mobsfscan 1.0.1）。
- harness-bootstrap は任意（存在する場合に使用し、必須ではない）。

## [1.0.0] - 2026-09-01

### 追加
- 初版スキル：Phase 0-8、知識層（基準の表、保存データの機微情報、スキャナのマトリクス、
  トリアージ、スキャナが検出できないもの、カバレッジのチェックリスト）、指摘事項と報告書のテンプレート。
