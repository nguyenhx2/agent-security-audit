# 基準ベースライン - バージョン、適用範囲、引用方法

手順に戻る：`SKILL.md` Phase 0。モジュールごとの要件詳細は `standards/*.md` にある
（いずれも SKILL.md のモジュール表からリンク）。

## 目次
- 引用ルール
- ベースライン表（verified 2026-10-26）
- 適用するモジュール（システムが「何であるか」から導出）
- カバレッジの反射確認 - 表に無いものを問う
- 再検証の手順
- 旧パターン（廃止済みバージョン）

## 引用ルール

指摘事項は `standard + version + requirement ID` を引用し、ID 単体では決して引用しない。ID はバージョンに依存する：
OWASP Top 10 の `A03` は 2021 では *Injection* を、2025 では *Software Supply Chain Failures* を意味する。
「A03」単体は現時点で曖昧であり、将来は誤りとなる。

指摘事項の frontmatter ではこれを `standard`（下記の正規名）、`standard_version`、
`requirement_id` に分割する。正規名でない名称にはバリデータが警告を出す。正規名（この文字列をそのまま使用すること）：OWASP Top 10, OWASP
ASVS, OWASP API Security Top 10, OWASP Top 10 for LLM Applications, OWASP Top 10 for Agentic
Applications, OWASP MCP Top 10, OWASP AISVS, OWASP MASVS, OWASP MASTG, OWASP Mobile Top 10, OWASP
Kubernetes Top 10, OWASP Non-Human Identities Top 10, OWASP Top 10 CI/CD Security Risks, PCI DSS, CIS AWS Foundations, CIS Azure
Foundations, CIS GCP Foundations, CIS Kubernetes, CIS Docker, SLSA, NIST SSDF SP 800-218, NIST SP
800-63-4, CWE, GDPR, UK GDPR, Japan APPI, Japan My Number Act, IPA How to Secure Your Web Site, MHLW Medical Information Security Guidelines, MIC/METI Medical Service Provider Guidelines, FISC Security Guidelines, Vietnam PDPL, Vietnam Cybersecurity Law, CCPA, HIPAA, EU CRA,
EU AI Act, NIS2, DORA。未検証の版：`standard_version: 2022 (UNVERIFIED)`。CWE は決して主たる
`standard` にしない - `cwe:` に記載する。`also_maps_to` の各エントリにはバージョンを付ける。

書式：`OWASP ASVS 5.0.0 V8.2.1`、`OWASP Top 10:2025 A01`、`PCI DSS v4.0.1 Req 3.3.1`、
`OWASP API Security Top 10 2023 API1`、`OWASP Top 10 for Agentic Applications 2026 ASI02`、`OWASP Top 10 for LLM Applications 2026 LLM01`、
`CIS AWS Foundations v7.1.0 2.1.1`、`CWE-89`。該当する CWE があれば必ず追加する - 最も安定した
相互参照であり、スキャナが出力する値でもある。

## ベースライン表

`verified: 2026-10-26`（発行団体の情報に対して Web で検証済み。同日にすべての行を再確認した）。これが本スキルの出荷時ベースラインである。
**Phase 0 ルール：** 本日がこの日付から 90 日を超えている場合、引用前に対象範囲の行を再検証し
（手順は下記）、報告書に新しい日付を記載する。90 日以内であればそのまま引用し、
この日付を報告書に転記する。確認できないものは `(UNVERIFIED)` を付けて引用する。

| 基準 | バージョン | 公開 | モジュールファイル |
|----------|---------|----------|-------------|
| OWASP Top 10 (web) | **2025**（A01-A10 を再編。A03 Supply Chain、A10 Exceptional Conditions が新設） | 確定版：RC 2025-11-06、RC 表記は 2025-12-24 に削除（OWASP/Top10 リポジトリ） | `reference/standards/owasp-web.md` |
| OWASP ASVS | **5.0.0**（V1-V17） | 2025-05-30 | `reference/standards/owasp-web.md` |
| CWE Top 25 | **2025** | 2025-12 | `reference/standards/owasp-web.md` |
| OWASP API Security Top 10 | **2023**（新しい版なし） | 2023 | `reference/standards/owasp-api.md` |
| PCI DSS | **v4.0.1**（将来日付の要件は 2025-03-31 に発効。PCI SSC の 2026-06/07 の意見募集は次の改訂を示唆している - 引用前に再確認する） | 2024-06 | `reference/standards/pci-dss.md` |
| OWASP Top 10 for LLM Applications | **2026**（2025 から ID を再採番） | 2026-08-03（発表 2026-09-01） | `reference/standards/ai-llm-agentic.md` |
| OWASP Top 10 for Agentic Applications | **2026**（ASI01-ASI10） | 2025-12-09 | `reference/standards/ai-llm-agentic.md` |
| OWASP MCP Top 10 | **beta**（随時更新される文書。`(beta)` を付けて引用。公式の ID 表記は `MCPxx:2025`） | 2025-2026 | `reference/standards/ai-llm-agentic.md` |
| OWASP AISVS | **1.01**（213 の要件、12 章。Appendix C = AI 支援によるセキュアコーディング、AC.8.x 職務分離） | 2026-10-16（GitHub のリリース、1.0 と同時） | `reference/standards/ai-llm-agentic.md` |
| OWASP MASVS / MASTG / MASWE | **2.1.0** / **2.0.0** / **1.0.0** | 2024-01-18 / 2026-06-30 / 2026-08-17 | `reference/standards/mobile.md` |
| OWASP Mobile Top 10 | **2024** | 2024 | `reference/standards/mobile.md` |
| CIS AWS / Azure / GCP Foundations | **v7.1.0** / **v6.0.0** / **v5.0.0** | 2026 | `reference/standards/cloud-iac.md` |
| CIS Kubernetes | **v2.1.0**（CIS-CAT の掲載は 2.0.1）。EKS/AKS/GKE は **v2.0.0** | - | `reference/standards/cloud-iac.md` |
| CIS Docker | **v1.9.0** | - | `reference/standards/cloud-iac.md` |
| OWASP Kubernetes Top 10 | **2025** | 2025 | `reference/standards/cloud-iac.md` |
| OWASP Top 10 CI/CD Security Risks | 単一版（CICD-SEC-1..10） | 2022-11 | `reference/standards/supply-chain.md` |
| SLSA | **v1.2**（Source Track を追加） | 2025-11 | `reference/standards/supply-chain.md` |
| OWASP Non-Human Identities Top 10 | **2025**（NHI1-NHI10） | 2025 | `reference/standards/supply-chain.md` |
| NIST SSDF SP 800-218 | **v1.1** 確定版（Rev 1 / v1.2 = 初期公開ドラフト 2025-12-17、確定版ではない） | 2022-02 | `reference/standards/supply-chain.md` |
| NIST SP 800-63-4 | **final**（デジタルアイデンティティ / 認証器） | 2025-07-31 | `reference/standards/owasp-web.md` |
| NIST SP 800-53 Rev 5 | **5.2.0** | 2025-08-27 | 顧客が要求する場合のみ引用 |
| ISO/IEC 27001 | **2022 + Amd 1:2024** | 2024-02 | 顧客が要求する場合のみ引用 |
| IPA How to Secure Your Web Site（安全なウェブサイトの作り方） | **改訂第7版**（第4刷） | 2021-03-31 | `reference/standards/owasp-web.md` Part E |
| MHLW Medical Information Security Guidelines（医療情報システムの安全管理に関するガイドライン） | **第7.0版**（5 編構成、保守委託機関編を新設） | 2026-06-29（通知 産情発0629第1号） | `reference/standards/medical.md` |
| MIC/METI Medical Service Provider Guidelines（医療情報を取り扱う情報システム・サービスの提供事業者における安全管理ガイドライン） | **第2.0版** | 2025-03-28 | `reference/standards/medical.md` |
| FISC Security Guidelines（金融機関等コンピュータシステムの安全対策基準・解説書） | **第14版**（令和8年3月版。区分は 統制基準 / 実務基準 / 設備基準 / 監査基準） | 2026-03（日は二次情報による。2026-10-26 に fisc.or.jp へ到達できず - 項番は UNVERIFIED、区分を引用する） | `reference/standards/finance.md` |
| Japan APPI | 現行条文（2022 年以降の条番号）。改正法 Act No. 56 of 2026 は 2026-07-17 公布、罰則は 6 か月後、その他は政令で定める日（2028-07 まで） | 2026-07-17 | `reference/standards/privacy.md` |
| Japan Credit Card Security Guidelines（クレジットカード・セキュリティガイドライン） | **6.1版**（6.0版 = 2025-03-04 の実質的な改訂） | 2026-03-11 | `reference/standards/ecommerce.md` |
| FSA Cybersecurity Guidelines（金融分野におけるサイバーセキュリティに関するガイドライン） | **2024**（技術的な改正 2025-07-04） | 2024-10-04 | `reference/standards/finance.md` |
| Japan Government Unified Standards（政府機関等のサイバーセキュリティ対策のための統一基準群） | **令和7年度版**（ガイドラインの改定 2025-09-05、2026-06-12） | 2025-07-01 | `reference/standards/public-sector.md` |
| ISMAP / ISMAP-LIU | 運用中（管理基準の改定案が 2025-12 に策定、確定は UNVERIFIED） | - | `reference/standards/public-sector.md` |
| Japan Active Cyber Defense Act（サイバー対処能力強化法） | 2025-05 成立。資産の届出とインシデント報告は 2026-10-01 から（二次情報） | 2025-05-16 | `reference/standards/public-sector.md` |
| MEXT Education Information Security Guidelines（教育情報セキュリティポリシーに関するガイドライン） | **2025-03** 改訂 | 2025-03-25 | `reference/standards/education.md` |
| JC-STAR（IoT ラベリング、IPA） | ★1 は 2025-03-25 から。★3 の要件は 2026-06-12 | 2025-03-25 | `reference/standards/iot-ot.md` |
| Japan Telecommunications Business Act、外部送信規律 | 施行中 | 2023-06-16 | `reference/standards/privacy.md` |
| 番号法のガイドライン（特定個人情報の適正な取扱いに関するガイドライン（事業者編）） | 令和7年6月 改正 | 2025-06 | `reference/standards/privacy.md` |
| ETSI EN 303 645 | **V3.1.3** | 2024-09 | `reference/standards/iot-ot.md` |
| IEC 62443-3-3 / 4-1 / 4-2 | **Ed.1**（2013 / 2018 / 2019。4-1 と 4-2 の Ed.2 は 2026 年後半から 2027 年の見込み） | - | `reference/standards/iot-ot.md` |
| UN R155 / UN R156 | R155 は原シリーズ + 補足。R156 は 01 シリーズ | 2024-07 から新車に義務化（EU、日本） | `reference/standards/iot-ot.md` |
| FERPA / COPPA | 34 CFR 99（2011） / 16 CFR 312 は 2025 年改正、遵守義務は 2026-04-22 から | - | `reference/standards/education.md` |
| GLBA Safeguards Rule / NYDFS 23 NYCRR 500 | 2023 年改正（FTC への通知は 2024-05-13 から） / 最終段階 2025-11-01 | - | `reference/standards/finance.md` |
| Vietnam Circular 09/2020/TT-NHNN + 50/2024/TT-NHNN | 施行中（50/2024 は 2025-01-01 から） | - | `reference/standards/finance.md` |
| Vietnam E-commerce Law 122/2025/QH15 + Decree 248/2026/ND-CP | 施行中 | 2026-07-01 | `reference/standards/ecommerce.md` |
| Vietnam Decree 85/2016/ND-CP | 施行中として掲載。根拠法は 2026-07-01 に置き換えられ、後継は見つからない（注記を付けて引用） | 2016 | `reference/standards/public-sector.md` |
| METI Cybersecurity Management Guidelines（サイバーセキュリティ経営ガイドライン） | **3.0**（SCS 評価制度の ★3/★4 は 2026 年度末頃の開始を目標、未開始） | 2023-03-24 | 参考情報のみ（組織面） |
| プライバシー / 業界別法令 | 適用法域ごとに異なる | モジュール参照 | `reference/standards/privacy.md` |

## 適用するモジュール

`scripts/detect_stack.py` がリポジトリのフィンガープリントから `standards_modules` を出力する。スコーピングの
質問でユーザーに確認すること。フィンガープリントが選択したモジュールを黙って外してはならない。

| システムが持つもの | 必須モジュール |
|---------------|---------------------|
| 何らかのアプリケーションコード | `owasp-web`（Top 10:2025 + ASVS 5.0.0 + CWE） |
| HTTP ルート / API 面 | + `owasp-api` |
| カード決済、決済 SDK、またはカード情報らしきカラム | + `pci-dss` + `reference/method/sensitive-data-at-rest.md` |
| 個人、アカウント、健康、生体データ | + `privacy`（適用法域を選択） |
| LLM 呼び出し、RAG、エージェント、MCP サーバー/クライアント | + `ai-llm-agentic` |
| Android / iOS / Flutter / React Native | + `mobile` |
| Terraform / CFN / CDK / K8s / Helm / Dockerfile | + `cloud-iac` |
| CI パイプライン、ロックファイル、ビルド/リリース自動化 | + `supply-chain` |
| 資金移動（返金、元帳、ウォレット、支払い） | `pci-dss` モジュール内のトランザクション整合性の性質（原子性、冪等性、監査証跡） |
| 業種（detect の `sectors`、またはユーザーの申告） | + 業種別モジュール：`medical`（医療 / 患者）、`finance`（銀行、決済事業者、証券、暗号資産）、`ecommerce`（EC サイト、マーケットプレイス）、`public-sector`（政府機関、地方公共団体、重要インフラ）、`education`（学校、学習プラットフォーム、子ども）、`iot-ot`（機器、産業制御、車両） |
| 日本の顧客、または報告書の言語が ja | OWASP と並べて `IPA How to Secure Your Web Site` を引用する（`owasp-web` Part E）。`privacy` では `Japan APPI` を最初に挙げる |
| 日本の大企業への供給者（コードではなくユーザーの状況） | 経済産業省の SCS 評価制度（★3 / ★4、2026 年度末頃）に言及し、その項目をベースラインの確認項目に対応付ける。独立したモジュールではない |

## カバレッジの反射確認 - 表に無いものを問う

対象範囲にどの基準も無い欠陥クラスは、誰も見ないクラスとなる。行が欠けていた初回パスで実際に
見逃された例：保存されたカードデータの未暗号化（PCI の行なし）、互いに異なる 2 本のデプロイパイプラインと
長期有効な CI 認証情報（CICD-SEC/SLSA の行なし）、「アカウント削除」後も個人情報が残存（プライバシーの
行なし）、冪等性キーの無い非原子的な返金（トランザクション整合性の行なし）。

Phase 1 の前に：システムが「何であるか」を列挙し（決済を受けるか？ 個人情報を保存するか？ パイプラインでデプロイするか？
LLM を呼ぶか？ 資金を動かすか？ モバイルクライアントがあるか？ 管理コンソールがあるか？）、対象モジュールとの差分を取る。
次に、基準の狭間に落ちるクラスについて `reference/method/coverage-checklist.md` と照合する。

## 再検証の手順

1. 対象範囲の各基準について：WebSearch `"<standard>" latest version` を実行し、発行元のサイトで確認する
   （owasp.org、genai.owasp.org、pcisecuritystandards.org、cisecurity.org、csrc.nist.gov、slsa.dev、
   cwe.mitre.org、公式の法令官報）。
2. バージョン + 公開日 + 出典 URL を報告書の Method セクションに記録する。
3. 確認できない場合 -> `(UNVERIFIED)`。その版の特定の ID を権威あるものとして引用しない。
4. バージョンが変わった場合：この表とモジュールファイルの両方を更新し、スキルの `z` バージョンを上げ（モジュールの追加・削除時は `y` - `CHANGELOG.md` の Versioning rules を参照）、
   CHANGELOG エントリを追加する（`CHANGELOG.md` を参照）。

## 旧パターン

<details>
<summary>廃止済みバージョン - 古い報告書で見分けるためのもの。新しい指摘事項には決して引用しない</summary>

- OWASP Top 10 **2021**：A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection,
  A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable and Outdated Components,
  A07 Identification and Authentication Failures, A08 Software and Data Integrity Failures,
  A09 Security Logging and Monitoring Failures, A10 SSRF。2025 への対応：2021-A03 -> 2025-A05、
  2021-A02 -> 2025-A04、2021-A05 -> 2025-A02、2021-A06 -> 2025-A03（範囲拡大）、2021-A10 SSRF -> 2025-A01。
- OWASP ASVS **4.0.3**：章番号が 5.0.0 と異なる（例：4.0.3 V4 = Access Control、5.0.0 V8 =
  Authorization）。再マッピングし、ID を決して流用しない。
- PCI DSS **v3.2.1**：2024-03-31 に廃止。v4.0 は 2024-12-31 に廃止され v4.0.1 に置き換え。
- CIS AWS Foundations v1.x-v6.x、SLSA v0.1 / v1.0 / v1.1。
- OWASP Top 10 for LLM Applications **2025**（LLM01 Prompt Injection, LLM02 Sensitive Information
  Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06
  Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09
  Misinformation, LLM10 Unbounded Consumption）- 2026 版に置き換え。ID は移動済み。
- OWASP AISVS 1.0（1.01 に置き換え）。
- Vietnam Decree 13/2023/ND-CP：PDPL 91/2025/QH15 のもと Decree 356/2025/ND-CP に置き換え（2026-01-01）。
</details>
