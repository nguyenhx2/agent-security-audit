# 基準と業種

[English](../standards-and-sectors.md) · **日本語**

指摘事項は必ず、版を付けて基準を引用します。スキルはコードから読み取れる内容と利用者の申告から適用する基準を選び、レビューレーンがそれに照らしてコードを確認します。

![対象範囲の図。技術領域：Web と API（OWASP Top 10:2025、ASVS 5.0.0、API Security Top 10 2023、CWE Top 25 2025、IPA 安全なウェブサイトの作り方）、モバイル（MASVS 2.1.0、MASTG 2.0.0、Mobile Top 10 2024）、クラウドと IaC（CIS ベンチマーク、OWASP Kubernetes Top 10 2025）、CI/CD とサプライチェーン（OWASP CI/CD Top 10、SLSA v1.2、SSDF v1.1、Non-Human Identities Top 10 2025）、AI・LLM・エージェント・MCP（LLM Top 10 2026、Agentic Top 10 2026、MCP Top 10 beta、AISVS 1.01）と AI コーディングエージェントの設定、保存データと決済（PCI DSS v4.0.1）、プライバシー（GDPR、個人情報保護法、ベトナム PDPL、CCPA、HIPAA、EU CRA、EU AI Act）。業種：医療、金融と暗号資産、EC、公共、教育、IoT・OT・車両について、日本、米国、EU、ベトナムの規則。](../../assets/coverage-map.ja.svg)

## 基準モジュール

参照資料は <!--n:standards_modules-->14<!--/n--> 個の基準モジュールに分かれています。レーンが読むのは対象範囲のモジュールだけで、その中でも必要な節だけです。

| モジュール | 主な基準と版 | 適用する条件 |
|---|---|---|
| `owasp-web` | OWASP Top 10:2025、OWASP ASVS 5.0.0、CWE Top 25 2025、NIST SP 800-63-4、IPA 安全なウェブサイトの作り方（第 7 版） | アプリケーションのコードがある |
| `owasp-api` | OWASP API Security Top 10 2023。GraphQL、WebSocket、gRPC、Webhook | HTTP のルートや API がある |
| `pci-dss` | PCI DSS v4.0.1、取引の完全性（アトミック性、冪等性、監査証跡） | カード決済、決済 SDK、カード番号らしき列、または資金の移動がある |
| `privacy` | GDPR、個人情報保護法（2026 年の改正を含む）、マイナンバー法、ベトナム PDPL、EU CRA、EU AI Act、CCPA、HIPAA | 個人、アカウント、健康、生体のデータがある |
| `ai-llm-agentic` | OWASP Top 10 for LLM Applications 2026、OWASP Top 10 for Agentic Applications 2026、OWASP MCP Top 10（beta）、OWASP AISVS 1.01 | LLM の呼び出し、RAG、エージェント、MCP のサーバーやクライアント、AI コーディングエージェントの設定がある |
| `mobile` | OWASP MASVS 2.1.0、OWASP MASTG 2.0.0、OWASP Mobile Top 10 2024 | Android、iOS、Flutter、React Native |
| `cloud-iac` | CIS AWS v7.1.0、Azure v6.0.0、GCP v5.0.0 Foundations、CIS Kubernetes v2.1.0、CIS Docker v1.9.0、OWASP Kubernetes Top 10 2025 | Terraform、CloudFormation、CDK、Kubernetes、Helm、Dockerfile |
| `supply-chain` | OWASP Top 10 CI/CD Security Risks、SLSA v1.2、NIST SSDF SP 800-218 v1.1、OWASP Non-Human Identities Top 10 2025 | CI のパイプライン、ロックファイル、ビルドとリリースの自動化 |
| `medical` | 医療情報システムの安全管理に関するガイドライン 7.0、総務省・経済産業省の提供事業者向けガイドライン 2.0、HIPAA の参照先 | 業種：医療 |
| `finance` | FISC 安全対策基準（第 14 版）、金融分野におけるサイバーセキュリティに関するガイドライン、暗号資産の保管の確認、GLBA Safeguards Rule、NYDFS 23 NYCRR 500、ベトナムの通達 09/2020 と 50/2024 | 業種：金融または暗号資産 |
| `ecommerce` | クレジットカード・セキュリティガイドライン 6.1、ベトナム電子商取引法 122/2025 と政令 248/2026 | 業種：EC |
| `public-sector` | 政府統一基準群、ISMAP、サイバー対処能力強化法、ベトナム政令 85/2016 とサイバーセキュリティ法 116/2025 | 業種：公共 |
| `education` | 教育情報セキュリティポリシーに関するガイドライン、FERPA、COPPA | 業種：教育 |
| `iot-ot` | JC-STAR、ETSI EN 303 645、EU CRA、IEC 62443、UN R155 / R156 | 業種：IoT、OT、車両 |

基準の一覧は、`SKILL.md` の日付（`standards-verified`）に各発行元で検証しています。その日付から 90 日を過ぎて監査を実行すると、スキルは引用の前に対象の行を検証し直し、報告書に新しい日付を記載します。確認できないものは `(UNVERIFIED)` を付けて引用します。公開日や置き換えられた旧版を含む完全な表は [`standards/index.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/reference/standards/index.md) にあります。

## 引用の規則

指摘事項は `基準名 + 版 + 要件 ID` の形で引用し、ID だけの引用はしません。ID は版ごとに意味が変わります。OWASP Top 10 の `A03` は 2021 年版ではインジェクションでしたが、2025 年版ではソフトウェアサプライチェーンの不備です。版のない「A03」は、今は曖昧で、将来は誤りになります。

書式の例：

```text
OWASP Top 10:2025 A01
OWASP ASVS 5.0.0 V8.2.1
OWASP API Security Top 10 2023 API1
PCI DSS v4.0.1 Req 3.3.1
OWASP Top 10 for LLM Applications 2026 LLM01
OWASP Top 10 for Agentic Applications 2026 ASI02
CIS AWS Foundations v7.1.0 2.1.1
CWE-89
```

指摘事項ファイルでは、これを 3 つのフロントマターの項目、`standard`（正式名称）、`standard_version`、`requirement_id` に分けて書きます。検証スクリプトは <!--n:standards-->59<!--/n--> 個の正式名称を受け付け、それ以外には警告を出します。たとえば `OWASP Top 10`、`OWASP ASVS`、`PCI DSS`、`Japan APPI`、`IPA How to Secure Your Web Site`、`FISC Security Guidelines` などです。CWE は `cwe` の項目に書き、主たる基準にはしません。`also_maps_to` の各項目にも版を付けます。フィード（KEV、JVN）を指摘事項の基準として引用することはなく、アドバイザリの URL は根拠の節に書きます。

## 業種

`detect_stack.py` は依存関係と識別子（`karte`、`monshin`、`kanja`、`zengin`、`furikomi` のようなローマ字を含む）から <!--n:sectors-->9<!--/n--> つの業種シグナルを読み取り、業種モジュール（6 つ）に対応付けます。

| 業種モジュール | シグナル | 日本 | 米国、EU、国際 | ベトナム |
|---|---|---|---|---|
| 医療 | medical | 医療情報システムの安全管理に関するガイドライン 7.0、総務省・経済産業省の提供事業者向けガイドライン 2.0 | HIPAA、GDPR 第 9 条 | PDPL |
| 金融と暗号資産 | finance、crypto | FISC 安全対策基準（第 14 版）、金融分野におけるサイバーセキュリティに関するガイドライン、暗号資産の保管の確認 | GLBA Safeguards Rule、NYDFS 23 NYCRR 500 | 通達 09/2020、50/2024 |
| EC | ecommerce | クレジットカード・セキュリティガイドライン 6.1 | PCI DSS v4.0.1 | 電子商取引法 122/2025、政令 248/2026 |
| 公共 | government | 政府統一基準群、ISMAP、サイバー対処能力強化法 | - | 政令 85/2016、サイバーセキュリティ法 116/2025 |
| 教育 | education | 教育情報セキュリティポリシーに関するガイドライン | FERPA、COPPA | - |
| IoT・OT・車両 | iot、ot、automotive | JC-STAR | ETSI EN 303 645、EU CRA、IEC 62443、UN R155 / R156 | - |

業種が対象範囲に入る経路：

- **コードから検出する。** 依存関係（FHIR と HL7、全銀、ウォレットやブロックチェーンのライブラリ、EC プラットフォーム、LTI、MQTT や IoT の SDK、Modbus、OPC UA、CAN）や識別子のキーワードから検出します。既知の誤検知は閾値で避けています。`Sku` だらけの Azure SDK は EC ではなく、カード決済だけではリポジトリを `finance` とはしません。
- **利用者が申告する。** 「うちは銀行です」「市役所向けのシステムです」と伝えれば、コードに現れていなくてもその業種を加えます。重点の質問では「Other」で追加できます。
- 検出した業種は重点の質問に表示され、法令の質問も行われます。

オフライン評価で、本物に近いフィクスチャから各業種を検出できること、業種でないものからは検出しないことを確かめています（[eval/README.ja.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/eval/README.ja.md)）。

## 日本の基準

日本の顧客向け、または報告書の言語に日本語がある場合：

- OWASP と並べて「安全なウェブサイトの作り方」（`IPA How to Secure Your Web Site`）を引用します。
- プライバシー法では個人情報保護法（`Japan APPI`）を最初に、条文の対応表（安全管理措置、漏えい等の報告とその期限、外国への提供）とともに扱います。
- 業種の規則として、厚生労働省の医療情報の安全管理ガイドライン、FISC 安全対策基準、金融分野におけるサイバーセキュリティに関するガイドライン、クレジットカード・セキュリティガイドライン、政府統一基準群、ISMAP、サイバー対処能力強化法、文部科学省の教育情報セキュリティポリシーに関するガイドライン、JC-STAR を扱います。
- 日本語の報告書では、基準の表で日本の基準を日本語の名称で表示します。
- 大企業に納入する事業者の場合、経済産業省の SCS 評価制度（★3 / ★4）を背景情報として記載します。独立したモジュールではありません。

## 網羅性の確認

対象範囲にどの基準もない欠陥の種類は、誰も確認しない種類になります。スキルは偵察の前に、システムが何であるか（決済を受けるか、個人データを保存するか、パイプラインでデプロイするか、LLM を呼ぶか、資金を動かすか、モバイルのクライアントや管理画面があるか）を書き出し、対象範囲のモジュールと突き合わせます。さらに、基準と基準の間に落ちる種類を [`coverage-checklist.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/reference/method/coverage-checklist.md) で確認します。Deep ではチェックリストのすべての行を、Standard では対象範囲のモジュールの行を評価し、Quick では確認しなかった種類を未確認範囲として列挙します。

## 関連ページ

- [指摘事項と報告書](reports.md)：指摘事項での引用の見え方
- [初めての監査](first-audit.md)：重点と法令の質問
- [`standards/index.md`](https://github.com/nguyenhx2/agent-security-audit/blob/main/editions/ja/security-audit/reference/standards/index.md)：版、公開日、再検証
