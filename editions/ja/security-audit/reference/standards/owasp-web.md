# モジュール: owasp-web - OWASP Top 10:2025 + ASVS 5.0.0 + CWE Top 25 2025

あらゆるアプリケーションコードに適用するベースライン。バージョンは `reference/standards/index.md` に従う（2026-10-26 確認）。
リスクは `OWASP Top 10:2025 A0x`、検証可能な要件は `OWASP ASVS 5.0.0 V<ch>.<sec>.<req>` の形式で引用し、
CWE も併記する。検出手段（Seen）: **S** = SAST で検出可能、**M** = 手動のみ、
**S+M** = スキャナで個々の事例は検出できるが、設計上の欠陥はコードを読む必要がある。

## 目次
- Part A - Top 10:2025 のチェック（A01-A10）
- Part B - ASVS 5.0.0 章ルーター（V1-V17）
- Part C - CWE Top 25 2025 早見表
- Part D - 認証の詳細（NIST SP 800-63-4）
- Part E - IPA「安全なウェブサイトの作り方」（日本）早見表

## Part A - OWASP Top 10:2025

### A01 Broken Access Control（アクセス制御の不備、SSRF を含むようになった） - ASVS V8, V4; CWE-862/863/639/918/352
| チェック | 確認箇所 / grep のヒント | 検出 |
|-------|-------------------|------|
| すべての特権ルートにサーバー側の認可チェックがある（UI で隠すだけではない） | ルートテーブル、ミドルウェアチェーン、`@PreAuthorize`、`before_action`、`permission_classes`、`[Authorize]`、ガード | M |
| オブジェクト所有権を強制している（IDOR/BOLA）: クエリが現在のユーザー/テナントで絞り込まれている | 所有者フィルタのない `findById(req.params.id)`、`Model.find(params[:id])`、`get_object_or_404(pk=` | M |
| マルチテナントのクエリでテナント分離ができている | `tenant_id`、`org_id`、行レベルセキュリティ、グローバルクエリフィルタ | M |
| デフォルト拒否であり、新しいルートが指定漏れで公開されない | ルーター登録と認証ミドルウェアの順序 | M |
| SSRF: ユーザー指定 URL へのサーバー側フェッチが許可リスト方式であり、メタデータ IP（169.254.169.254、fd00:ec2::254）をブロックし、リダイレクトを無条件に追従しない | `requests.get(url`、`fetch(`、`http.Get(`、`RestTemplate`、`HttpClient`、Webhook、画像/URL プレビュー、PDF レンダラー | S+M |
| Cookie 認証で状態を変更するルートの CSRF 対策 | `csrf`、`SameSite`、`csurf`、`protect_from_forgery`、`@csrf_exempt` | S+M |
| CORS が資格情報付きで任意のオリジンを反射しない | `Access-Control-Allow-Origin`、`cors({ origin: true, credentials: true })` | S+M |
| ファイル読み込み/配信でのパストラバーサル | `path.join(base, req.`、`send_file(`、`../` | S |

### A02 Security Misconfiguration（セキュリティ設定ミス） - ASVS V13, V3; CWE-16/611/1004
| チェック | 確認箇所 / grep のヒント | 検出 |
|-------|-------------------|------|
| 本番でデバッグ無効、クライアントにスタックトレースを返さない | `DEBUG = True`、`app.debug`、`NODE_ENV`、`display_errors`、`developer_exception_page` | S |
| セキュリティヘッダー: CSP、HSTS、X-Content-Type-Options、frame-ancestors | helmet、`SecurityMiddleware`、`secure_headers`、リバースプロキシ設定 | S+M |
| Cookie: `Secure`、`HttpOnly`、`SameSite` | セッション設定 | S |
| XXE: 外部エンティティが無効化されている | XML パーサーファクトリ、`resolve_entities`、`DocumentBuilderFactory` | S |
| デフォルト資格情報 / サンプルアカウント / 管理コンソールの露出 | シード、フィクスチャ、`admin/admin`、actuator、`/h2-console`、`/debug` | S+M |
| 管理 / デバッグのプレーンに到達できない：Tomcat manager と WAR のデプロイ、JMX、Jolokia、`health` 以外の actuator、Ignition、Telescope、Werkzeug / Rails のコンソール | `tomcat-users.xml`、`management.endpoints`、`APP_DEBUG`、`debug=True`、`platform.md` のシグナル | S+M |
| Web ルートから機微なもの（`.env`、バックアップ、ダンプ、`.git/`、`phpinfo()`）を配信しない。ディレクトリ一覧表示なし。ドットファイルを拒否する | ドキュメントルートの設定、`public/`、`platform.md` のシグナル `webroot-sensitive-file`、`phpinfo-exposed`、`directory-listing` | S+M |
| 認証、CSRF、TLS 検証、テナントのスコープが、環境変数のフラグや未設定の変数で決して無効にならない | `process.env.X` の既定値、制御を囲む `if env != 'production'` | M |
| クラウド/IaC の既定値（`reference/standards/cloud-iac.md` を参照） | Terraform/CFN/K8s | S |

### A03 Software Supply Chain Failures（ソフトウェアサプライチェーンの不備） - ASVS V15.2, V13; CWE-1104/829/494
2021 年の「脆弱なコンポーネント」からチェーン全体に拡大された。詳細は `reference/standards/supply-chain.md`。
| チェック | 確認箇所 | 検出 |
|-------|-------|------|
| 既知の脆弱な依存関係（到達可能なものを優先） | ロックファイル、Trivy/OSV の出力 | S |
| ロックファイルが存在しコミットされている、バージョンが固定されている | `package-lock.json`、`poetry.lock`、`go.sum` | S |
| 依存関係の混乱（dependency confusion）/ タイポスクワッティング・スロップスクワッティング（AI が提案した名前） | 新規/見慣れない依存関係、公開レジストリで解決できてしまうプライベートスコープ名 | M |
| CI のアクションがコミット SHA に固定されている、`pull_request_target` + PR head のチェックアウトがない | `.github/workflows`（zizmor） | S |
| 完全性検証のないリモートスクリプト / CDN アセット（`curl | sh`、SRI のない `<script src>`） | Dockerfile、HTML、インストールスクリプト | S+M |
| ランタイム、サーバー、データストア、ベースイメージがサポート中で最新のパッチ適用状況にある（ロックファイルの SCA には見えない） | `platform.md` の指定、`intel.md`（KEV、NVD、IPA / JPCERT/CC、EOL）、`reference/method/threat-intel.md` | S+M |

### A04 Cryptographic Failures（暗号化の失敗） - ASVS V11, V12, V14; CWE-327/328/330/916/319
| チェック | 確認箇所 / grep のヒント | 検出 |
|-------|-------------------|------|
| パスワード: 適切なコストの Argon2id / scrypt / bcrypt / PBKDF2。MD5/SHA-x 単体は決して使わず、可逆にも決してしない | パスワードに対する `md5(`、`sha1(`、`createHash('sha256')`、`encrypt(password` | S+M |
| ECB を使わない、静的な IV/nonce を使わない、AEAD を優先（AES-GCM、ChaCha20-Poly1305） | `AES/ECB`、`Cipher.getInstance("AES")`、`iv = b'\x00'` | S |
| トークン/ID には CSPRNG を使う | シークレットに対する `Math.random`、`random.random`、`rand()` | S |
| 鍵がハードコードされていない、ローテーション可能、データ鍵に KMS/HSM を使用 | `SECRET_KEY =`、`private_key`、コミットされた `.pem` | S |
| 外部および内部の機微な通信すべてで TLS を強制、証明書検証を無効化していない | `verify=False`、`rejectUnauthorized: false`、`InsecureSkipVerify: true` | S |
| 保存データの機微情報が暗号化 / トークン化されている | `reference/method/sensitive-data-at-rest.md` | M |

### A05 Injection（インジェクション） - ASVS V1, V2; CWE-89/78/79/94/77/917/1336
| チェック | 確認箇所 / grep のヒント | 検出 |
|-------|-------------------|------|
| SQL/NoSQL はパラメータ化されている、文字列連結でクエリを組み立てない | `+ req.`、`execute(` 内の f-string / `%`、`$where`、`raw(`、`Sequelize.literal`、`$queryRawUnsafe` | S |
| NoSQL のフィルタに型がある：リクエストのオブジェクトが `find` / `findOne` に演算子（`$ne`、`$gt`、`$regex`）を注入できない。入力から作る正規表現はエスケープする | `find(req.body`、`{email: req.body.email}`、`sanitizeFilter`、`express-mongo-sanitize`、文字列への変換（CWE-943） | S+M |
| OS コマンド: ユーザー入力を含めてシェルを使わない | `exec(`、`child_process`、`os.system`、`subprocess(..., shell=True)`、`Runtime.exec` | S |
| XSS: 文脈に応じた出力エンコーディング、安全でないシンクがない | `innerHTML`、`dangerouslySetInnerHTML`、`v-html`、`|safe`、`html_safe`、`raw(`、`@Html.Raw` | S+M |
| テンプレートインジェクション / eval | `eval(`、`new Function(`、`render_template_string(`、`Velocity`、`vm.runIn` | S |
| LDAP / XPath / ヘッダー / ログインジェクション | 文字列連結を伴う `ldap.search(`、ヘッダー内の CRLF、ログ内の信頼できないデータ | S+M |
| LLM 機能のプロンプトインジェクション -> `reference/standards/ai-llm-agentic.md` | プロンプトの組み立て | M |

### A06 Insecure Design（安全でない設計） - ASVS V2（ビジネスロジック）, V15; CWE-840/841/799
| チェック | 確認箇所 | 検出 |
|-------|-------|------|
| ビジネスフローの悪用: サインアップ、OTP、クーポン、チェックアウトのレート/量の制限 | `reference/standards/owasp-api.md` API6 のフロー | M |
| ステートマシンを飛ばせない（支払い -> 発送、検証 -> 有効化） | ワークフロー/ステータス遷移 | M |
| 信頼境界が明示されている、Webhook が検証されている（署名 + タイムスタンプ + リプレイ対策） | 決済/プロバイダーのコールバック | M |
| 資金移動: アトミック、冪等、監査ログあり（`reference/standards/pci-dss.md` のトランザクション完全性） | 返金、台帳 | M |

### A07 Authentication Failures（認証の不備） - ASVS V6, V7, V9, V10; CWE-287/307/384/798/521
| チェック | 確認箇所 / grep のヒント | 検出 |
|-------|-------------------|------|
| ログイン、OTP、リセットでのブルートフォース / クレデンシャルスタッフィング対策（レート制限、ロックアウト、CAPTCHA） | ログインハンドラー | M |
| ログイン/権限変更時にセッションを再生成、ログアウト/パスワード変更時に無効化 | セッション再生成の呼び出し | M |
| JWT: アルゴリズム固定（`alg: none` / HS-RS 混同を拒否）、`exp` を検証、シークレットが強固、避けられる場合は localStorage に置かない | `jwt.verify(`、`algorithms=`、verify なしの `decode(` | S+M |
| NIST SP 800-63-4 に沿ったパスワードポリシー（Part D） | サインアップ/リセットのバリデーション | M |
| 管理者と機微な操作には MFA、リカバリーフローがログインより弱くない | 管理者認証、リセットトークン（使い捨て、短い TTL、ハッシュ化して保存） | M |
| OAuth 2.0 Security BCP（RFC 9700、2025-01）に沿った OAuth/OIDC: 全クライアントで PKCE、リダイレクト URI の完全一致、`state`/`nonce`、implicit / ROPC グラントなし、送信者制約付きまたは短命のトークン、audience の検証 | OAuth クライアント/サーバー設定 | M |
| JWT BCP（RFC 8725）に沿った JWT: 明示的なアルゴリズム許可リスト、`kid`/`jku`/`x5u` を無条件に信頼しない、`typ` を検証、用途ごとに鍵を分離 | JWT ライブラリと verify 呼び出し | S+M |
| パスキー / WebAuthn: RP ID とオリジンを検証、チャレンジは使い捨てかつサーバー生成、AAL2 以上ではユーザー検証を必須、`signCount` / バックアップフラグを処理 | WebAuthn サーバーライブラリの設定 | M |
| メッセージやタイミングによるユーザー列挙 | ログイン/リセット/サインアップのレスポンス | M |

### A08 Software or Data Integrity Failures（ソフトウェアまたはデータの完全性の不備） - ASVS V15, V5; CWE-502/345/494
| チェック | 確認箇所 / grep のヒント | 検出 |
|-------|-------------------|------|
| 信頼できないデータの安全でないデシリアライズがない | `pickle.loads`、`yaml.load(`（safe_load ではないもの）、`ObjectInputStream`、`unserialize(`、`BinaryFormatter`、`Marshal.load` | S |
| 更新、成果物、Webhook、Cookie が署名/検証されている | 署名検証の呼び出し。検証関数の本体を読む（無効化された制御のチェック） | M |
| マスアサインメントがブロックされている | `Model.create(req.body)`、`update(params)`、`permit!`、エンティティへの `@ModelAttribute` | S+M |
| プロトタイプ汚染 | 信頼できないオブジェクトのディープマージ、`__proto__` | S+M |

### A09 Security Logging and Alerting Failures（セキュリティログとアラートの不備） - ASVS V16; CWE-778/117/532
| チェック | 確認箇所 | 検出 |
|-------|-------|------|
| 認証イベント、認可失敗、管理者操作、決済イベントが「誰が/何を/いつ」付きでログ記録されている | それらのハンドラー付近のロガー呼び出し | M |
| ログにシークレット / トークン / PAN / パスワード / 完全な個人情報がない | `logger.*(req.body)`、`console.log(user)` - `scripts/sensitive_sweep.py` が `log` を検出する | S+M |
| ログが改ざん耐性を持つ / 集約されている、悪用の兆候に対するアラートがある | インフラ設定 | M |
| フォレンジックへの備え：管理、エクスポート、ロール変更、トークン発行のイベントについて誰がどのレコードを読んだか（実行者、送信元 IP、オブジェクト ID）を記録する。アクセスログをホスト外に送り 12 か月以上保持する。5xx / ワーカーのクラッシュのアラートがある | それらのハンドラでのロガー呼び出し、ログの転送、`retention_in_days` | M |

### A10 Mishandling of Exceptional Conditions（例外的な状況の不適切な処理、2025 年新設） - ASVS V16, V2; CWE-754/755/390/248/636
| チェック | 確認箇所 / grep のヒント | 検出 |
|-------|-------------------|------|
| フェイルクローズ: 認可/検証/決済の経路での例外は拒否となり、決して許可しない | `try { verify } catch { return true / next() }`、チェックを囲む `except: pass` | M |
| エラーが内部情報（スタック、SQL、パス）を漏らさない | グローバルエラーハンドラー | S+M |
| エラー時のリソース後始末（トランザクションのロールバック、ロック解放、部分書き込みの取り消し） | DB トランザクション、ファイルハンドル | M |
| 未処理の Promise rejection / panic がクラッシュやロジックのバイパスを起こす | catch のない `.then(`、goroutine の panic、入力に対する `unwrap()` | S+M |
| 外向き呼び出しのタイムアウトとリトライに上限がある | タイムアウトのない HTTP クライアント | S+M |

## Part B - ASVS 5.0.0 章ルーター

Top 10 のリスクの背後にある*検証可能な要件*を引用するために ASVS を使う。指摘事項を書く際は ASVS 5.0.0
文書で正確な要件番号を確認する（https://github.com/OWASP/ASVS）。サブ番号を確認できない場合は、
推測せず章/節（`OWASP ASVS 5.0.0 V8.2`）を引用する。

| 章 | トピック | 引用すべき典型的な欠陥 |
|---------|-------|-------------------------------|
| V1 | Encoding and Sanitization（エンコーディングとサニタイズ） | インジェクション、XSS、安全でないデシリアライズのシンク |
| V2 | Validation and Business Logic（バリデーションとビジネスロジック） | バリデーション欠如、ビジネスフローの悪用、自動化対策 |
| V3 | Web Frontend Security（Web フロントエンドセキュリティ） | CSP、Cookie フラグ、CORS、クリックジャッキング、SRI、postMessage |
| V4 | API and Web Service（API と Web サービス） | REST/GraphQL/WebSocket 固有事項、コンテンツタイプ、HTTP メソッドの扱い |
| V5 | File Handling（ファイル処理） | アップロードの種類/サイズ、Web ルート外での保存、パストラバーサル、zip slip |
| V6 | Authentication（認証） | パスワードポリシー、ブルートフォース、MFA、資格情報のリカバリー |
| V7 | Session Management（セッション管理） | 再生成、タイムアウト、ログアウト、トークンバインディング |
| V8 | Authorization（認可） | 機能/オブジェクト/フィールドレベルの認可、テナント分離 |
| V9 | Self-contained Tokens（自己完結型トークン） | JWT 検証、アルゴリズム固定、クレーム（exp/aud/iss） |
| V10 | OAuth and OIDC | PKCE、リダイレクト URI、state/nonce、トークンの扱い |
| V11 | Cryptography（暗号） | アルゴリズム、鍵管理、乱数、ハッシュ |
| V12 | Secure Communication（安全な通信） | 全経路での TLS、証明書検証、HSTS |
| V13 | Configuration（設定） | シークレット管理、デバッグ、既定値、依存関係の設定 |
| V14 | Data Protection（データ保護） | 機微データの分類、保存時の保護、キャッシュ、保持期間 |
| V15 | Secure Coding and Architecture（セキュアコーディングとアーキテクチャ） | 依存関係の衛生管理、危険な関数、並行処理、マスアサインメント |
| V16 | Security Logging and Error Handling（セキュリティログとエラー処理） | セキュリティイベント、ログインジェクション、エラー処理、フェイルクローズ |
| V17 | WebRTC | TURN/STUN、メディア暗号化、シグナリング認証（WebRTC がある場合のみ） |

レベル: L1 = 全アプリの最低限、L2 = 機微データを扱うアプリ（監査の既定の目標）、
L3 = 高保証（決済の中核、医療、重要インフラ）。報告書には目標レベルを明記する。

## Part C - CWE Top 25 2025 早見表

順位上位 10: CWE-79 XSS、CWE-89 SQLi、CWE-352 CSRF、CWE-862 Missing Authorization、CWE-787 OOB
Write、CWE-22 Path Traversal、CWE-416 Use After Free、CWE-125 OOB Read、CWE-78 OS Command Injection、
CWE-94 Code Injection。メモリ安全性の CWE（787/416/125）は C/C++/unsafe Rust/ネイティブモジュールにのみ
該当する。これらについては Semgrep のカバレッジは部分的であるため、欠落を明記するか言語固有のツールを使う。
全リスト: https://cwe.mitre.org/top25/

## Part D - 認証の詳細（NIST SP 800-63-4、最終版 2025-07-31）

クライアントが NIST に準拠している場合、または ASVS V6 の根拠として引用する:
- パスワード: 単一要素の場合は最低 15 文字（MFA 併用時は 8 文字）、少なくとも 64 文字まで許容、
  文字種構成ルールなし、定期的な強制変更なし、漏洩済み/よく使われるパスワードのリストと照合する。
- フィッシング耐性のある認証器（WebAuthn/パスキー）は AAL3 で必須、管理者には推奨。
- ハードコードされた資格情報（CWE-798）は Top 10:2025 の **A07**（認証）に対応し、A04 ではない。
- SMS OTP は制限付き認証器である。特権ユーザーの唯一の第二要素になっている場合は指摘する。
注: PCI DSS v4.0.1 Req 8.3.6 は対象範囲のシステムについて別途、最低 12 文字（数字 + 英字）を要求する。
適用される方を引用し、決済システムでは両方を引用する。

## Part E - IPA「安全なウェブサイトの作り方」（日本）早見表
日本の契約や受入検査では、IPA の 安全なウェブサイトの作り方（正規名 `IPA How to Secure Your Web Site`、版は
`reference/standards/index.md` に従う）への準拠がしばしば求められる。顧客が日本企業である場合、または報告書の
言語が ja の場合は、OWASP / ASVS の引用と並べて第 1 章の項番とともに引用する：
`IPA How to Secure Your Web Site 7th 1.1`。このガイドは 根本的解決（原因を取り除く修正）と 保険的対策（緩和策）を
示している。コードが保険的対策しか適用していない指摘事項は、その旨を記載する。

| 項番 | 脆弱性 | ガイドが求める根本的解決 | Top 10:2025 | ASVS 5.0.0 | CWE |
|---|---|---|---|---|---|
| 1.1 | SQL インジェクション | すべてのクエリでプレースホルダ / バインド変数を使う | A05 | V1.2 | CWE-89 |
| 1.2 | OS コマンド・インジェクション | シェルを起動する API を使わない。引数を固定する | A05 | V1.2 | CWE-78 |
| 1.3 | パス名パラメータの未チェック / ディレクトリ・トラバーサル | 入力からファイル名を作らない。ディレクトリを固定する。ファイル名部分のみを使う | A01 | V5.3 | CWE-22 |
| 1.4 | セッション管理の不備 | 推測できない ID、ログイン時に再発行、URL に含めない、`Secure` 属性付きの Cookie | A07 | V7.1、V7.2 | CWE-384 |
| 1.5 | クロスサイト・スクリプティング | すべての出力をエスケープする。属性値を引用符で囲む。URL のスキームを制限する。入力からスクリプトでマークアップを生成しない | A05 | V1.2、V3.4 | CWE-79 |
| 1.6 | CSRF（クロスサイト・リクエスト・フォージェリ） | 状態を変更するリクエストに秘密のトークンまたは再認証。`SameSite` は保険的対策 | A01 | V3.5 | CWE-352 |
| 1.7 | HTTP ヘッダ・インジェクション | ヘッダ出力用の API を使い、入力から CR/LF を入れない | A05 | V4.2 | CWE-113 |
| 1.8 | メールヘッダ・インジェクション | ヘッダを固定し、入力から CR/LF を入れない | A05 | V1.3 | CWE-93 |
| 1.9 | クリックジャッキング | `frame-ancestors` / `X-Frame-Options` | A02 | V3.4 | CWE-1021 |
| 1.10 | バッファオーバーフロー | 境界を検査する API、メモリ安全な言語 | A05 | V1.4 | CWE-120 |
| 1.11 | アクセス制御や認可制御の欠落 | すべてのリソースでサーバー側の認可 | A01 | V8.2 | CWE-862、CWE-639 |
