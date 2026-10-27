# カバレッジチェックリスト：手法カタログに照らした監査の採点

**これはクロスチェックであり、監査の背骨ではない。** バージョン付きの基準
（`reference/standards/index.md`）は引き続きすべての指摘事項の根拠であり、指摘事項は `standard + version +
requirement id` を引用する。このチェックリストは逆方向の失敗のためにある：選んだ基準が何を見るかを決めてしまうため、
**対応付けた基準の隙間に落ちる脆弱性クラス**は見えなくなる。選んだ基準がそれを含意していると信じるのではなく、
このリストで自分の監査を採点する：「オープンリダイレクトは本当に確認したか。Host ヘッダポイズニングは。
マスアサインメントは。」

**出典：** Hacksplaining の脆弱性カタログ（https://www.hacksplaining.com/lessons）。実践的で手法志向のレッスン集
である。こうしたカタログは**変化する**：脅威の状況に応じてレッスンが追加・改名される（下記の AI クラスは最近の
追加分）。固定ではなく**生きたチェックリスト**として扱い、監査時に出典を再確認し、増えたクラスを追加する。

## 目次
使い方、アクセス制御と認証、インジェクションとデータフロー、通信とネットワーク、
クロスオリジンとブラウザ、サプライチェーンと運用、露出・パッチ適用状況・侵害時の影響範囲、
AI 固有、報告書への反映。

## 使い方
すべての行を確認する。各行について：このクラスが当てはまり得るリポジトリで、この監査はそれを確認したか。
covered（確認済）/ not-applicable（該当なし）/ **gap**（欠落）を付ける。欠落はそれ自体がカバレッジに関する
指摘事項であり、対象外の言語を記載するのと同じように、報告書のカバレッジのセクション
（`templates/audit-report.md.template` のセクション 2）に記載する。`Seen by` 列は、SAST の実行結果が
クリーンであることがそもそも根拠になるかを示す：**SAST** = スキャナで検出できる（それでも読んで確認する）。
**Manual** = 決定的なツールでは構造的に見えないため、何も検出されないことに意味はない。読解で探す
（`reference/method/design-flaws.md`）。**SAST+Manual** = スキャナで一部は見つかるが、設計上の欠陥は読解が必要。**Script+Manual** = 同梱の
スクリプト（`platform_inventory.py`、`threat_intel.py`）が手掛かりを列挙し、判定は読解で行う。

基準の列は `reference/standards/index.md` のバージョン付きの表に対応する。指摘事項で引用する際はバージョンも
付ける（例：`OWASP ASVS 5.0.0`、`OWASP API Security Top 10 2023`、`PCI DSS v4.0.1`）。

## アクセス制御と認証
| クラス | 概要 | 根拠となる基準 | 確認箇所 | Seen by |
|-------|----------|-----------------|---------------|---------|
| Broken Access Control（アクセス制御の不備） | リソースやアクションに対する authz の欠落 / 誤り | ASVS; API Top 10 (BOLA/BFLA) | 特権を要するすべてのエンドポイントにおけるサーバー側の authz チェック | Manual |
| Privilege Escalation（権限昇格） | ユーザーがロールを超える権限を得る | ASVS; API Top 10 | ロール / 権限のチェック、管理者専用の経路、状態遷移 | Manual |
| Session Fixation（セッション固定） | 認証後にセッション ID が更新されない | ASVS（セッション管理） | ログインハンドラ：権限変更時にセッションが再生成されるか | Manual |
| Weak Session IDs（脆弱なセッション ID） | 予測可能 / エントロピーの低いセッショントークン | ASVS（セッション管理） | トークン生成：乱数源、長さ、エントロピー | SAST+Manual |
| User Enumeration（ユーザー列挙） | 応答からアカウントの存在有無がわかる | ASVS 5.0.0; Top 10:2025 | ログイン / リセット / サインアップ：エラーメッセージや応答時間に差があるか | Manual |
| Password Mismanagement（パスワードの不適切な管理） | 弱いハッシュ、可逆な保存、ポリシーなし | ASVS; `reference/method/sensitive-data-at-rest.md` を参照（可逆 = 誤り） | パスワードの保存と検証、マイグレーション / スキーマ | SAST+Manual |
| Clickjacking（クリックジャッキング） | 攻撃者が UI をフレームに埋め込みクリックを乗っ取る | ASVS 5.0.0; Top 10:2025 | `X-Frame-Options` / `frame-ancestors` CSP ヘッダ | SAST |
| Token / ID Validity Oracle（トークン / ID の有効性オラクル） | 不正な形式・未知・期限切れ・有効なトークンやオブジェクト ID で、ステータス、本文、サイズ、応答時間が異なる | ASVS 5.0.0 V6; API Top 10 2023 API2; CWE-204, CWE-208 | トークンの照合と認証ミドルウェアのエラー分岐、オブジェクトのルートでの 401/403/404 の使い分け、シークレットの `==` 比較 | Manual |
| Rate-limit Key and Coverage（レート制限のキーと適用範囲） | SMS / メール送信、リセット、OTP 検証、検索、エクスポート、GraphQL のエイリアスに制限がない。キーが偽装可能なヘッダー由来。複数インスタンスの背後でメモリ内ストアを使う | API Top 10 2023 API4, API6; CWE-307, CWE-799 | リミッターの設定（`keyGenerator`、`throttle`、ストア）を `routes.md` と照らし合わせる | Manual |
| Client-IP Header Trust（クライアント IP ヘッダーの信頼） | `X-Forwarded-For` の先頭の値を許可リスト、レート制限のキー、監査ログ、地域ブロックに信頼して使う | ASVS 5.0.0 V13; CWE-348, CWE-290 | `trust proxy`、`ProxyFix`、`TrustedProxies`、`RemoteIpValve`、IP 許可リストのコード | SAST+Manual |
| Long-lived / Unrevocable Tokens（長期間有効 / 失効できないトークン） | API トークン、PAT、ログイン保持やリフレッシュのトークンに有効期限やスコープがない、平文で保存されている、パスワード変更・ロール変更・無効化で失効しない | ASVS 5.0.0 V7, V9; API Top 10 2023 API2; NHI Top 10 2025 NHI7; CWE-613 | トークンのテーブル（`expires_at`、ハッシュ、`scopes`）、発行 / 検証のコード、無効化とパスワード変更のハンドラ | Manual |
| Spoofable Gateway Identity（偽装可能なゲートウェイの ID） | バックエンドが接続元を検証せずにプロキシのヘッダー（`X-User`、`X-Forwarded-User`）からユーザー / テナントを読む。バックエンドのポートにも直接到達できる | Top 10:2025 A07; CWE-290 | ミドルウェアでのヘッダー読み取り、compose / Kubernetes でのバックエンドのポート公開 | Manual |
| Insecure Config Fallback（安全でない設定のフォールバック） | 認証、CSRF、TLS 検証、テナントのスコープが環境変数のフラグや変数の未設定で無効になる。リテラルの既定シークレット | Top 10:2025 A02, A10; CWE-1188, CWE-636 | `process.env.X or '...'` のような既定値、`getenv(.., default)`、制御を囲む `if env != 'production'`、本番を弱めるオーバーレイ | SAST+Manual |
| Account Linking / Email Collision（アカウント連携 / メールアドレスの衝突） | ソーシャル / SSO ログインが `email_verified` なしにメールアドレスで既存アカウントに統合される。IdP のキーが `iss` + `sub` でない。先行登録による乗っ取り | ASVS 5.0.0 V10; Top 10:2025 A07; CWE-287 | OAuth のコールバック、メールアドレスによるユーザー検索、「危険なメール連携」のフラグ | Manual |
| MFA Bypass / Factor Management（MFA の迂回 / 認証要素の管理） | 別のログイン経路（API、モバイル、旧方式、SSO）が MFA を通らない。再認証なしに認証要素やリカバリーコードを変更できる。端末記憶のトークンが紐付けられていない | ASVS 5.0.0 V6; NIST SP 800-63-4; PCI DSS v4.0.1 Req 8.4.2; CWE-308 | `routes.md` のすべてのログインルートと MFA チェックの対応、認証要素の CRUD ハンドラ | Manual |
| SAML Assertion Handling（SAML アサーションの処理） | 読み取る要素とは別の要素で署名を検証している。audience、recipient、有効期限、`InResponseTo` を確認していない | Top 10:2025 A07; ASVS 5.0.0 V6; CWE-347 | SAML ライブラリの設定（`wantAssertionsSigned`、`strict`）、独自のアサーション解析 | Manual |
| Scope-bypassing Data Access（スコープを迂回するデータアクセス） | 生の SQL、`unscoped()`、`withoutGlobalScopes()`、service-role / 管理者用の DB クライアント、テナントのフィルタを通らないジョブやエクスポート | API Top 10 2023 API1; ASVS 5.0.0 V8; CWE-639, CWE-863 | すべての DB クライアントと生のクエリを列挙し、それぞれのテナント条件を確認する | Manual |
| Signed URLs and Share Links（署名付き URL と共有リンク） | TTL が長い、またはワイルドカードのキーを持つ事前署名 URL、オブジェクトの認可なしの発行、ACL 変更後も有効。有効期限や失効のない共有リンク | API Top 10 2023 API1; CWE-639, CWE-613 | `getSignedUrl`、`generate_presigned_url`、`createSignedUrl`、共有トークンのテーブル | Manual |
| Search Index Exposure（検索インデックスの露出） | 管理者用またはスコープのない検索キーがクライアントにある。非公開のフィールドがインデックスされている。ユーザーごとのフィルタがない。非表示のフィールドでの並べ替え / 絞り込みがオラクルになる | API Top 10 2023 API3; CWE-200, CWE-203 | インデクサーのコード、クライアントのバンドル内のキー、検索エンドポイントのフィルタ | Manual |
| Revocation Propagation（失効の伝播） | 無効化されたユーザー、削除されたメンバー、格下げされたロールが、トークン、キャッシュされた権限、JWT のクレーム、ソケット、キュー内のジョブを通じてアクセスを保持する | ASVS 5.0.0 V7, V8; CWE-613 | 無効化 / メンバー削除のハンドラが何を無効にするか | Manual |
| Unreferenced Privileged Routes（参照されない特権ルート） | どのクライアントも呼ばないルート（ロール変更、ユーザー作成、なりすまし、一括操作）にまだ到達できる。「隠れている」ことは認可ではない | API Top 10 2023 API5, API9; CWE-285 | `routes.json` とクライアント（Web、モバイル、生成されたクライアント）の API 呼び出しを突き合わせる | Manual |

## インジェクションとデータフロー
| クラス | 概要 | 根拠となる基準 | 確認箇所 | Seen by |
|-------|----------|-----------------|---------------|---------|
| SQL Injection（SQL インジェクション） | 信頼できない入力がパラメータ化されずにクエリへ到達する | ASVS; Top 10:2025 A05 | データアクセス層、文字列連結で組み立てたクエリ | SAST |
| Command Execution（コマンド実行） | 信頼できない入力がシェル / OS 呼び出しへ到達する | ASVS; Top 10:2025 A05 | `exec`/`system`/`spawn` の呼び出し箇所 | SAST |
| Remote Code Execution（リモートコード実行） | 攻撃者が任意のコードを実行する | ASVS 5.0.0; Top 10:2025 | デシリアライズ、テンプレート評価、動的な `eval`、アップロード+インクルード | SAST+Manual |
| Cross-Site Scripting (Reflected/DOM/Stored)（クロスサイトスクリプティング） | 信頼できないデータが有効なマークアップ / スクリプトとして描画される | ASVS; Top 10:2025 A05 | すべてのシンクでの出力エンコーディング、`innerHTML`、テンプレートの自動エスケープ | SAST+Manual |
| Cross-Site Script Inclusion (XSSI)（クロスサイトスクリプトインクルージョン） | 機微な JS/JSON が `<script>` 経由でクロスオリジンに読み込まれる | ASVS | スクリプトとして配信される JSON エンドポイント、XSSI 対策のプレフィックス | Manual |
| CSS Injection（CSS インジェクション） | 攻撃者が制御する CSS によるデータ持ち出し / 改ざん | ASVS | ユーザーが制御するスタイルの内容 / 属性 | Manual |
| Regex Injection (ReDoS)（正規表現インジェクション） | 細工した入力による壊滅的なバックトラック | ASVS; DoS | 正規表現にコンパイルされるユーザー入力、高コストなパターン | Manual |
| Mass Assignment（マスアサインメント） | リクエストが設定すべきでないフィールドにバインドされる | API Top 10 | 許可リストなしのモデルバインディング / `update(params)` | Manual |
| Prototype Pollution（プロトタイプ汚染） | 入力経由で `__proto__`/プロトタイプチェーンが変更される | ASVS 5.0.0; Top 10:2025 | 信頼できないオブジェクトの再帰的なマージ / クローン | SAST+Manual |
| NoSQL Operator Injection（NoSQL 演算子インジェクション） | リクエストのオブジェクトがクエリのフィルタに届き、`$ne`、`$gt`、`$regex`、`$where` でクエリが変わる（ログインの迂回、ブラインドでの列挙） | Top 10:2025 A05; CWE-943 | `find(req.body`、`{email: req.body.email}`、`$regex: req.`、`qs` のブラケット解析、無害化 / 文字列への変換なし | SAST+Manual |
| Export / Import Scope and CSV Formula（エクスポート / インポートの範囲と CSV 数式） | エクスポートがサービスの権限で動く、またはテナントをまたぐ。インポートが認可を通らない。セルが `= + - @` で始まる | API Top 10 2023 API1, API3; CWE-639, CWE-1236 | エクスポート / レポート / バックアップのジョブ、CSV / XLSX の書き出し処理、インポートのエンドポイント | Manual |
| Queue / Event Consumer Trust（キュー / イベントのコンシューマーの信頼） | コンシューマーがメッセージ本文中の ID で認可している。プッシュのエンドポイント（SNS、Pub/Sub、EventBridge）に署名や送信元の確認がない。副作用が冪等でない | Top 10:2025 A08; CWE-345, CWE-290 | コンシューマーのハンドラ、プッシュ型 Webhook のルート、重複排除のキー | Manual |
| Decompression / Expansion Bombs（解凍 / 展開爆弾） | 本文の展開、アーカイブの解凍、画像のデコードで、展開後のサイズ、エントリ数、ピクセル数に上限がない | API Top 10 2023 API4; CWE-409 | `zlib`、`gunzip`、`ZipFile`、`unzipper`、`MAX_IMAGE_PIXELS`、`limitInputPixels` | SAST+Manual |
| Pre-auth Cost / Password Length（認証前のコスト / パスワード長） | レート制限より前に高コストなハッシュや外部呼び出しがある。パスワードの最大長がない。72 バイトを超える bcrypt の入力が黙って切り詰められる | ASVS 5.0.0 V6; API Top 10 2023 API4; CWE-405 | ログイン / サインアップのハンドラ、`bcrypt(id + password)` のような入力 | Manual |
| XML External Entities (XXE)（XML 外部エンティティ） | XML パーサでの外部エンティティ解決 | ASVS; Top 10:2025 A02 | XML パーサの設定：外部エンティティ解決が無効化されているか | SAST |
| XML Bombs（XML 爆弾） | エンティティ展開による DoS（billion laughs） | ASVS; DoS | XML パーサのエンティティ展開の上限 | SAST+Manual |
| Directory Traversal（ディレクトリトラバーサル） | `../` により想定ルート外のファイルに到達する | ASVS 5.0.0; Top 10:2025 | ユーザー入力から組み立てたパス、ファイル読み取り / 配信ハンドラ | SAST |
| File Upload Vulnerabilities（ファイルアップロードの脆弱性） | アップロードの種類 / サイズ / 保存先に制限がない | ASVS 5.0.0; Top 10:2025 | アップロードハンドラ：種類の許可リスト、保存パス、実行可否 | SAST+Manual |
| Open Redirects（オープンリダイレクト） | 検証されていない入力からリダイレクト先を取得する | ASVS 5.0.0; Top 10:2025 | リクエストパラメータから組み立てたリダイレクト / `Location` | SAST+Manual |
| Server-Side Request Forgery（サーバーサイドリクエストフォージェリ） | サーバーが攻撃者の選んだ URL を取得する（クラウドメタデータ、内部サービス） | Top 10:2025 A01; API Top 10 2023 API7 | URL 取得処理、Webhook、プレビュー、PDF レンダラ | SAST+Manual |
| Fail-open error handling（フェイルオープンなエラー処理） | セキュリティチェック内の例外によりアクセスが許可される | Top 10:2025 A10 | verify/authz/決済を囲み成功を返す `catch`/`except` | Manual |
| Race conditions / double-spend（競合状態 / 二重支払い） | 同時リクエストにより残高 / 上限チェックを回避する | ASVS 5.0.0 V15; `reference/standards/pci-dss.md` を参照 | ロックやバージョン管理のない読み取り-変更-書き込み | Manual |

## 通信とネットワーク
| クラス | 概要 | 根拠となる基準 | 確認箇所 | Seen by |
|-------|----------|-----------------|---------------|---------|
| Unencrypted Communication（暗号化されていない通信） | 機微な通信が平文で行われる | ASVS; PCI DSS v4.0.1（伝送）; CIS | HTTP を許可するエンドポイント / サービス、内部サービス呼び出し | SAST+Manual |
| SSL Stripping（SSL ストリッピング） | 中間者が HTTPS を HTTP に格下げする | ASVS | HSTS ヘッダ + preload、TLS 強制の設定 | SAST+Manual |
| Downgrade Attacks（ダウングレード攻撃） | 弱いプロトコル / 暗号スイートへの強制的なフォールバック | ASVS; CIS | TLS バージョン / 暗号スイートのポリシー、サーバー設定 / IaC | SAST+Manual |
| DNS Poisoning（DNS ポイズニング） | 偽造された DNS 応答で通信がリダイレクトされる | インフラ/CIS | リゾルバの信頼、DNSSEC、固定されたエンドポイント | Manual |
| Host Header Poisoning（Host ヘッダポイズニング） | アプリが攻撃者の設定した `Host` をリンクやキャッシュキーに信頼して使う | ASVS | 絶対 URL / パスワードリセットリンクの組み立て、キャッシュキー | Manual |
| Subdomain Squatting（サブドメインの乗っ取り） | 廃止済みホストを指す残存 DNS が取得される | CIS; インフラ | 廃止されたリソースを指す DNS レコード | Manual |
| Shared-cache Leakage / Cache Deception（共有キャッシュからの漏洩 / キャッシュディセプション） | 認証済みの応答が CDN やプロキシにキャッシュされる（`private` / `no-store` なし）、拡張子に基づくキャッシュ規則、応答を変えるがキーに含まれないヘッダー、ユーザーやテナントを含まないキャッシュキー | ASVS 5.0.0 V14; Top 10:2025 A02; CWE-524 | リポジトリ内の CDN / エッジの設定、`proxy_cache`、フレームワークのキャッシュミドルウェア、キャッシュキーの組み立て | Manual |
| Request Smuggling / Parse Disagreement（リクエストスマグリング / 解析の不一致） | リポジトリ内のプロキシが曖昧な `Transfer-Encoding` / `Content-Length` を転送する、HTTP/2 のダウングレード、独自の HTTP 解析 | ASVS 5.0.0 V4; CWE-444 | リポジトリ内の nginx / HAProxy / Envoy の設定、独自のサーバー | Manual |

## クロスオリジンとブラウザ
| クラス | 概要 | 根拠となる基準 | 確認箇所 | Seen by |
|-------|----------|-----------------|---------------|---------|
| Cross-Origin Resource Sharing (CORS)（オリジン間リソース共有） | 過度に寛容な CORS により認証済みデータが露出する | ASVS; API Top 10 | `Access-Control-Allow-Origin`：ワイルドカード、反射されたオリジン + 資格情報 | SAST+Manual |
| Cross-Site Request Forgery (CSRF)（クロスサイトリクエストフォージェリ） | 別サイトから状態を変更するリクエストが偽造される | ASVS 5.0.0; Top 10:2025 | 変更系ルートでの CSRF 対策トークン / SameSite Cookie | Manual |
| Malvertising（マルバタイジング） | 悪意あるサードパーティの広告 / スクリプト | ASVS; Insecure Design | サードパーティのスクリプト / iframe、CSP `script-src` | Manual |
| Browser Messaging and Storage（ブラウザのメッセージングとストレージ） | `message` ハンドラが `event.origin` を厳密に確認しない。データ付きの `postMessage(.., '*')`。認証済みの応答をキャッシュする Service Worker。ログアウト後も残るトークン | ASVS 5.0.0 V3; CWE-346 | `addEventListener('message'`、`sw.js` / Workbox のキャッシュ、ログアウトのハンドラ | SAST+Manual |

## サプライチェーンと運用
| クラス | 概要 | 根拠となる基準 | 確認箇所 | Seen by |
|-------|----------|-----------------|---------------|---------|
| Toxic Dependencies（有害な依存関係） | 既知の脆弱性を持つサードパーティパッケージ | ASVS; Top 10:2025 A03 | ロックファイル：SCA を実行（Trivy/OSV、`reference/tooling/scanners.md`） | SAST |
| Slop Squatting（スロップスクワッティング） | AI が幻覚したパッケージ名を攻撃者が登録する | Top 10:2025 A03; AISVS 1.01; LLM Top 10 2026 LLM04 | 新規 / 見慣れない依存関係、特に AI が提案したもの。それぞれ実在し正規であるかを確認 | Manual |
| Native Code / FFI（ネイティブコード / FFI） | リポジトリ内の C/C++ 拡張、cgo、JNI、node-gyp のアドオン、Rust の `unsafe` におけるメモリ安全性の不具合 | CWE Top 25 2025 (CWE-787, CWE-416, CWE-125) | `binding.gyp`、`*.c`、`ext_modules`、`import "C"`、`unsafe {` - ネイティブ専用のレビューを実施していなければ未カバー領域として記載する | SAST+Manual |
| CI Cache / Artifact Poisoning（CI のキャッシュ / 成果物の汚染） | 信頼できないトリガーのジョブが、特権ジョブが復元またはリリースするキャッシュや成果物を書き込む。成果物をダイジェストではなく名前で取得する | CICD-SEC-4, CICD-SEC-9; SLSA v1.2; CWE-494 | トリガー間で共有される `actions/cache` のキー、`workflow_run` 内の `download-artifact` | SAST+Manual |
| Denial of Service（サービス拒否） | リソース枯渇によりサービスが停止する | ASVS; DoS | 上限のないループ / ファンアウト、レート制限の欠落、ReDoS、XML 爆弾 | Manual |
| Logging and Monitoring（ログと監視） | セキュリティログの欠落 / 不足 | ASVS; Top 10:2025 A09 | 認証イベント、管理操作：記録されているか、アラートはあるか、ログにシークレットがないか | Manual |
| Information Leakage（情報漏えい） | スタックトレース、詳細なエラー、メタデータによる内部情報の漏えい | ASVS 5.0.0; Top 10:2025 | エラーハンドラ、デバッグフラグ、レスポンスヘッダ、コメント | SAST+Manual |
| Lax Security Settings（緩いセキュリティ設定） | 安全でない既定値 / 弱い設定 | ASVS; CIS; Top 10:2025 A02 | フレームワークの設定、クラウド / IaC の既定値（Checkov を実行） | SAST |
| Insecure Design（安全でない設計） | 実装ではなく設計上の欠陥 | ASVS; Top 10:2025 A06 | 信頼境界、ワークフロー、脅威モデルの欠落 | Manual |
| Email Spoofing（メールのなりすまし） | メール認証の欠落による送信者の偽装 | インフラ/CIS | SPF / DKIM / DMARC レコード | Manual |

## 露出、パッチ適用状況、侵害時の影響範囲（`platform.md` と `intel.md` から始める）
インシデント報告（国の CERT の注意喚起、ハニーポットのデータ）の大半の背景にある、初期侵入と侵害後のクラス：
インターネットから到達できるパッチ未適用のランタイムや製品、配信されるべきでなかったファイルやツール、
そして侵害されると何にでも到達できるサーバー。手法：`reference/method/threat-intel.md`。

| クラス | 概要 | 根拠となる基準 | 確認箇所 | Seen by |
|-------|----------|-----------------|---------------|---------|
| Runtime / Server Patch Level（ランタイム / サーバーのパッチ適用状況） | インタプリタ、サーバー、データストア、ベースイメージが、KEV / 国内注意喚起 / 深刻な CVE のあるバージョンで指定されている、またはサイクルの最新パッチより古い | Top 10:2025 A03; ASVS 5.0.0 V15; PCI DSS v4.0.1 Req 6.3.3; CWE-1395 | `intel.md` の act-now / review の行、Dockerfile、compose、マニフェスト、バージョンファイル、CI での指定 | Script+Manual |
| End-of-life Runtime / Framework（サポート終了のランタイム / フレームワーク） | ランタイム、OS、データストア、フレームワークのサイクルがベンダーの EOL を過ぎている、またはそれを許容するバージョン範囲 | Top 10:2025 A03; PCI DSS v4.0.1 Req 6.3.3, Req 12.3.4; CWE-1104 | `intel.md` のサポート状況の列。マネージドランタイム（Lambda / Functions の `runtime`）も含む | Script+Manual |
| Emergency Patch Readiness（緊急パッチへの備え） | ランタイムの修正を数時間で出荷できない：再ビルドの予定がないタグ追従、ベースイメージの自動更新なし、ディストリビューションのパッケージから入れたランタイム、ダイジェストの未固定 | SSDF v1.1 RV.2; SLSA v1.2; CWE-1395 | `platform.md` のシグナル `no-image-update-automation`、`unpinned-base-image`、CI の再ビルドのトリガー | Script+Manual |
| Web-root File Exposure（Web ルートのファイル露出） | 配信されるディレクトリ内の `.env`、`*.bak`、`*.sql`、アーカイブ、`.git/`、`phpinfo()`、`composer.json`。プロジェクトのルートを起点にした静的配信。ディレクトリ一覧表示 | Top 10:2025 A02; ASVS 5.0.0 V13; CWE-538, CWE-527 | `platform.md` のシグナル。nginx の `root`、`public/`、`express.static`、`WORKDIR` から決まるドキュメントルート、ドットファイルの拒否規則 | Script+Manual |
| Management / Debug Plane Exposure（管理 / デバッグのプレーンの露出） | Tomcat manager / WAR のデプロイ、JMX、Jolokia、health 以外の actuator、Ignition、Telescope、Werkzeug や Rails のデバッグコンソール、MFA のない管理パス | Top 10:2025 A02; API Top 10 2023 API9; CWE-306, CWE-489 | `tomcat-users.xml`、`management.endpoints`、`APP_DEBUG`、`debug=True`、Dockerfile の `COPY *.war` | SAST+Manual |
| Exposed Admin / BI / Data Services（露出した管理 / BI / データのサービス） | Metabase、Grafana、Kibana、Jupyter、phpMyAdmin、Adminer などや、認証なしで公開された Redis / Elasticsearch / Mongo / Postgres | Top 10:2025 A02; CIS Docker v1.9.0; Kubernetes Top 10 2025 K06; CWE-306 | `platform.md` のシグナル `admin-tool-image`、`datastore-port-published`。LoadBalancer 型の Service、Ingress のホスト | Script+Manual |
| Upload-to-Execution Path（アップロードから実行への経路） | アップロードがスクリプトのハンドラを持つドキュメントルート配下に保存される。`.htaccess` / `.user.ini` をアップロードできる。アプリのユーザーがコードのディレクトリに書き込める。書き込み可能なルートファイルシステム | Top 10:2025 A06; ASVS 5.0.0 V5; CWE-434, CWE-732 | アップロード先とドキュメントルートの関係、nginx の `location ~ \.php` の範囲、Dockerfile の `USER` と `chown`、`read_only` | Manual |
| Build-context Leakage（ビルドコンテキストからの漏洩） | `.env*`、`.git`、鍵を除外する `.dockerignore` なしの `COPY . .`。シークレットやソースマップを同梱するパッケージ | Top 10:2025 A02; CIS Docker v1.9.0; CWE-538 | Dockerfile の `COPY` の元と `.dockerignore`、`package.json` の `files`、`.npmignore`、`MANIFEST.in` | Manual |
| Post-compromise Blast Radius（侵害時の影響範囲） | egress が開いたアプリ層（ボットのダウンロード、DDoS への加担、C2 への到達）、コンテナ内の root、実行イメージ内のシェルとダウンロードツール、サービス間で共有される DB のスーパーユーザー、使い回されるワークロードのロール | Kubernetes Top 10 2025 K05, K08; NHI Top 10 2025 NHI9; CWE-250 | `platform.md` のシグナル `sg-egress-any`、`k8s-no-networkpolicy`、`container-runs-as-root`、`download-tools-in-runtime-image`。DB の権限付与、IAM ロールの割り当て | Script+Manual |
| Detection and Forensic Readiness（検知とフォレンジックへの備え） | 誰がどのレコードを読んだかの記録がない。管理、ロール変更、トークン発行、エクスポートのイベントが記録されない。アクセスログがホスト上にしかない、または 12 か月未満しか保持されない | Top 10:2025 A09; ASVS 5.0.0 V16; PCI DSS v4.0.1 Req 10.2.1, Req 10.5.1; CWE-778 | 認証 / 管理 / エクスポートのハンドラでのロガー呼び出し、ログの転送、`retention_in_days`、バケットのライフサイクル | Manual |

## AI 固有（詳細：`reference/standards/ai-llm-agentic.md`）
| クラス | 概要 | 根拠となる基準 | 確認箇所 | Seen by |
|-------|----------|-----------------|---------------|---------|
| Prompt Injection（プロンプトインジェクション） | 信頼できないコンテンツがモデルへの指示を上書きする | AISVS 1.01; LLM Top 10 2026 LLM01; Agentic Top 10 2026 ASI01 | プロンプトの組み立て：信頼できないデータと指示の混在、ツール呼び出しの制御 | Manual |
| Data Extraction Attacks（データ抽出攻撃） | モデルが学習データ / コンテキストを漏らすよう誘導される | AISVS 1.01; LLM Top 10 2026 | システムプロンプト / シークレットの露出、RAG のコンテキスト境界 | Manual |
| Bias and Unreliability（バイアスと信頼性の欠如） | モデル出力が用途に対して不公平または信頼できない | AISVS 1.01; LLM Top 10 2026 | チェックなしにモデル出力が意思決定を左右する箇所 | Manual |
| Excessive Agency / Tool Misuse（過剰な権限 / ツールの悪用） | エージェントのツールが必要以上に広い。破壊的操作に承認がない | LLM Top 10 2026 LLM03; Agentic 2026 ASI02/ASI03 | ツールレジストリ、エージェントに渡された認証情報 | Manual |
| Improper Output Handling（不適切な出力処理） | モデル出力がエンコードされずに HTML/eval/SQL/シェルへ到達する | LLM Top 10 2026 LLM10 | 生成結果の描画 / 実行 | SAST+Manual |
| MCP Tool Poisoning（MCP ツールポイズニング） | ツールのメタデータに隠れた指示 / ラグプルが含まれる | MCP Top 10 (beta) MCP03 | MCP サーバーのツール説明、`.mcp.json` | Manual |
| Agent Permission Over-grant（エージェント権限の過剰付与） | コミットされたエージェントの許可リストが書き込み / 公開 / マージ / 持ち出しのコマンドを事前承認している | Agentic 2026 ASI02/ASI03; LLM Top 10 2026 LLM03 | `.claude/settings.json` の allow/deny、`defaultMode`、スキルの `allowed-tools` | Manual |
| Fail-open Agent Hooks（フェイルオープンなエージェントフック） | エラー時にブロックせず終了する、コマンドの形式を見逃す、または一部の OS で動作しないガード用フック | Top 10:2025 A10; Agentic 2026 ASI02 | `.claude/hooks/*`、フックの終了コード、プラットフォーム | Manual |
| Unvetted Agent Skills / MCP Servers（未審査のエージェントスキル / MCP サーバー） | 出所、バージョン固定、スクリプトのレビューがない同梱スキルや MCP サーバー | Agentic 2026 ASI04; MCP Top 10 (beta) MCP04/MCP09 | `.agents/skills`、`SKILL.md` のスクリプト、`.mcp.json` の起動コマンド | Manual |
| Committed Prompt Logs（コミットされたプロンプトログ） | シークレット、個人データ、顧客データを含むプロンプト履歴 / トランスクリプトがリポジトリ内にある | LLM Top 10 2026 LLM02; CWE-532 | `prompt_history*`、トランスクリプト、`.specstory/`（peek.py） | Manual |
| Agent Self-approval（エージェントの自己承認） | エージェントが自らの変更をコミット、承認、マージ、リリースする | AISVS 1.01 AC.8.1/AC.8.4; CICD-SEC-1 | git 履歴、ブランチルール、エージェントの許可リスト | Manual |

## 業種
detect が `sectors` を列挙した場合（またはユーザーが業種を挙げた場合）は、業種別モジュールの「コードから根拠を示せる
確認項目」の表（`medical` M01-M07、`finance` F01-F10 / C01-C06、`ecommerce` E01-E11、`public-sector` G01-G08、
`education` D01-D08、`iot-ot` T01-T11）を同じ方法で確認する：行ごとに カバー済み / 該当なし / 欠落 とする。

## 報告書への反映
この確認で出た**欠落**はすべて、監査報告書（セクション 2）のカバレッジに関する記載となる。**Manual** と
されたクラスのうち読解していないものは「クリーン」ではなく未調査であり、その旨を記載する（Manual クラスに
対するスキャナの沈黙には意味がない）。保存のクラスについては `reference/method/sensitive-data-at-rest.md` に従い、
設計レベルの Manual クラスの探し方は `reference/method/design-flaws.md` にある。手順に戻る：
`SKILL.md` の Phase 4。
