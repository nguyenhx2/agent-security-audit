# モジュール：owasp-api - OWASP API Security Top 10 2023

HTTP/GraphQL/gRPC/WebSocket のあらゆる面に適用する。`OWASP API Security Top 10 2023 APIx` に加え、
ASVS 5.0.0 の章（V4 API、V8 Authorization、V2 Business Logic）と CWE を引用する。バージョンは
`reference/standards/index.md` に従う。ほぼすべての行が **Manual**（手動確認）- API の認可不備はパターンではなく「欠如」として現れる。

## 方法：まずエンドポイント一覧を作る
1. ルーター/コントローラー/OpenAPI 仕様からルートを列挙する（ドキュメントからではない）。GraphQL では
   すべての query、mutation、subscription、resolver を、gRPC ではすべてのサービスメソッドを列挙する。
2. 各ルートについて：認証は必須か？ ロール/権限チェックは？ オブジェクト所有者チェックは？ 入力スキーマは？ レート制限は？
   作業メモに表として記録する - 表の欠けこそが指摘事項である。
3. 一覧をゲートウェイ/IaC が公開しているものと比較する（API9）：未文書化、旧バージョン
   （`/v1/`）、デバッグ用、または内部用のルートが外部から到達可能でないか。

## チェック項目

| ID | リスク | 検証内容 | 場所 / grep のヒント |
|----|------|----------------|--------------------|
| API1 | Broken Object Level Authorization (BOLA/IDOR) | クライアントが指定した ID によるオブジェクト参照が、すべて呼び出し元（所有者/テナント）に限定されている | `params.id`、`req.params`、`{id}` パス変数 -> `findById`、`get(pk=`、`find(params[:id])`。GraphQL の `node(id:)` resolver |
| API2 | Broken Authentication | トークン検証が完全（署名、alg、exp、aud、iss）。認証を迂回するルートがない。総当たり対策の制限がある。API キーが URL に含まれない | 認証ミドルウェア、JWT 検証、`/login`、`/token`、`apiKey=` クエリパラメータ |
| API3 | Broken Object Property Level Authorization | 書き込み時にマスアサインメントがない。読み取り時に過剰な露出がない（シリアライザは許可されたフィールドのみ返す。例：`password_hash`、`is_admin`、`ssn` を返さない） | `req.body` をモデルに展開、`fields = '__all__'`、許可リストのない `toJSON`、内部フィールドを公開する GraphQL 型 |
| API4 | Unrestricted Resource Consumption | ページネーション上限、リクエストサイズ制限、アップロード制限、レート制限、GraphQL の深さ/複雑度制限、タイムアウト。コストの発生する呼び出し（SMS、メール、LLM トークン）はユーザー単位で抑制 | 上限のない `limit=`、`bodyParser` の制限、`graphql-depth-limit`、リクエスト経路内の LLM 呼び出し |
| API5 | Broken Function Level Authorization | 管理者/特権機能がサーバー側でロールを確認している。HTTP メソッドの切り替え（GET と DELETE）で迂回できない | `/admin`、`/internal`、ロールデコレータ、ミドルウェアを欠くルートグループ |
| API4+ | レート制限のキーと適用範囲 | コストや悪用につながるすべてのルートに制限がある（SMS / メール送信、リセット、OTP 検証、検索、エクスポート、GraphQL のエイリアス）。キーが偽装可能なヘッダー（信頼するプロキシの一覧がない `X-Forwarded-For`）ではない。ストアがインスタンス間で共有されている | `keyGenerator`、`trust proxy`、`throttle`、メモリ内ストア、`routes.md` とリミッター設定の対応 |
| API6 | Unrestricted Access to Sensitive Business Flows | 自動化されると事業に損害を与えるフロー（購入、予約、紹介、クーポン、登録、OTP）に自動化対策がある | チェックアウト、プロモーション、招待、OTP のエンドポイント |
| API7 | Server Side Request Forgery | ユーザーが影響を与えられる URL をサーバー側で取得する場合に許可リスト化されている。メタデータエンドポイントと内部アドレス範囲を遮断。DNS リバインディングを考慮 | Webhook、URL インポート、画像プロキシ、PDF/HTML レンダリング、OAuth `request_uri` |
| API8 | Security Misconfiguration | CORS、詳細すぎるエラー、TLS の欠如、過度に許可された HTTP メソッド、本番環境での GraphQL introspection/playground の既定有効 | CORS 設定、エラーハンドラ、`introspection: true`、`playground` |
| API9 | Improper Inventory Management | 旧 API バージョン、ステージングホスト、デバッグ用エンドポイントが廃止または保護されている。OpenAPI が実態と一致 | `/v1`、`/beta`、`/debug`、本番の swagger、IaC/ゲートウェイのルート一覧 |
| API10 | Unsafe Consumption of APIs | サードパーティの応答を検証、タイムアウト設定、TLS 検証、リダイレクトを盲目的に追従しない。パートナーからのデータを信頼できないものとして扱う | 外向き HTTP クライアント、Webhook コンシューマ、決済事業者の応答 |

## プロトコル固有のチェック（ASVS 5.0.0 V4 とともに引用）
| 対象面 | 検証内容 | 場所 |
|---------|----------------|-------|
| GraphQL | resolver でのフィールド単位の認可（ゲートウェイだけでなく）。深さ/複雑度/コストの制限。エイリアスとバッチングの悪用を制限（エイリアスを付けた 1000 個の `login` mutation による総当たり）。本番では introspection と playground を無効化。公開クライアントには persisted queries | resolver、`graphql-shield`、`depthLimit`、Apollo/Yoga の設定 |
| WebSocket | アップグレード時に `Origin` を確認（クロスサイト WebSocket ハイジャック）。接続時の認証に加え、メッセージ/サブスクリプションごとの認可。メッセージサイズとレートの制限 | `ws`、`socket.io`、ActionCable、Channels のコンシューマ |
| gRPC | 本番ではサーバーリフレクションを無効化。メソッド単位の認証インターセプタ。TLS（`insecure` チャネルを使わない）。メッセージサイズ制限。デッドラインの設定 | インターセプタ、`grpc.reflection`、チャネル認証情報 |
| Webhook（受信） | 生のボディに対して定数時間比較で署名を検証、タイムスタンプの許容幅、リプレイ/冪等性の保護 | 事業者のコールバックハンドラ |

## 重大度の目安
- 他ユーザーの個人情報、決済・健康データ、または管理機能を露出する BOLA/BFLA -> データ分類に応じて P0/P1
  （`reference/method/triage.md`）。
- コスト増幅要因のない API4 -> 通常 P2。有料の下流処理（SMS/LLM）がある場合 -> P1。
- 本番環境の GraphQL introspection 単独 -> 隠れた特権操作を露出しない限り Info/P2。
