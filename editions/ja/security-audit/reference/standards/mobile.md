# モジュール：mobile - OWASP MASVS 2.1.0、MASTG 2.0.0、Mobile Top 10 2024

Android（Java/Kotlin）、iOS（Swift/ObjC）、Flutter、React Native、Expo、Capacitor/Ionic に適用する。
コントロールには `OWASP MASVS 2.1.0 MASVS-<GROUP>-<n>` を、リスクには `OWASP Mobile Top 10 2024 Mx` を
引用する。検証手法を挙げる場合は MASTG 2.0.0 のテスト ID（`MASTG-TEST-xxxx`）を引用する。
スキャナ：`mobsfscan`（ソース）。Semgrep の Dart カバレッジは弱い - Flutter ではそのカバレッジの欠落を明記する。

## アプリバイナリ内のものはすべて公開情報である
アプリにコンパイルされたキー、シークレット、エンドポイントの認証情報、機能フラグ（`strings.xml`、
`Info.plist`、Expo/RN が同梱する `.env`、Dart 定数、`BuildConfig` フィールド）は**定義上
公開されている** -> シークレットには P0 の強制ルール（`reference/method/triage.md`）。サーバー側のコントロールで
引き下げることはできない。

## MASVS グループ別のチェック

| グループ | 検証内容 | 場所 / grep のヒント | Top 10 2024 |
|-------|----------------|--------------------|-------------|
| STORAGE | SharedPreferences/UserDefaults/AsyncStorage/Hive/平文 SQLite に機微データがない。Keystore/Keychain/EncryptedSharedPreferences を使用。バックアップから機微ファイルを除外。ログやクリップボードに機微データがない | `SharedPreferences`、`UserDefaults`、`AsyncStorage`、`shared_preferences`、`Log.d`、`print(`、`allowBackup="true"` | M9 |
| CRYPTO | ハードコードされたキー/IV がない。鍵素材にはプラットフォームのキーストア。最新のアルゴリズム | `SecretKeySpec("...")`、`IvParameterSpec(new byte[16])`、定数キーを用いる Dart `encrypt` | M10 |
| AUTH | 認証をサーバー側で強制。生体認証は Keystore/Keychain の暗号操作に紐付ける（真偽値ではない）。セッショントークンを失効可能 | `CryptoObject` なしの `BiometricPrompt`、結果を真偽値として使う `LAContext.evaluatePolicy` | M3 |
| NETWORK | TLS のみ。平文通信なし。証明書検証が損なわれていない。高リスクアプリでは証明書ピンニング | `usesCleartextTraffic="true"`、`NSAllowsArbitraryLoads`、すべてを受け入れる独自の `TrustManager`/`HostnameVerifier`、`badCertificateCallback => true` | M5 |
| PLATFORM | エクスポートされたコンポーネントを保護。ディープリンクを検証。WebView を強化（信頼できないコンテンツで `setJavaScriptEnabled` + `addJavascriptInterface` を使わない、ファイルアクセスなし）。インテント/URL スキームが呼び出し元を信頼しない | `android:exported="true"`、intent-filter、`addJavascriptInterface`、`setAllowFileAccess(true)`、信頼できない URL を読み込む `WKWebView`、`openURL` ハンドラ | M4, M8 |
| CODE | 依存関係が最新。入力を検証。信頼できない提供元からの動的コード読み込みがない。サポートされた最小 SDK | `DexClassLoader`、RN ブリッジ内の `eval`、Gradle/Podfile/pubspec 内の古い SDK | M2, M4 |
| RESILIENCE | （脅威モデルが必要とする場合のみ）root/脱獄検知、改ざん/デバッグ検知、難読化。証明書ピンニングは MASVS-NETWORK-2、タップジャッキングは MASVS-PLATFORM-3 であり RESILIENCE ではない | ProGuard/R8 の設定、リリースビルドの `debuggable="true"` | M7 |
| PRIVACY | データ最小化、権限の正当性、トラッキングへの同意、サードパーティ SDK のデータフローの申告 | `AndroidManifest` の権限、ATT プロンプト、同意前の分析 SDK 初期化 | M6 |

M1 Improper Credential Usage は STORAGE/CRYPTO/AUTH のシークレットに、M8 Security Misconfiguration は
PLATFORM/NETWORK の設定に対応する。

## Flutter / React Native 固有の事項
- Flutter：`flutter_secure_storage`（良い）と `shared_preferences`（平文）。リリースビルドは
  `--obfuscate` 付き。`dart:io HttpClient.badCertificateCallback`。`--dart-define` のシークレットはバイナリに含まれる。
- React Native / Expo：`EXPO_PUBLIC_*` と `react-native-config` の値は JS バンドルに同梱される。
  AsyncStorage は平文。Hermes バイトコードは保護にならない。

## カバレッジの記載
静的なソースレビューではランタイムの保護（ピンニングの有効性、root 検知、
ランタイムでのキーチェーンのアクセス可能性）を検証できない。MASTG の動的テストは未実施である旨を明記する。
