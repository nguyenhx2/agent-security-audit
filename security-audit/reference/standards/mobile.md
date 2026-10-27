# Module: mobile - OWASP MASVS 2.1.0, MASTG 2.0.0, Mobile Top 10 2024

Apply to Android (Java/Kotlin), iOS (Swift/ObjC), Flutter, React Native, Expo, Capacitor/Ionic.
Cite `OWASP MASVS 2.1.0 MASVS-<GROUP>-<n>` for the control and `OWASP Mobile Top 10 2024 Mx` for
the risk; MASTG 2.0.0 test IDs (`MASTG-TEST-xxxx`) when you name the verification technique.
Scanner: `mobsfscan` (source); Semgrep coverage of Dart is weak - state the gap for Flutter.

## Everything in the app binary is public
Any key, secret, endpoint credential, or feature flag compiled into the app (`strings.xml`,
`Info.plist`, `.env` bundled by Expo/RN, Dart constants, `BuildConfig` fields) is **public by
definition** -> P0 override for secrets (`reference/method/triage.md`). Server-side controls cannot
downgrade it.

## Checks by MASVS group

| Group | What to verify | Where / grep hints | Top 10 2024 |
|-------|----------------|--------------------|-------------|
| STORAGE | No sensitive data in SharedPreferences/UserDefaults/AsyncStorage/Hive/plain SQLite; use Keystore/Keychain/EncryptedSharedPreferences; backups exclude sensitive files; no sensitive data in logs or clipboard | `SharedPreferences`, `UserDefaults`, `AsyncStorage`, `shared_preferences`, `Log.d`, `print(`, `allowBackup="true"` | M9 |
| CRYPTO | No hard-coded keys/IVs; platform keystore for key material; modern algorithms | `SecretKeySpec("...")`, `IvParameterSpec(new byte[16])`, Dart `encrypt` with const keys | M10 |
| AUTH | Auth enforced server-side; biometrics bound to a Keystore/Keychain crypto operation (not a boolean); session tokens revocable | `BiometricPrompt` without `CryptoObject`, `LAContext.evaluatePolicy` result used as a bool | M3 |
| NETWORK | TLS only; no cleartext; certificate validation intact; pinning for high-risk apps | `usesCleartextTraffic="true"`, `NSAllowsArbitraryLoads`, custom `TrustManager`/`HostnameVerifier` accepting all, `badCertificateCallback => true` | M5 |
| PLATFORM | Exported components protected; deep links validated; WebViews hardened (no `setJavaScriptEnabled` + `addJavascriptInterface` on untrusted content, no file access); intents/URL schemes not trusting caller | `android:exported="true"`, intent-filters, `addJavascriptInterface`, `setAllowFileAccess(true)`, `WKWebView` loading untrusted URLs, `openURL` handlers | M4, M8 |
| CODE | Dependencies current; input validated; no dynamic code loading from untrusted sources; min SDK supported | `DexClassLoader`, `eval` in RN bridge, outdated SDKs in Gradle/Podfile/pubspec | M2, M4 |
| RESILIENCE | (Only if threat model requires) root/jailbreak detection, tamper/debug detection, obfuscation. Certificate pinning is MASVS-NETWORK-2 and tapjacking is MASVS-PLATFORM-3 - not RESILIENCE | ProGuard/R8 config, `debuggable="true"` in release | M7 |
| PRIVACY | Data minimisation, permissions justified, consent for tracking, third-party SDK data flows declared | `AndroidManifest` permissions, ATT prompts, analytics SDK init before consent | M6 |

M1 Improper Credential Usage maps to STORAGE/CRYPTO/AUTH secrets; M8 Security Misconfiguration to
PLATFORM/NETWORK config.

## Flutter / React Native specifics
- Flutter: `flutter_secure_storage` (good) vs `shared_preferences` (plain); release builds with
  `--obfuscate`; `dart:io HttpClient.badCertificateCallback`; secrets in `--dart-define` are in the binary.
- React Native / Expo: `EXPO_PUBLIC_*` and `react-native-config` values ship in the JS bundle;
  AsyncStorage is plaintext; Hermes bytecode is not protection.

## Coverage statement
Static source review cannot verify runtime protections (pinning effectiveness, root detection,
keychain accessibility at runtime). State MASTG dynamic tests as not performed.
