# コントリビュート

[English](../contributing.md) · **日本語**

Issue とプルリクエストを歓迎します。基準は「主張したものを今も見つけるか、そしてそれだけを見つけるか」で、それを確かめるゲートは自動化されています。詳しい手引きは [CONTRIBUTING.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/CONTRIBUTING.md)（英語）にあります。

## Issue を報告する

- **不具合、誤検知、見逃した欠陥の種類、誤った基準の引用：** [GitHub](https://github.com/nguyenhx2/agent-security-audit/issues) で Issue を作成してください。スキルのバージョン（インストールしたスキルの `VERSION` ファイル）、OS、深さ、期待していた結果を書いてください。監査したコードは、最小限の作り話の例で説明してください。本物の秘密情報、個人データ、非公開のコードは貼り付けないでください。
- **スキル自体の脆弱性**（悪意のあるリポジトリやフィードによって、スクリプトがコードを実行する、自分のフォルダの外に書き込む、秘密情報を漏らす、使うべきでないときにネットワークに接続する、など）：公開の Issue は作らず、[SECURITY.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/SECURITY.md) に書かれている非公開の脆弱性報告を使ってください。

監査したリポジトリの脆弱性はそのリポジトリの所有者に、サードパーティのスキャナやフィードの問題はそれぞれの提供元に報告してください。

## プルリクエストの流れ

1. 原本である英語版 `security-audit/` で変更します。
2. 日本語版 `editions/ja/security-audit/` に同じ変更を反映します。コードはバイト単位で同じにし、コメント、docstring、ヘルプ、コンソールのメッセージは翻訳します。
3. 新しい検出や誤検知の修正には、評価のケースを追加します。`eval/fixtures/` の下に小さなフィクスチャを置き、`eval/cases.json` にそのフィクスチャについて成り立つことを書きます。期待する結果を先に書いてください。
4. リポジトリのルートでゲートを実行します。すべて終了コード 0 で終わる必要があります。

   ```bash
   python security-audit/tests/selftest.py
   python editions/ja/security-audit/tests/selftest.py
   python eval/run_eval.py
   python scripts/check_editions.py
   python scripts/validate_release.py
   python scripts/build_plugins.py --check
   python scripts/check_numbers.py
   python scripts/check_mermaid.py
   python scripts/check_svg.py
   ```

5. プルリクエストを作成します。CI はセルフテストを Ubuntu、Windows、macOS の Python 3.9 と 3.13 で、それ以外を Ubuntu で実行します。

書き方の決まり：em ダッシュは使わず普通のハイフンだけを使い、改行コードは LF にし、数値をでっち上げないでください。ドキュメントの数値は `scripts/check_numbers.py` が確認します。スキャナのピンは手で上げず、毎週の `update-pins` ワークフローが提案します（[スキャナ](scanners.md)）。

## プロジェクトを支援する

このスキルで時間を節約できたら、[GitHub Sponsors](https://github.com/sponsors/nguyenhx2) または [Buy Me a Coffee](https://buymeacoffee.com/nguyenhx2) で支援できます（リポジトリの Sponsor ボタンからも開けます）。

[![Buy me a coffee](../../assets/bmc-button.svg)](https://buymeacoffee.com/nguyenhx2)

![Buy Me a Coffee の QR コード：buymeacoffee.com/nguyenhx2](../../assets/bmc-qr.png)

## 関連ページ

- [CONTRIBUTING.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/CONTRIBUTING.md)
- [リリースの手順](https://github.com/nguyenhx2/agent-security-audit/blob/main/docs/RELEASING.ja.md)
- [eval/README.ja.md](https://github.com/nguyenhx2/agent-security-audit/blob/main/eval/README.ja.md)：オフライン評価
