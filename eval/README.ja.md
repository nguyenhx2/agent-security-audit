# オフライン評価

[English](README.md) · **日本語**

`run_eval.py` は、API キー・ネットワーク・Docker なしで、監査の土台となる決定的な部分がスキルの説明どおりに動くことを push のたびに確認します。実際の監査を実費で行うライブベンチマークは [`benchmark/`](../benchmark/README.md) にあります。

```bash
python eval/run_eval.py                 # すべて実行（約 2-4 分。大半はセルフテスト）
python eval/run_eval.py --no-selftest   # 速い部分のみ。結果は eval/results/tmp/ に出力
```

チェックごとに 1 行を出力し、最後に `eval N/M` を表示します。すべてのチェックが通ったときだけ終了コード 0 です。フル実行では [`results/latest.json`](results/latest.json) に、部分ごとの合計、適合率と再現率、各チェックの結果を書き出します。タイムスタンプやパスを含まないため、結果が変わったときだけファイルが変わります。`scripts/check_numbers.py` はこのファイルを読み、README に書かれた数値を検証します。

## 各部分が証明すること

| 部分 | 実行するもの | 証明すること |
|---|---|---|
| gates | 両エディションの `tests/selftest.py`、`scripts/check_editions.py`、`vendor/skill-check.py --published` | すべてのスクリプトが両言語でテストどおりに動き、チェック数も同じであること。文字列を伏せると日本語版のコードが英語版と同一であること。スキルがハーネスのスキルリンター（frontmatter の上限、トリガー、参照、トリガーケース）を通ること。 |
| detect | [`fixtures/detect/`](fixtures/detect) に対する `detect_stack.py` | 各業種が依存関係または識別子（`kanja`、`karte`、`monshin` などのローマ字を含む）から検出され、対応する基準モジュールが選ばれること。業種に似た語を含む陰性例（`Sku` だらけの Azure SDK、販促クーポン、単純な API）では業種が検出されないこと。業種ごとの適合率と再現率で採点します。 |
| platform | [`fixtures/platform/`](fixtures/platform) に対する `platform_inventory.py` | ロックファイルのスキャナからは見えない場所のデプロイバージョン（Dockerfile の `ARG` で指定した PHP、compose のイメージ、Terraform の Lambda ランタイム、`.nvmrc`）が見つかり、露出シグナル（root で動くコンテナ、実行イメージ内のダウンロードツール、管理ツール、公開されたデータストアのポート、Web ルート配下の `.env` と `phpinfo()`、`allow_url_include`）が出ること。堅牢化した陰性例ではどれも出ないこと。シグナルごとに採点します。 |
| intel | [`fixtures/feeds/`](fixtures/feeds) に対する `threat_intel.py --feeds-dir` | デプロイされた PHP の正確なバージョンに KEV と国内の注意喚起が重なると EPSS 付きで「直ちに対応」になること。MySQL 5.7 がサポート終了と判定されること。バージョン範囲は最も低いサイクルで判定されること。HTML のエラーページを返すフィードは合格ではなく明示的な欠落になること。悪意あるフィード本文（右から左への上書き文字、注入された指示、外部リンク）が無害化されること。キャッシュが空のオフライン実行でも終了コード 0 で、すべてのフィードが欠落として記録されること。 |

## ケースの追加

`fixtures/detect/` または `fixtures/platform/` にフォルダを追加し、[`cases.json`](cases.json) にそのフィクスチャについて**事実であること**（属する業種、デプロイするコンポーネント、出るべきシグナルと出てはいけないシグナル）を書きます。期待値を先に書いてから評価を実行してください。失敗したケースは修正すべき検出器の欠落であり、通るまでフィクスチャを調整するものではありません。

フィクスチャはスキャン前に一時フォルダへコピーされるため、外側の git リポジトリがスクリプトの見る内容を変えることはありません。IPA フィードの悪意ある文字はリポジトリには保存していません。`fixtures/feeds/ipa.rdf` の `{BIDI}` をコピー時に置き換えます。
