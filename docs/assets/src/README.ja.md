# 図のソースとブランド

[English](README.md) · **日本語**

このフォルダの各 `.drawio` ファイルは、`docs/assets/` にある同名の SVG のソースです。編集するのはソースで、
SVG を直接編集してはいけません。どの図にも英語のソースと `.ja` のソースがあり、片方を変えたらもう片方も変えます。

| ソース | 図の内容 | 掲載先 |
|---|---|---|
| `audit-pipeline.drawio` | Phase 0-8：スクリプトが行うこと、モデルが行うこと、出力 | README「監査の流れ」、ARCHITECTURE |
| `threat-intel-flow.drawio` | リポジトリの指定 -> platform_inventory -> threat_intel <- フィード -> intel.json -> トリアージ -> 報告書 | README「ライブ脅威情報」、ARCHITECTURE |
| `coverage-map.drawio` | 技術領域と業種、それぞれの基準 | README「確認する範囲」 |
| `model-allocation.drawio` | 深さとサブエージェントごとのモデルと effort | README「タスクごとのモデル」、ARCHITECTURE |
| `scanner-update-flow.drawio` | 毎週の起動 -> update_pins --check <- レジストリ -> スモークテスト -> 書き込みとゲート -> PR 1 件 -> 人がマージ -> z リリース。失敗 -> Issue。監査中のピン | README「最新に追従するツール」 |

## 再生成

リポジトリのルートで実行します。2 つ目の手順は省略できません。draw.io の書き出しそのままでは、
`scripts/check_svg.py` が拒否する DOCTYPE が付き、GitHub のダークテーマでカードの色が反転するテーマ用スタイルが残り、
`<title>` と `<desc>` もありません。

```sh
for f in audit-pipeline threat-intel-flow coverage-map model-allocation scanner-update-flow; do
  for v in "" ".ja"; do
    "C:/Program Files/draw.io/draw.io.exe" -x -f svg --svg-theme light -o raw.svg "docs/assets/src/$f$v.drawio"
    python docs/assets/src/drawio_clean.py "docs/assets/src/$f$v.drawio" raw.svg "docs/assets/$f$v.svg"
  done
done
rm raw.svg
python scripts/check_svg.py
```

ほかのプラットフォームでは、最初のパスをその環境の draw.io に置き換えます（Linux は `drawio`、macOS は
`/Applications/draw.io.app/Contents/MacOS/draw.io`）。draw.io 30.0.4 と `drawio_clean.py` の組み合わせは
タイムスタンプを書き込まないため、書き出し直しても同じバイト列になります。

読み上げ用のタイトルと説明は描画されません。各ソースの `<diagram>` 要素の `figure-title` 属性と
`figure-desc` 属性にあり、`drawio_clean.py` がそれを SVG にコピーします。図を変えたら、これらも変えてください。
README の代替テキストが役に立つのは 1 つの言語だけですが、`<desc>` は SVG を読むすべての人に届きます。

## 図の規約

- **不透明なカードを 1 枚。** どの図も `#F8FAFC` のカード（枠線 `#CBD5E1`）の上に描き、GitHub のライトテーマでも
  ダークテーマでも同じように読めるようにします。背景を透明にしてはいけません。
- **自己完結。** 外部のフォントや画像、`<script>`、SMIL アニメーション、不透明度 0 の要素は使いません。
  すべて `scripts/check_svg.py` が検査します。
- **`html=0` のセル、`whiteSpace=nowrap`。** 文字はただの SVG の `<text>` なので、`<img>` の中でも表示されます。
  長すぎる行は折り返されずにはみ出すため、手で改行し、書き出し結果を確認します。
- **フォント：** ソースでは Helvetica。表示側がシステムのサンセリフ体（`.ja` では日本語フォント）に置き換えます。
  タイトル 22 太字、サブタイトル 14、カード見出し 14（密な表では 12）太字、本文 12。
- **色は役割を表し、すべての図で同じです：**

| 役割 | 塗り | 枠線 | 文字 |
|---|---|---|---|
| 決定論的なスクリプト（モデルなし） | `#FFFFFF` | `#3E5C7A` | `#0B1F33` / `#334155` |
| モデルの判断（Sonnet） | `#CCFBF1` | `#0F766E` | `#134E4A` |
| モデルの判断（Opus） | `#0F766E` | `#0F766E` | `#FFFFFF` |
| メインセッションのリード | `#F1F5F9` | `#94A3B8` | `#334155` |
| ネットワーク、ライブフィード | `#FEF3C7` | `#B45309` | `#78350F` |
| 未確認範囲、失敗 | `#FEE2E2` | `#B91C1C` | `#7F1D1D` |
| 出力、フェーズの見出し | `#FFFFFF` / `#16365C` | `#16365C` | `#0B1F33` / `#FFFFFF` |

- **矢印：** `#475569`、2 px、ブロック型の矢じり、直交ルーティング。フィードからの入力は琥珀色 `#B45309`、
  失敗の経路は赤 `#B91C1C` の破線、任意の手順は破線。
- **日本語の文字** は README.ja と同じ約物を使います。`、` と `。`、日本語の前後では全角の `（）` と `：`、
  見出しやカードの題には `。` を付けず、コードとファイル名はそのまま書きます。

## ブランドの配色

バナー、ロゴ、図、プラグインのアイコンで共通の配色です。

| トークン | 16 進 | 用途 |
|---|---|---|
| Ink navy | `#0B1F33` | ワードマーク、見出し、盾の下端 |
| Navy | `#16365C` | 盾の本体、フェーズの見出し、マーク内のコード行 |
| Navy light | `#1E4470` | 盾のグラデーションの上端 |
| Steel | `#3E5C7A` | 補助的な文字、スクリプトのカード |
| Signal teal | `#2DD4BF` | マークのレンズと盾の縁 |
| Teal | `#14B8A6` | アクセント |
| Teal deep | `#0F766E` | 文字に使えるティール（タグライン、Opus のセル） |
| Teal light | `#5EEAD4` | 縁のグラデーションの上端 |
| Amber | `#F59E0B` | ライブの信号と、マーク内で光る指摘 |
| Amber deep | `#B45309` | 文字に使える琥珀色（フィードの矢印） |
| Glass | `#EAF6F8` | レンズの内側 |
| Paper | `#F5F8FB` から `#E4EDF5` | バナーの背景のグラデーション |

マーク：

- `logo.svg`：フルサイズのマーク。紺の盾（監査の境界）、3 行のコードを読むレンズ（1 行が琥珀色に光る指摘）、
  琥珀色の信号（監査時に取得する脆弱性情報）。
- `logo-mark.svg`：小さいサイズ用のマーク。盾、レンズ、琥珀色の 1 行と点。プラグインのアイコンは
  `scripts/make_icons.py` がここから描画します。マークを変えたら、このスクリプトを実行し直してください。
- `readme-banner.svg` / `.ja.svg`：README のバナー。README に埋め込むのは隣の PNG で、どの環境でも同じフォントで
  表示されます。PNG は SVG からヘッドレスの Chrome で 1600 x 400 として書き出します（例：puppeteer の
  `page.screenshot`、ビューポート 1600 x 400）。
