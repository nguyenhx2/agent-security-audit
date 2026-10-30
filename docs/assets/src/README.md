# Figure sources and brand

**English** · [日本語](README.ja.md)

Each `.drawio` file here is the source of the SVG of the same name in `docs/assets/`. Edit the
source, never the SVG. Every figure has an English source and a `.ja` source; change one and you
change the other.

| Source | Figure | Shown in |
|---|---|---|
| `audit-pipeline.drawio` | Phases 0-8: what scripts do, what models do, the outputs | README "How an audit runs", ARCHITECTURE |
| `threat-intel-flow.drawio` | Repo pins -> platform_inventory -> threat_intel <- feeds -> intel.json -> triage -> report | README "Live threat intelligence", ARCHITECTURE |
| `coverage-map.drawio` | Technical domains and industry sectors with their standards | README "What it checks" |
| `model-allocation.drawio` | Model and effort per depth and subagent | README "Models per task", ARCHITECTURE |
| `scanner-update-flow.drawio` | Weekly trigger -> update_pins --check <- registries -> smoke test -> write + gates -> one PR -> human merge -> z release; failures -> issue; pins during an audit | README "Tools that keep up" |

## Regenerate

From the repository root. The second step is not optional: the raw draw.io export carries a
DOCTYPE that `scripts/check_svg.py` refuses, theme styles that flip the card on GitHub's dark
theme, and no `<title>` or `<desc>`.

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

On another platform, replace the first path with the local draw.io binary (`drawio` on Linux,
`/Applications/draw.io.app/Contents/MacOS/draw.io` on macOS). draw.io 30.0.4 plus
`drawio_clean.py` writes no timestamp, so a re-export is byte-identical.

The accessible title and description are not drawn. They live in the `figure-title` and
`figure-desc` attributes on each source's `<diagram>` element, and `drawio_clean.py` copies them
into the SVG. Change the drawing and you change those too: the README alt text serves one language,
the `<desc>` serves every reader of the SVG.

## Diagram conventions

- **One opaque card.** Every figure sits on a `#F8FAFC` card with a `#CBD5E1` border, so it reads
  the same on GitHub's light and dark themes. Never a transparent background.
- **Self-contained.** No external fonts or images, no `<script>`, no SMIL animation, nothing at
  opacity 0. `scripts/check_svg.py` enforces all of it.
- **`html=0` cells, `whiteSpace=nowrap`.** Text is plain SVG `<text>`, so it renders in an `<img>`
  context. A line that is too long overflows instead of wrapping: break it by hand and re-check the
  export.
- **Font:** Helvetica in the source; the viewer substitutes its system sans (and its Japanese
  font for `.ja`). Title 22 bold, subtitle 14, card heading 14 (12 in dense grids) bold, body 12.
- **Colour means a role, the same in every figure:**

| Role | Fill | Stroke | Text |
|---|---|---|---|
| Deterministic script, no model | `#FFFFFF` | `#3E5C7A` | `#0B1F33` / `#334155` |
| Model judgement (Sonnet) | `#CCFBF1` | `#0F766E` | `#134E4A` |
| Model judgement (Opus) | `#0F766E` | `#0F766E` | `#FFFFFF` |
| Lead in the main session | `#F1F5F9` | `#94A3B8` | `#334155` |
| Network, live feeds | `#FEF3C7` | `#B45309` | `#78350F` |
| Gap, failure | `#FEE2E2` | `#B91C1C` | `#7F1D1D` |
| Output, phase header | `#FFFFFF` / `#16365C` | `#16365C` | `#0B1F33` / `#FFFFFF` |

- **Edges:** `#475569`, 2 px, block arrow, orthogonal. Feeds into a step: amber `#B45309`. A
  failure path: red `#B91C1C`, dashed. An optional step: dashed.
- **Japanese text** follows the README.ja punctuation: `、` and `。`, full-width `（）` and `：`
  around Japanese, no `。` in headings or card titles, code and file names unchanged.

## Brand palette

One palette for the banner, the logo, the figures and the plugin icon.

| Token | Hex | Use |
|---|---|---|
| Ink navy | `#0B1F33` | wordmark, headings, the shield's base |
| Navy | `#16365C` | shield body, phase headers, code lines in the mark |
| Navy light | `#1E4470` | top of the shield gradient |
| Steel | `#3E5C7A` | secondary text, script cards |
| Signal teal | `#2DD4BF` | the lens and the shield rim in the mark |
| Teal | `#14B8A6` | accents |
| Teal deep | `#0F766E` | text-safe teal (tagline, Opus cells) |
| Teal light | `#5EEAD4` | top of the rim gradient |
| Amber | `#F59E0B` | the live signal and the lit finding in the mark |
| Amber deep | `#B45309` | text-safe amber (feed edges) |
| Glass | `#EAF6F8` | inside the lens |
| Paper | `#F5F8FB` to `#E4EDF5` | banner background gradient |

The marks:

- `logo.svg` - the full mark: a navy shield (the audit's boundary), a lens reading three code
  lines with one lit in amber (a finding), and an amber signal (advisories fetched at audit time).
- `logo-mark.svg` - the small-size mark: shield, lens, one amber line and the amber dot. The plugin
  icon is rendered from it by `scripts/make_icons.py`; change the mark, re-run that script.
- `readme-banner.svg` / `.ja.svg` - the README banner. The PNGs next to them are what the READMEs
  embed, so fonts render the same everywhere. Regenerate a PNG at 1600 x 400 from its SVG in a
  headless Chrome (for example puppeteer's `page.screenshot` with a 1600 x 400 viewport).
