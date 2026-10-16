# MITRE ATT&CK Navigator for Dummies

Pick a few APT groups and get a color-coded ATT&CK overlap map with no clicking around in the Navigator.

The tool pulls the latest MITRE ATT&CK data for the **Enterprise** matrix (the default), or for **Mobile** or **ICS** if you ask for it. It finds every technique (T-code) the selected groups are documented as using, and colors each one by how many of the groups share it. The result is a layer you open in the real [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/).

## What it looks like

APT28, APT29, Lazarus Group and APT41, captured directly from the live [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (dark theme) after loading the tool's layer files with **Open Existing Layer**.

### Parent techniques only

Each T-code is colored by how many of the 4 groups use it or any of its sub-techniques.

![ATT&CK Navigator, dark theme: parent-only overlap layer for APT28, APT29, Lazarus Group and APT41](https://raw.githubusercontent.com/BrentPizza/MITRE-ATTACK-Navigator-for-Dummies/main/docs/navigator_dark_parent_only.png)

### Parent techniques and sub-techniques

Sub-techniques expand beside their parents, and each one is colored by its own overlap. A parent can be red while some of its sub-techniques are only used by one group. Click the image for full size.

![ATT&CK Navigator, dark theme: parent and sub-technique overlap layer for APT28, APT29, Lazarus Group and APT41](https://raw.githubusercontent.com/BrentPizza/MITRE-ATTACK-Navigator-for-Dummies/main/docs/navigator_dark_parent_and_sub.png)

Close-up of the first tactics:

![Close-up of the parent and sub-technique layer](https://raw.githubusercontent.com/BrentPizza/MITRE-ATTACK-Navigator-for-Dummies/main/docs/navigator_dark_parent_and_sub_detail.png)

All files from this run (both layers, Excel, PDF and slide legends) are in [`examples/APT28_APT29_Lazarus_APT41`](examples/APT28_APT29_Lazarus_APT41).

## Colors

The color scale adapts to how many groups you pick. Light green always means one group. The more groups you pick, the more steps there are between "one group" and "all of them":

| Groups picked | 🟩 LIGHT GREEN | 🟨 YELLOW | 🟧 ORANGE | 🟥 RED | ⬛ DARK RED |
|---|---|---|---|---|---|
| 1 | 1 | | | | |
| 2 | 1 | | | 2 (both) | |
| 3 | 1 | 2 | | 3 (all) | |
| 4 | 1 | 2 | 3 | 4 (all) | |
| 5 | 1 | 2 | 3 | 4 | 5 (all) |
| 6 | 1 | 2–3 | 4 | 5 | 6 (all) |
| 7 | 1 | 2–3 | 4–5 | 6 | 7 (all) |
| 8 | 1 | 2–3 | 4–5 | 6–7 | 8 (all) |
| 10 | 1 | 2–4 | 5–7 | 8–9 | 10 (all) |

The numbers are how many of the selected groups use a technique. From 5 groups up, the counts between 1 and "all" are split into three near-equal bands (yellow, orange, red), and dark red is kept for techniques that **every** selected group uses. Each report, layer legend and console run prints the exact scale used. The full lookup table (1–20 groups), color hex codes and a worked example are in **[docs/COLOR_RULES.md](docs/COLOR_RULES.md)**.

Only techniques that at least one selected group has used are shown. Everything else is left out, both in the reports and in the Navigator layer.

## What you get

Every run creates two sets of outputs, plus a legend for slides:

```
output/<timestamp>_<matrix>_<groups>/
├── <groups>_legend_for-light-navigator.svg   slide legend for a light Navigator screenshot
├── <groups>_legend_for-dark-navigator.svg    slide legend for a dark Navigator screenshot
├── (.png copies of both legends, if Pillow is installed)
├── 1_Parent_Only/       parent T-codes only (sub-technique use rolled up into the parent)
│   ├── <groups>_parent-only_layer.json
│   ├── <groups>_parent-only.xlsx
│   └── <groups>_parent-only.pdf
└── 2_Parent_and_Sub/    parent T-codes + the sub-techniques used, each with its own color
    ├── <groups>_parent-and-sub_layer.json
    ├── <groups>_parent-and-sub.xlsx
    └── <groups>_parent-and-sub.pdf
```

* **`_layer.json`**: an ATT&CK Navigator layer. Unused techniques are hidden. In the parent-and-sub layer, sub-techniques expand under their parents.
* **`.xlsx`**: an Excel workbook with three sheets:
  * **Summary**: groups, color legend and counts per tactic.
  * **Technique Overlap**: one row per technique with a ✔ per group. Filterable, and sub-technique rows can be collapsed.
  * **Tactic Matrix**: a Navigator-style grid.
* **`.pdf`**: a dark-themed report with a summary page, the color-coded matrix and a detail table.
* **`_legend_for-*-navigator.svg`** (and `.png`): a slide-ready legend table (merged **LEGEND** header, one color cell and label per overlap level, e.g. "All 4 groups", "3 of 4 groups"). Use the `light` file on a screenshot of the light Navigator theme and the `dark` file on the dark theme.

### Slide legend

Clip the matrix from ATT&CK Navigator into PowerPoint, then insert the matching legend (Insert → Pictures) on top of an empty corner.

* **SVG** (always produced): a vector image, so it stays sharp at any size. PowerPoint draws its text in **Franklin Gothic Medium, bold** from the workstation's own fonts. Inserting SVG needs PowerPoint 2019, 2021 or Microsoft 365.
* **PNG** (only when the optional Pillow library is installed): for older PowerPoint versions. It uses Franklin Gothic (Bold, then Demi, Heavy or Medium) if installed, otherwise the bundled [Libre Franklin](fonts/OFL.txt), the open-source version of the same typeface. The console says which font it used.

The PDF report for the same 4 groups (summary page and matrix):

![PDF summary page](https://raw.githubusercontent.com/BrentPizza/MITRE-ATTACK-Navigator-for-Dummies/main/docs/summary.png)
![PDF matrix with sub-techniques](https://raw.githubusercontent.com/BrentPizza/MITRE-ATTACK-Navigator-for-Dummies/main/docs/matrix_parent_and_sub.png)

## Quick start

**All you need is Python 3.10 or newer.** Nothing gets installed. The ATT&CK data ships in `data/`, and `--offline` runs on plain Python plus only the libraries already on the machine (see [Offline use](#offline-use)).

1. Download or clone this repo.
2. Open a terminal (Command Prompt or PowerShell) in the repo folder and run:
   ```
   python attack_overlap.py --offline
   ```
   (`--offline` never touches the network and never loads anything that isn't already installed.)
3. Pick the matrix: just press **Enter** for Enterprise, or type `mobile` or `ics`.
4. Type your groups, separated by commas. You can use names, aliases or G-IDs:
   ```
   Groups> APT28, Cozy Bear, G0034
   ```
5. Confirm. The output folder opens automatically.

On a personal PC you can also double-click `Run ATTACK Overlap.bat`, which does the same thing.

The ATT&CK data for all three matrices ships in `data/`, so the tool works straight after download, including on machines with no internet (see [Offline use](#offline-use)).

Interactive commands:

| Command | Does |
|---|---|
| `list` | show every group |
| `find bear` | search names and aliases |
| `quit` | exit |

## Command line

Enterprise is the default. Put `mobile` or `ics` first to use one of those matrices instead:

```bash
python attack_overlap.py APT29 "Aquatic Panda" APT1                 # Enterprise
python attack_overlap.py mobile APT28 APT-C-23 Windshift            # Mobile
python attack_overlap.py ics "Sandworm Team" ALLANITE APT33         # ICS
```

Names don't need exact spacing or capitals (`AquaticPanda` works). Not every group appears in every matrix. To see which groups a matrix has, use `python attack_overlap.py mobile --list`.

| Option | Description |
|---|---|
| `--mode both\|parents\|subs` | which output set(s) to build (default `both`) |
| `--no-campaigns` | ignore techniques from campaigns attributed to the groups (included by default, same as attack.mitre.org) |
| `--include-software` / `--no-software` | count (or don't count) techniques of the malware and tools each group uses. Off by default for Enterprise, on by default for Mobile and ICS, where ATT&CK links most groups to techniques through their malware |
| `--update` | re-download the latest ATT&CK data before running |
| `--offline` | never use the network and use only libraries already installed: ATT&CK data comes from `data/`, and outputs whose library is missing are skipped with a note |
| `--list` / `--search TEXT` | list or search the groups in the chosen matrix, then exit |
| `--title "..."` | custom report title |
| `--out DIR` | custom output folder |

## Offline use

The repo includes the MITRE ATT&CK data for all three matrices, so it runs on an air-gapped or offline machine:

```
data/
├── enterprise-attack.json
├── mobile-attack.json
└── ics-attack.json
```

Add `--offline` to any command. The tool then never touches the network and **does not install or load any library that isn't already installed on the machine**. It does not use the bundled copies in `vendor/` either:

```bash
python attack_overlap.py --offline APT28 APT29 "Lazarus Group"
python attack_overlap.py --offline mobile APT28 APT-C-23
```

What you get depends only on what the machine already has:

| Output | Needs | If missing |
|---|---|---|
| Navigator layers (`_layer.json`, both sets) | Python only | always delivered |
| SVG slide legends | Python only | always delivered |
| Excel workbooks (`.xlsx`) | `openpyxl` | skipped |
| PDF reports (`.pdf`) | `reportlab` | skipped |
| PNG slide legends | `Pillow` | skipped (SVG still delivered) |

Each skipped output is reported on screen and in `NOTE_outputs_not_delivered.txt` in the output folder, e.g.:

```
NOTE: openpyxl library needed for Excel workbook - cannot deliver Excel workbook
NOTE: reportlab library needed for PDF report - cannot deliver PDF report
NOTE: Pillow library needed for PNG slide legend - cannot deliver PNG slide legend (SVG slide legend still provided)
```

Whatever is delivered is identical to a full run. Every run also prints which data file it used and how current it is, e.g. `ATT&CK Enterprise data: data/enterprise-attack.json (MITRE data as of 2026-07-31) [offline]`.

To refresh the bundled data, run once on a machine with internet using `--update`, then copy the updated `data/` folder across.

## Bundled libraries (normal runs only)

Without `--offline`, the tool can still produce the Excel and PDF outputs on a machine that doesn't have the libraries installed. It does this with **`vendor/`**, which holds plain, readable Python source (no compiled code) for [openpyxl](https://openpyxl.readthedocs.io/) 3.1.5 (MIT license) and its helper et_xmlfile 2.0.0 (MIT), and [reportlab](https://www.reportlab.com/) 5.0.1 (BSD license). Each library's license file is inside its `*.dist-info` folder. Installed copies always take priority, and **`--offline` never uses `vendor/`**.

* **Pillow** contains compiled code, so it is never bundled. reportlab loads Pillow at startup but only uses it to embed pictures, which these PDFs never do. When Pillow is missing, `vendor/_no_pillow/` gives reportlab a small stand-in so the PDF can still be built.
* **`data/`** holds the ATT&CK data and **`fonts/`** the PNG legend font, so nothing is downloaded.

Tested on Python 3.11, 3.12 and 3.13 with network access blocked:
* with no packages installed, using `--offline` (layers and SVG legends, plus the notes)
* with no packages installed, without `--offline` (everything except the PNG legends)
* with everything installed

Whatever is delivered is identical to a full install.

## Loading the layer in ATT&CK Navigator

1. Open <https://mitre-attack.github.io/attack-navigator/>.
2. Choose **Open Existing Layer**, then **Upload from local**.
3. Pick the `_layer.json` file.

Hover over a technique to see which groups used it. The legend shows the color key.

## How overlap is calculated

* A group "uses" a technique if ATT&CK has a `uses` relationship from the group, or from a campaign attributed to it, to that technique or one of its sub-techniques.
* **Parent T-codes**: any sub-technique use counts toward its parent. For example, T1059.001 counts as T1059.
* **Sub-techniques** (in the parent-and-sub outputs) are scored on their own. A parent can be RED while some of its sub-techniques are a lower color.
* Revoked and deprecated objects are ignored.
* If only one group is selected, everything it uses is LIGHT GREEN.
* Each run uses one matrix. The output folder and file names start with it (`Enterprise_`, `Mobile_` or `ICS_`), and the layer opens in the matching Navigator matrix.

## Data and attribution

This tool uses the [MITRE ATT&CK®](https://attack.mitre.org/) dataset from [mitre/cti](https://github.com/mitre/cti).
ATT&CK® is a registered trademark of The MITRE Corporation, used under MITRE's [Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
This project is not affiliated with or endorsed by MITRE.
