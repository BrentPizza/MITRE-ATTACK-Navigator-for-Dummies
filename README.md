# MITRE ATT&CK Navigator for Dummies

Pick a few APT groups and get a color-coded ATT&CK overlap map with no clicking around in the Navigator.

The tool pulls the latest MITRE ATT&CK data. It finds every technique (T-code) the selected groups are documented as using, and colors each one by how many of the groups share it:

| Color | Meaning |
|---|---|
| 🟥 **RED** | Used by **3 or more** selected groups (or **both**, if you only picked 2) |
| 🟨 **YELLOW** | Used by **exactly 2** groups (only when you picked 3 or more) |
| 🟩 **LIGHT GREEN** | Used by only **one** selected group |

Only techniques that at least one selected group has used are shown. Everything else is left out, both in the reports and in the Navigator layer.

## What you get

Every run creates two sets of outputs:

```
output/<timestamp>_<groups>/
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

A full example for APT28, APT29 and Sandworm Team is in [`examples/`](examples/APT28_APT29_Sandworm).

![Summary page](docs/summary.png)
![Matrix with sub-techniques](docs/matrix_parent_and_sub.png)

## Quick start (Windows, no command line needed)

1. Install [Python 3.10+](https://www.python.org/downloads/) and tick **"Add python.exe to PATH"**.
2. Download or clone this repo.
3. Double-click **`Run ATTACK Overlap.bat`**.
4. Type your groups, separated by commas. You can use names, aliases or G-IDs:
   ```
   Groups> APT28, Cozy Bear, G0034
   ```
5. Confirm. The output folder opens automatically.

The first run downloads the ATT&CK dataset (about 50 MB) into `data/`. Later runs reuse it.

Interactive commands:

| Command | Does |
|---|---|
| `list` | show every group |
| `find bear` | search names and aliases |
| `quit` | exit |

## Command line

```bash
pip install -r requirements.txt
```

```bash
python attack_overlap.py APT28 APT29 "Sandworm Team"
```

| Option | Description |
|---|---|
| `--mode both\|parents\|subs` | which output set(s) to build (default `both`) |
| `--no-campaigns` | ignore techniques from campaigns attributed to the groups (included by default, same as attack.mitre.org) |
| `--include-software` | also count techniques of the malware and tools each group uses |
| `--update` | re-download the latest ATT&CK data before running |
| `--domain enterprise\|mobile\|ics` | which ATT&CK matrix to use (default `enterprise`) |
| `--list` / `--search TEXT` | list or search groups, then exit |
| `--title "..."` | custom report title |
| `--out DIR` | custom output folder |

## Loading the layer in ATT&CK Navigator

1. Open <https://mitre-attack.github.io/attack-navigator/>.
2. Choose **Open Existing Layer**, then **Upload from local**.
3. Pick the `_layer.json` file.

Hover over a technique to see which groups used it. The legend shows the color key.

## How overlap is calculated

* A group "uses" a technique if ATT&CK has a `uses` relationship from the group, or from a campaign attributed to it, to that technique or one of its sub-techniques.
* **Parent T-codes**: any sub-technique use counts toward its parent. For example, T1059.001 counts as T1059.
* **Sub-techniques** (in the parent-and-sub outputs) are scored on their own. A parent can be RED while some of its sub-techniques are YELLOW or GREEN.
* Revoked and deprecated objects are ignored.
* If only one group is selected, everything it uses is LIGHT GREEN.

## Data and attribution

This tool uses the [MITRE ATT&CK®](https://attack.mitre.org/) dataset from [mitre/cti](https://github.com/mitre/cti).
ATT&CK® is a registered trademark of The MITRE Corporation, used under MITRE's [Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
This project is not affiliated with or endorsed by MITRE.
