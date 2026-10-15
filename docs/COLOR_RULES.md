# Color Rules

Every technique (T-code) is colored by **how many of the selected groups use it**. The color scale depends on how many groups you selected. Light green always means "only one group". With more groups, there are more steps between "one group" and "every group".

## The colors

| Color | Hex | Meaning |
|---|---|---|
| 🟩 **LIGHT GREEN** | `#90EE90` | Used by only **one** selected group |
| 🟨 **YELLOW** | `#F4D35E` | **Low** overlap |
| 🟧 **ORANGE** | `#F48C06` | **Medium** overlap |
| 🟥 **RED** | `#E5383B` | **High** overlap. With 2–4 groups selected, red is also "used by all of them" |
| ⬛ **DARK RED** | `#9D0208` | Used by **every** selected group. Only appears when 5 or more groups are selected |

## The rules

1. **1 group:** everything is light green.
2. **2 groups:** 1 = light green, 2 = red.
3. **3 groups:** 1 = light green, 2 = yellow, 3 = red.
4. **4 groups:** 1 = light green, 2 = yellow, 3 = orange, 4 = red.
5. **5 or more groups:**
   * 1 = light green
   * **all** of them = dark red
   * The counts in between (2 up to one less than the total) are split into three bands that are as equal as possible: yellow (lowest), orange, red (highest). When the split isn't even, the extra counts go to the lower bands first.

## Lookup table

Find the number of groups you selected. The cells show how many of those groups use a technique for it to get each color.

| Groups selected | 🟩 Light green | 🟨 Yellow | 🟧 Orange | 🟥 Red | ⬛ Dark red |
|---|---|---|---|---|---|
| 1 | 1 | — | — | — | — |
| 2 | 1 | — | — | 2 (both) | — |
| 3 | 1 | 2 | — | 3 (all) | — |
| 4 | 1 | 2 | 3 | 4 (all) | — |
| 5 | 1 | 2 | 3 | 4 | 5 (all) |
| 6 | 1 | 2–3 | 4 | 5 | 6 (all) |
| 7 | 1 | 2–3 | 4–5 | 6 | 7 (all) |
| 8 | 1 | 2–3 | 4–5 | 6–7 | 8 (all) |
| 9 | 1 | 2–4 | 5–6 | 7–8 | 9 (all) |
| 10 | 1 | 2–4 | 5–7 | 8–9 | 10 (all) |
| 11 | 1 | 2–4 | 5–7 | 8–10 | 11 (all) |
| 12 | 1 | 2–5 | 6–8 | 9–11 | 12 (all) |
| 13 | 1 | 2–5 | 6–9 | 10–12 | 13 (all) |
| 14 | 1 | 2–5 | 6–9 | 10–13 | 14 (all) |
| 15 | 1 | 2–6 | 7–10 | 11–14 | 15 (all) |
| 16 | 1 | 2–6 | 7–11 | 12–15 | 16 (all) |
| 17 | 1 | 2–6 | 7–11 | 12–16 | 17 (all) |
| 18 | 1 | 2–7 | 8–12 | 13–17 | 18 (all) |
| 19 | 1 | 2–7 | 8–13 | 14–18 | 19 (all) |
| 20 | 1 | 2–7 | 8–13 | 14–19 | 20 (all) |

More than 20 groups follows the same rule. Every run also prints its exact scale, both in the console and in the legend of the layer, Excel workbook and PDF.

## Example

With 6 groups selected (APT28, APT29, Lazarus Group, APT41, Turla, FIN7):

| Technique used by… | Color |
|---|---|
| 1 group | 🟩 Light green |
| 2 or 3 groups | 🟨 Yellow |
| 4 groups | 🟧 Orange |
| 5 groups | 🟥 Red |
| all 6 groups | ⬛ Dark red |

## Parents and sub-techniques

* **Parent-only output:** a group counts toward a parent T-code if it uses the parent or any of its sub-techniques. For example, T1059.001 counts as T1059.
* **Parent-and-sub output:** each sub-technique is colored on its own count. A parent can therefore be red while some of its sub-techniques are a lower color.

The rule lives in `color_bands()` in [`attack_overlap.py`](../attack_overlap.py).
