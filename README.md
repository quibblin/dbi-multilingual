# DBI Multilingual (921 Patcher)

A single-file Python patcher ([`dbi_patcher.py`](dbi_patcher.py)) that builds **DBI Multilingual** from the upstream translated DBI 921 release (`rashevskyv/DBIPatcher`), adding:

- **35-language YAML support** (`languages.yaml`, defaulting to `en` English) with all 24 existing `DBIPatcher` languages, original built-in Russian (`ru`), plus 10 additional world languages (`ar`, `hi`, `bn`, `vi`, `th`, `tl`, `ms`, `el`, `cs`, `sv`).
- **In-app Main Menu "Language" button** (right below **DBI Settings**, above **Exit**) that lists all languages from `sdmc:/switch/DBI/languages.yaml`, updates `selected_language` in `languages.yaml` when changed, and hot-reloads the active translation table on the fly.
- **Interactive `DeviceID` HTTP consent popup**: the first time a remote HTTP server sends `WWW-Authenticate: DeviceID` in a session, a red modal asks whether to **Allow `(+)`** or **Block (any other button)** for the rest of the session.
- **Serial privacy hardening**: stops DBI from scanning `/atmosphere/automatic_backups/*PRODINFO*` (so Exosphere/Incognito serial blanking is respected) and removes DBI's obfuscated hardcoded-serial special cases.
- **No binaries distributed**: `dbi_patcher.py` downloads the upstream `DBI.nro` and 24 upstream translation CSVs directly from `rashevskyv/DBIPatcher` tag `921` and verifies the exact SHA-256 hash before patching.

---

## Quick Start

Requires **Python 3.10+** (standard library only for patching and building translations).

```bash
python3 dbi_patcher.py
```

This will:
1. Download and SHA-256 verify `DBI.nro` (`816db30d9ccc88e3a1cdc6e294ae71ba92b101628437ecddc94d9168fb1aa319`) and the 24 upstream CSVs into `.cache/`.
2. Generate `dbi-output/` containing:
   - `DBI.nro` (patched **DBI Multilingual** binary)
   - `languages.yaml` (active selection `selected_language: en` + all 35 languages)
   - `translation.bin` (English fallback table)
   - `translations/translation_<code>.bin` (34 compiled `DBITRNS` v3 hash-indexed tables)
   - `translations/<code>.yaml` (34 human-editable YAML dictionaries)

### Useful CLI Options

```bash
# Print every documented patch group and offset
python3 dbi_patcher.py --list-patches

# Use a local base DBI 921 NRO without downloading
python3 dbi_patcher.py --input /path/to/DBI.nro --no-download

# Customize the Homebrew Menu app title (default: "DBI Multilingual")
python3 dbi_patcher.py --app-name "DBI Multilingual"

# Recompile .bin lookup tables after editing any dbi-output/translations/*.yaml
python3 dbi_patcher.py --rebuild-translations

# Run offline Capstone + Unicorn ARM64 verification (requires capstone & unicorn)
python3 dbi_patcher.py --verify
```

---

## SD Card Installation

Copy the generated files from `dbi-output/` onto your Switch SD card:

```text
sdmc:/switch/DBI/DBI.nro
sdmc:/switch/DBI/languages.yaml
sdmc:/switch/DBI/translation.bin
sdmc:/switch/DBI/translations/translation_*.bin
```

*(The `.yaml` dictionaries in `dbi-output/translations/` are for human editing on your PC and do not need to be copied to the SD card.)*

### Switching Languages

- **In DBI:** Open **Main Menu → Language**. Use **Up/Down** to move, **L/R** to switch pages, **A** to apply, and **B** to cancel. Selecting a language rewrites `selected_language:` in `sdmc:/switch/DBI/languages.yaml` (preserving comments and custom entries) and immediately hot-reloads the translation table.
- **Manually:** Edit `selected_language: en` at the top of `sdmc:/switch/DBI/languages.yaml` to any language code listed in the file (use `ru` for DBI's built-in Russian strings).

---

## Patch Groups Overview

All patches and assembly routines live declaratively inside `PATCH_GROUPS` in [`dbi_patcher.py`](dbi_patcher.py):

| Group | Offsets | Purpose |
| :--- | :--- | :--- |
| **1. Dedicated BSS Expansion** | `0x38`, `0xfc` | Grows NRO `bss_size` and `MOD0.bss_end` by `+0x4000` (`0x1274000..0x1277fff`) for collision-free, boot-zeroed runtime state above `DBIPatcher`'s `0x1273dc0..0x1273fff` region. |
| **2. Serial Privacy & Hardcoded-Serial Removal** | `0x16c814`, `0x9f6a0`, dead immediates | Skips `/atmosphere/automatic_backups/*PRODINFO*` scanning in `get_console_serial` (respecting Exosphere/Incognito blanking), bypasses both obfuscated hardcoded-serial branches (`XAJ7**********` [tail SHA-256: `5cb63abbe2f4c61c`] and `XAJ7**********` [tail SHA-256: `e6b0f1fa9683e078`], raw serials redacted), and `NOP`-scrubs their unreachable inline-immediate loads. |
| **3. Interactive `DeviceID` HTTP Consent Popup** | `0x378f2c` → `0x950d00` | Hooks the HTTP `WWW-Authenticate: DeviceID` retry trigger into Code Cave 1 (dead `libde265` tail). Shows a native red warning modal on first request per session (`(+)` Allow / any other button Block), caches the choice in BSS `0x1274000`, and fails closed to Block if no UI window is available. |
| **4. YAML Startup Language Loader** | `0x9500e0` → `0xbe1100` | Hooks `DBIPatcher`'s `ensure_loaded()` into Code Cave 2 (`.text` zero tail). Parses `sdmc:/switch/DBI/languages.yaml`, loads the `selected_language` table via unhooked `read_file_to_string` (`0x950564`), supports native `ru` without repeated disk retries, and falls back to `translation.bin` if YAML is missing. |
| **5. Main Menu "Language" Button & Switcher** | `0x50dbb4` → `0xbe1100+` | Appends a native **Language** `MenuItem` right after **DBI Settings** (above **Exit**). Renders a 12-per-page selector, updates `selected_language:` in `languages.yaml` via 3-part `fopen("wb")`/`fwrite`/`fclose`, resets `DBIPatcher` state, and calls `ensure_loaded()` (`0x950078`) to hot-reload live. |
| **6. Homebrew Menu App Name (NACP)** | `0xfd719d` | Updates the NRO `ASET`/NACP title slots to **DBI Multilingual** (override with `--app-name`). |

---

## Supported Languages (35)

- **Default:** `en` (English US)
- **Built-in original:** `ru` (Russian / Русский)
- **23 additional `DBIPatcher` translations:** `engb`, `de`, `fr`, `frca`, `es`, `es419`, `it`, `pt`, `ptbr`, `nl`, `pl`, `tr`, `ua`, `be`, `kk`, `et`, `lt`, `lv`, `id`, `jp`, `kr`, `zhcn`, `zhtw`
- **10 added world languages** (in [`extra-translations/`](extra-translations/)):
  - `ar` — العربية (Arabic)
  - `hi` — हिन्दी (Hindi)
  - `bn` — বাংলা (Bengali)
  - `vi` — Tiếng Việt (Vietnamese)
  - `th` — ไทย (Thai)
  - `tl` — Filipino (Tagalog)
  - `ms` — Bahasa Melayu (Malay)
  - `el` — Ελληνικά (Greek)
  - `cs` — Čeština (Czech)
  - `sv` — Svenska (Swedish)

---

## Verification & Credits

- Every hook and code cave is verified offline using Capstone disassembly and Unicorn ARM64 CPU emulation (`python3 dbi_patcher.py --verify`) with zero networking.
- Built on top of the DBI 921 translation framework and upstream translations from [rashevskyv/DBIPatcher](https://github.com/rashevskyv/DBIPatcher) (release `921`).
