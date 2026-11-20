#!/usr/bin/env python3
"""
DBI 921 Single-File Privacy, Consent & YAML Multi-Language Patcher
==================================================================

Self-contained Python patcher for translated DBI 921 (rashevskyv/DBIPatcher build,
SHA-256: 816db30d9ccc88e3a1cdc6e294ae71ba92b101628437ecddc94d9168fb1aa319).

Contains:
  1. Documented PATCH_GROUPS registry describing every binary modification.
  2. Minimal ARM64 assembler + NRO patching engine (zero external build tools).
  3. YAML catalog generator (`languages.yaml`, default `selected_language: en`,
     35 languages: 24 DBIPatcher languages + Russian original + 10 extra world
     languages), per-language YAML dictionary exporter, and `DBITRNS` v3 compiler.
  4. Offline Unicorn ARM64 CPU verification suite (`--verify`, zero networking).

Usage:
  /opt/homebrew/bin/python3 dbi_patcher.py --verify
  /opt/homebrew/bin/python3 dbi_patcher.py --input path/to/DBI.nro --output-dir dbi-output
  /opt/homebrew/bin/python3 dbi_patcher.py --rebuild-translations --output-dir dbi-output
  /opt/homebrew/bin/python3 dbi_patcher.py --list-patches
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import shutil
import struct
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


# =============================================================================
# 1. CONSTANTS & DOCUMENTED PATCH REGISTRY
# =============================================================================

EXPECTED_BASE_921_SHA256 = (
    "816db30d9ccc88e3a1cdc6e294ae71ba92b101628437ecddc94d9168fb1aa319"
)
UPSTREAM_NRO_URL = (
    "https://github.com/rashevskyv/DBIPatcher/releases/download/921/DBI.nro"
)
UPSTREAM_CSV_URL_TMPL = (
    "https://raw.githubusercontent.com/rashevskyv/DBIPatcher/921/translations/{code}.csv"
)

# --- Verified DBI 921 NRO layout & symbol addresses ---
NRO_IMAGE_SIZE_OFF   = 0x18       # u32 image_size (0xfd5000)
NRO_BSS_SIZE_OFF     = 0x38       # u32 bss_size (0x29f000 -> 0x2a3000)
NRO_MOD0_PTR_OFF     = 0x04       # u32 mod0_offset (0xf0); mod0+12 = rel bss_end

OLD_BSS_SIZE         = 0x29F000
BSS_GROWTH           = 0x4000     # +16 KiB dedicated boot-zeroed BSS
NEW_BSS_BASE         = 0x1274000  # 0x1274000..0x1277fff (above DBIPatcher 0x1273dc0..0x1273fff)

# Dedicated BSS layout inside [0x1274000, 0x1278000):
BSS_DEVICEID_STATE   = NEW_BSS_BASE + 0x0000  # u64: ALLOW / BLOCK / 0
BSS_YAML_STR         = NEW_BSS_BASE + 0x0010  # 32B std::string for languages.yaml
BSS_LANG_COUNT       = NEW_BSS_BASE + 0x0040  # u32: number of parsed languages (max 64)
BSS_ACTIVE_IDX       = NEW_BSS_BASE + 0x0044  # i32: index matching selected_language (-1 if none)
BSS_SEL_VAL_OFF      = NEW_BSS_BASE + 0x0048  # u32: byte offset of selected_language value in yaml
BSS_SEL_VAL_LEN      = NEW_BSS_BASE + 0x004C  # u32: byte length of selected_language value in yaml
BSS_SEL_CODE         = NEW_BSS_BASE + 0x0050  # char[16]: NUL-terminated active code
BSS_LANG_TABLE       = NEW_BSS_BASE + 0x0100  # 64 * 0xC0 (12 KiB): {code[16], name[48], file[128]}
LANG_ENTRY_SIZE      = 0xC0                   # 192 bytes per entry (max 64 entries = 0x3000B)
LANG_MAX_ENTRIES     = 64
LANG_OFF_CODE        = 0x00                   # char[16]
LANG_OFF_NAME        = 0x10                   # char[48]
LANG_OFF_FILE        = 0x40                   # char[128]
BSS_POPUP_BUF        = NEW_BSS_BASE + 0x3100  # char[2048]: formatted Language picker modal text

# Existing DBIPatcher BSS state (DO NOT overlap; reset only during live language hot-reload):
DBIPATCHER_STATE     = 0x1273DC0  # +0 lock(u32), +4 retry(u32), +8 ready(u64), +10 magic(u64), +18 ptr(u64)
DBIPATCHER_PERSIST   = 0x1273DE0  # 32B std::string holding active translation.bin bytes
DBIPATCHER_FALLBACK_PATH = 0x94FD5C  # "sdmc:/switch/DBI/translation.bin" (len 0x20)

# Verified free zeroed code caves in DBI 921:
CAVE1_ADDR           = 0x950D00   # Dead libde265 tail (0x950c9c..0x9511b4, 1,304B zeroed)
CAVE1_END            = 0x9511B4
CAVE2_ADDR           = 0xBE1100   # .text zero tail (0xbe10bc..0xbe2000, 3,840B zeroed)
CAVE2_END            = 0xBE2000

# Verified DBI 921 hook sites & functions:
SERIAL_SNOOP_HOOK    = 0x16C814   # Inside get_console_serial (0x16c670), right after setsysExit()
SERIAL_EPILOGUE      = 0x16CCBC   # Clean epilogue of get_console_serial
AUTH_SERIAL_HOOK     = 0x09F6A0   # Inside build_deviceid_auth (0x9f660), right after adrp x23,#0xc0c000
AUTH_AFTER_SERIAL    = 0x09F7F0   # Immediately before splGetConfig(8, &device_id)

DEVICEID_HOOK        = 0x378F2C   # Sole HTTP WWW-Authenticate: DeviceID retry trigger
DEVICEID_RETRY_ADDR  = 0x378400   # Original ALLOW / retry path
DEVICEID_BLOCK_ADDR  = 0x3787F8   # Normal non-retry error fallthrough (BLOCK)

ENSURE_LOADED_FN     = 0x950078   # DBIPatcher ensure_loaded()
ENSURE_LOADED_READ   = 0x9500E0   # bl #0x147ae0 inside ensure_loaded()
READ_FILE_RAW_FN     = 0x950564   # Unhooked original read_file_to_string(len, path, sret out)

MAIN_MENU_ADD_HOOK   = 0x50DBB4   # bl #0x513e10 adding "DBI Settings" to MainMenu
MAIN_MENU_ADD_FN     = 0x513E10   # MainMenu::add_item(MainMenu*, unique_ptr<MenuItem>*)
MENU_ITEM_CTOR_FN    = 0x4EEB90   # MenuItem::MenuItem(this, std::string* label, std::function* cb, style*)
STD_FUNC_MGR_FN      = 0x4F8EB0   # Trivial captureless std::function manager
STD_FUNC_DTOR_FN     = 0x0AA390   # std::function::~function
STD_STR_DTOR_FN      = 0x75538C   # std::string::~string
UPTR_MENU_DTOR_FN    = 0x47D130   # unique_ptr<MenuItem>::~unique_ptr
OP_NEW_FN            = 0xB4DB00   # operator new(size_t)

GET_WIN_FN           = 0x679090   # Window** get_current_window()
SHOW_POPUP_FN        = 0x67EFB0   # Window::show_popup(win, &msg, &ansi_color, wait_key, sret &ev)
REPAINT_WIN_FN       = 0x67CCE0   # repaint_window(win, 1)
CHECK_BTN_FN         = 0x1B5830   # bool InputEvent::is_button_pressed(&ev, u64 mask)

FOPEN_FN             = 0xBB6160   # FILE* fopen(path, mode)
FWRITE_FN            = 0xBC3F20   # size_t fwrite(ptr, size, nmemb, FILE*)
FCLOSE_FN            = 0xBD0800   # int fclose(FILE*)
STRLEN_FN            = 0xBC2680   # size_t strlen(const char*)

# Session decision sentinels for DeviceID popup:
ALLOW_SENTINEL       = 0xD1B1A1105A110001
BLOCK_SENTINEL       = 0xD1B1B10C5B10C002

# HidNpadButton masks:
BTN_A                = 0x00001
BTN_B                = 0x00002
BTN_L                = 0x00040
BTN_R                = 0x00080
BTN_PLUS             = 0x00400
BTN_UP               = 0x22000    # DPad Up (0x2000) | StickL Up (0x20000)
BTN_DOWN             = 0x88000    # DPad Down (0x8000) | StickL Down (0x80000)

DEFAULT_APP_NAME     = "DBI Multilingual"
NACP_TITLE_SLOTS     = 16         # 16 language slots x 0x300 bytes (0x200 title + 0x100 author)
NACP_ENTRY_SIZE      = 0x300
NACP_TITLE_MAX       = 0x200

LANG_PAGE_SIZE       = 12         # 12 languages per page (35 langs = 3 crisp pages)


@dataclass(frozen=True)
class PatchSpec:
    """Single documented binary patch item."""
    name: str
    offset: int
    comment: str


@dataclass(frozen=True)
class PatchGroup:
    """Logical group of related binary patches with human-readable documentation."""
    group_id: str
    title: str
    summary: str
    patches: tuple[PatchSpec, ...]


# Declarative, human-readable catalog of every patch applied to DBI 921.
# Note: Hardcoded Switch serial numbers originally obfuscated in DBI 921 are
# intentionally redacted below (only the 4-char prefix + SHA-256 of the hidden
# last 71% are shown).
PATCH_GROUPS: tuple[PatchGroup, ...] = (
    PatchGroup(
        group_id="1_bss_expansion",
        title="Group 1: Dedicated BSS Expansion (+16 KiB)",
        summary=(
            "Extends the NRO BSS segment by +0x4000 bytes (0x1274000..0x1277fff) so all "
            "runtime state (DeviceID session decision, parsed YAML language table, and "
            "formatted UI popup buffer) lives in guaranteed boot-zeroed memory with zero "
            "overlap against DBI globals, TLS, or DBIPatcher's 0x1273dc0..0x1273fff state."
        ),
        patches=(
            PatchSpec(
                name="nro_bss_size",
                offset=NRO_BSS_SIZE_OFF,
                comment="Bump NRO header bss_size from 0x29f000 to 0x2a3000 (+0x4000).",
            ),
            PatchSpec(
                name="mod0_bss_end",
                offset=0xFC,
                comment="Bump MOD0.bss_end relative offset by +0x4000 (0x1274000 -> 0x1278000).",
            ),
        ),
    ),
    PatchGroup(
        group_id="2_serial_privacy",
        title="Group 2: Serial Privacy & Hardcoded-Serial Removal",
        summary=(
            "Stops DBI from bypassing Exosphere/Incognito serial blanking via SD PRODINFO "
            "backups, and removes DBI's obfuscated hardcoded-serial special cases "
            "(redacted: XAJ7********** [tail SHA-256: 5cb63abbe2f4c61c] and "
            "XAJ7********** [tail SHA-256: e6b0f1fa9683e078]; raw serials hidden)."
        ),
        patches=(
            PatchSpec(
                name="disable_prodinfo_snoop_and_serial_swap",
                offset=SERIAL_SNOOP_HOOK,
                comment=(
                    "In get_console_serial (0x16c670), branch directly to clean epilogue "
                    "0x16ccbc right after setsysExit(): disables scanning "
                    "/atmosphere/automatic_backups/*PRODINFO* and skips the obfuscated "
                    "hardcoded serial substitution (0x16cc20 -> 0x16cd98, redacted)."
                ),
            ),
            PatchSpec(
                name="disable_auth_hardcoded_serial_check",
                offset=AUTH_SERIAL_HOOK,
                comment=(
                    "In build_deviceid_auth (0x9f660), keep adrp x23,#0xc0c000 at 0x9f69c "
                    "and branch directly to 0x9f7f0: skips the obfuscated hardcoded serial "
                    "check (0x9f70c, redacted) and its replacement path (0x9faa8/0x9fad4)."
                ),
            ),
            PatchSpec(
                name="scrub_dead_serial_immediates",
                offset=0x09F6A4,
                comment=(
                    "Overwrite unreachable inline-immediate serial decryptor loads with NOPs "
                    "at 0x9f6a4..0x9f6c0, 0x9fad8..0x9faf4, 0x16cbb8..0x16cbd0, and "
                    "0x16cd2c..0x16cd48 so the dead obfuscated serial halves are wiped."
                ),
            ),
        ),
    ),
    PatchGroup(
        group_id="3_deviceid_consent_popup",
        title="Group 3: Interactive DeviceID HTTP Consent Popup",
        summary=(
            "Intercepts the sole HTTP WWW-Authenticate: DeviceID retry trigger so the first "
            "server requesting your Device ID in a session triggers a native red DBI modal "
            "asking to Allow (+) or Block (any other button) for the rest of the session."
        ),
        patches=(
            PatchSpec(
                name="http_deviceid_hook",
                offset=DEVICEID_HOOK,
                comment="Replace `str w21, [sp, #0x70]` with `b #0x950d00` into Code Cave 1.",
            ),
            PatchSpec(
                name="deviceid_popup_handler",
                offset=CAVE1_ADDR,
                comment=(
                    "Code Cave 1 (dead libde265 tail): checks BSS 0x1274000 sentinel; on "
                    "first trigger shows native red Window::show_popup modal, caches ALLOW "
                    "or BLOCK for the session, fails closed to BLOCK if Window* is NULL."
                ),
            ),
        ),
    ),
    PatchGroup(
        group_id="4_yaml_language_loader",
        title="Group 4: YAML Startup Language Loader",
        summary=(
            "Replaces DBIPatcher's hardcoded translation.bin read with a YAML-aware loader "
            "that reads sdmc:/switch/DBI/languages.yaml, resolves `selected_language` "
            "(default `en`), loads its compiled DBITRNS v3 table (or native Russian for "
            "`ru`), and falls back cleanly to translation.bin if languages.yaml is absent."
        ),
        patches=(
            PatchSpec(
                name="dbipatcher_read_hook",
                offset=ENSURE_LOADED_READ,
                comment="Redirect `bl #0x147ae0` inside ensure_loaded() to yaml_startup_loader.",
            ),
            PatchSpec(
                name="yaml_loader_and_parser",
                offset=CAVE2_ADDR,
                comment=(
                    "Code Cave 2 (.text zero tail 0xbe1100+): lightweight YAML parser and "
                    "startup loader using unhooked read_file_to_string (0x950564)."
                ),
            ),
        ),
    ),
    PatchGroup(
        group_id="5_main_menu_language_button",
        title="Group 5: Main Menu 'Language' Button & Live YAML Switcher",
        summary=(
            "Adds a native 'Language' button to DBI's Main Menu (right below 'DBI Settings' "
            "and above 'Exit') that reads all languages from languages.yaml, displays an "
            "interactive paged selector, rewrites `selected_language:` in languages.yaml "
            "in place when changed, and hot-reloads DBIPatcher's active translation table."
        ),
        patches=(
            PatchSpec(
                name="main_menu_settings_hook",
                offset=MAIN_MENU_ADD_HOOK,
                comment=(
                    "Redirect `bl #0x513e10` (adding 'DBI Settings') to main_menu_hook in "
                    "Code Cave 2, which adds 'DBI Settings' and then appends 'Language'."
                ),
            ),
            PatchSpec(
                name="language_picker_ui_and_writer",
                offset=CAVE2_ADDR,
                comment=(
                    "Inside Code Cave 2: paged modal (12/page, Up/Down/L/R/A/B), 3-part "
                    "fopen('wb')/fwrite/fclose updater preserving all YAML comments, and "
                    "live DBIPatcher state reset + reload via ensure_loaded (0x950078)."
                ),
            ),
        ),
    ),
    PatchGroup(
        group_id="6_nacp_metadata",
        title="Group 6: Homebrew Menu App Name (NACP Metadata)",
        summary=(
            "Updates the NRO ASET/NACP application title across all language slots "
            "so Homebrew Menu clearly displays 'DBI Multilingual' instead of stock 'DBI'."
        ),
        patches=(
            PatchSpec(
                name="nacp_app_title",
                offset=0xFD719D,
                comment="Set all 16 NACP title entries (0x200 bytes each) to 'DBI Multilingual'.",
            ),
        ),
    ),
)


# Complete 35-language catalog:
#   - English (US) default (`selected_language: en`)
#   - Original Russian built-in (`ru`, `file: ""`)
#   - All 23 remaining existing DBIPatcher languages
#   - 10 most common additional world languages (ar, hi, bn, vi, th, tl, ms, el, cs, sv)
LANGUAGES: list[tuple[str, str, str]] = [
    # (code, display_name_in_menu, source_kind)
    # Note: display names are kept concise (<= 38 UTF-8 bytes) for crisp DBI menu rendering.
    ("en",    "English (US)",            "existing"),
    ("ru",    "Russian / Русский (Orig)", "builtin"),
    ("engb",  "English (UK)",            "existing"),
    ("de",    "Deutsch (German)",        "existing"),
    ("fr",    "Français (French)",       "existing"),
    ("frca",  "Français (Canada)",       "existing"),
    ("es",    "Español (Spanish)",       "existing"),
    ("es419", "Español (LatAm)",         "existing"),
    ("it",    "Italiano (Italian)",      "existing"),
    ("pt",    "Português (Portugal)",    "existing"),
    ("ptbr",  "Português (Brasil)",      "existing"),
    ("nl",    "Nederlands (Dutch)",      "existing"),
    ("pl",    "Polski (Polish)",         "existing"),
    ("tr",    "Türkçe (Turkish)",        "existing"),
    ("ua",    "Українська (Ukrainian)",  "existing"),
    ("be",    "Беларуская (Belarusian)", "existing"),
    ("kk",    "Қазақша (Kazakh)",        "existing"),
    ("et",    "Eesti (Estonian)",        "existing"),
    ("lt",    "Lietuvių (Lithuanian)",   "existing"),
    ("lv",    "Latviešu (Latvian)",      "existing"),
    ("id",    "Bahasa Indonesia",        "existing"),
    ("jp",    "日本語 (Japanese)",        "existing"),
    ("kr",    "한국어 (Korean)",          "existing"),
    ("zhcn",  "简体中文 (Chinese Simp)",  "existing"),
    ("zhtw",  "繁體中文 (Chinese Trad)",  "existing"),
    # --- 10 most common additional world languages ---
    ("ar",    "العربية (Arabic)",        "extra"),
    ("hi",    "हिन्दी (Hindi)",           "extra"),
    ("bn",    "বাংলা (Bengali)",         "extra"),
    ("vi",    "Tiếng Việt (Vietnamese)", "extra"),
    ("th",    "ไทย (Thai)",              "extra"),
    ("tl",    "Filipino (Tagalog)",      "extra"),
    ("ms",    "Bahasa Melayu (Malay)",   "extra"),
    ("el",    "Ελληνικά (Greek)",        "extra"),
    ("cs",    "Čeština (Czech)",         "extra"),
    ("sv",    "Svenska (Swedish)",       "extra"),
]

# Verify display names fit cleanly inside our 48-byte BSS name slot
for _c, _n, _k in LANGUAGES:
    assert len(_c.encode("utf-8")) <= 15, f"Code too long: {_c}"
    assert len(_n.encode("utf-8")) <= 47, f"Name too long ({len(_n.encode())}): {_n}"


# =============================================================================
# 2. MINIMAL ARM64 ASSEMBLER (ZERO EXTERNAL TOOLCHAIN REQUIRED)
# =============================================================================

NOP = 0xD503201F
RET = 0xD65F03C0

COND_EQ = 0x0
COND_NE = 0x1
COND_HS = 0x2  # unsigned >=
COND_LO = 0x3  # unsigned <
COND_HI = 0x8  # unsigned >
COND_LS = 0x9  # unsigned <=
COND_GE = 0xA  # signed >=
COND_LT = 0xB  # signed <
COND_GT = 0xC  # signed >
COND_LE = 0xD  # signed <=


def enc_b(pc: int, target: int) -> int:
    delta = target - pc
    assert delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27), f"b out of range: {delta}"
    return 0x14000000 | ((delta >> 2) & 0x03FFFFFF)


def enc_bl(pc: int, target: int) -> int:
    delta = target - pc
    assert delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27), f"bl out of range: {delta}"
    return 0x94000000 | ((delta >> 2) & 0x03FFFFFF)


def enc_b_cond(cond: int, delta: int) -> int:
    assert delta % 4 == 0 and -(1 << 20) <= delta < (1 << 20), f"b.cond out of range: {delta}"
    return 0x54000000 | (((delta >> 2) & 0x7FFFF) << 5) | (cond & 0xF)


def enc_cbz(rt: int, delta: int, is64: bool = True) -> int:
    assert delta % 4 == 0 and -(1 << 20) <= delta < (1 << 20), f"cbz out of range: {delta}"
    sf = 1 if is64 else 0
    return (sf << 31) | 0x34000000 | (((delta >> 2) & 0x7FFFF) << 5) | rt


def enc_cbnz(rt: int, delta: int, is64: bool = True) -> int:
    assert delta % 4 == 0 and -(1 << 20) <= delta < (1 << 20), f"cbnz out of range: {delta}"
    sf = 1 if is64 else 0
    return (sf << 31) | 0x35000000 | (((delta >> 2) & 0x7FFFF) << 5) | rt


def enc_adrp(pc: int, rd: int, target_page: int) -> int:
    assert (target_page & 0xFFF) == 0
    diff = (target_page >> 12) - (pc >> 12)
    imm21 = diff & 0x1FFFFF
    return 0x90000000 | ((imm21 & 3) << 29) | (((imm21 >> 2) & 0x7FFFF) << 5) | rd


def enc_adr(pc: int, rd: int, target: int) -> int:
    delta = target - pc
    assert -(1 << 20) <= delta < (1 << 20), f"adr out of range: {delta}"
    imm21 = delta & 0x1FFFFF
    return 0x10000000 | ((imm21 & 3) << 29) | (((imm21 >> 2) & 0x7FFFF) << 5) | rd


def enc_add_imm(rd: int, rn: int, imm12: int, is64: bool = True, shift12: bool = False) -> int:
    assert 0 <= imm12 <= 0xFFF
    sf = 1 if is64 else 0
    sh = 1 if shift12 else 0
    return (sf << 31) | 0x11000000 | (sh << 22) | (imm12 << 10) | (rn << 5) | rd


def enc_sub_imm(rd: int, rn: int, imm12: int, is64: bool = True, shift12: bool = False) -> int:
    assert 0 <= imm12 <= 0xFFF
    sf = 1 if is64 else 0
    sh = 1 if shift12 else 0
    return (sf << 31) | 0x51000000 | (sh << 22) | (imm12 << 10) | (rn << 5) | rd


def enc_cmp_imm(rn: int, imm12: int, is64: bool = True) -> int:
    assert 0 <= imm12 <= 0xFFF
    sf = 1 if is64 else 0
    return (sf << 31) | 0x7100001F | (imm12 << 10) | (rn << 5)


def enc_add_reg(rd: int, rn: int, rm: int, is64: bool = True) -> int:
    sf = 1 if is64 else 0
    return (sf << 31) | 0x0B000000 | (rm << 16) | (rn << 5) | rd


def enc_sub_reg(rd: int, rn: int, rm: int, is64: bool = True) -> int:
    sf = 1 if is64 else 0
    return (sf << 31) | 0x4B000000 | (rm << 16) | (rn << 5) | rd


def enc_cmp_reg(rn: int, rm: int, is64: bool = True) -> int:
    sf = 1 if is64 else 0
    return (sf << 31) | 0x6B00001F | (rm << 16) | (rn << 5)


def enc_mov_reg(rd: int, rm: int, is64: bool = True) -> int:
    sf = 1 if is64 else 0
    return (sf << 31) | 0x2A0003E0 | (rm << 16) | rd


def enc_movz(rd: int, imm16: int, hw: int = 0, is64: bool = True) -> int:
    sf = 1 if is64 else 0
    return (sf << 31) | 0x52800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | rd


def enc_movk(rd: int, imm16: int, hw: int = 0, is64: bool = True) -> int:
    sf = 1 if is64 else 0
    return (sf << 31) | 0x72800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | rd


def enc_movn(rd: int, imm16: int, hw: int = 0, is64: bool = True) -> int:
    sf = 1 if is64 else 0
    return (sf << 31) | 0x12800000 | (hw << 21) | ((imm16 & 0xFFFF) << 5) | rd


def enc_mov_imm64(rd: int, val: int) -> list[int]:
    return [
        enc_movz(rd, (val >> 0) & 0xFFFF, 0, True),
        enc_movk(rd, (val >> 16) & 0xFFFF, 1, True),
        enc_movk(rd, (val >> 32) & 0xFFFF, 2, True),
        enc_movk(rd, (val >> 48) & 0xFFFF, 3, True),
    ]


def enc_mul(rd: int, rn: int, rm: int, is64: bool = True) -> int:
    sf = 1 if is64 else 0
    return (sf << 31) | 0x1B007C00 | (rm << 16) | (rn << 5) | rd


def enc_udiv(rd: int, rn: int, rm: int, is64: bool = True) -> int:
    sf = 1 if is64 else 0
    return (sf << 31) | 0x1AC00800 | (rm << 16) | (rn << 5) | rd


def enc_msub(rd: int, rn: int, rm: int, ra: int, is64: bool = True) -> int:
    sf = 1 if is64 else 0
    return (sf << 31) | 0x1B008000 | (rm << 16) | (ra << 10) | (rn << 5) | rd


def enc_ldr_uimm(rt: int, rn: int, byte_off: int = 0, is64: bool = True) -> int:
    scale = 8 if is64 else 4
    assert byte_off % scale == 0 and 0 <= byte_off // scale <= 0xFFF
    base = 0xF9400000 if is64 else 0xB9400000
    return base | ((byte_off // scale) << 10) | (rn << 5) | rt


def enc_ldrsw_uimm(rt: int, rn: int, byte_off: int = 0) -> int:
    assert byte_off % 4 == 0 and 0 <= byte_off // 4 <= 0xFFF
    return 0xB9800000 | ((byte_off // 4) << 10) | (rn << 5) | rt


def enc_str_uimm(rt: int, rn: int, byte_off: int = 0, is64: bool = True) -> int:
    scale = 8 if is64 else 4
    assert byte_off % scale == 0 and 0 <= byte_off // scale <= 0xFFF
    base = 0xF9000000 if is64 else 0xB9000000
    return base | ((byte_off // scale) << 10) | (rn << 5) | rt


def enc_ldrb_uimm(rt: int, rn: int, byte_off: int = 0) -> int:
    assert 0 <= byte_off <= 0xFFF
    return 0x39400000 | (byte_off << 10) | (rn << 5) | rt


def enc_strb_uimm(rt: int, rn: int, byte_off: int = 0) -> int:
    assert 0 <= byte_off <= 0xFFF
    return 0x39000000 | (byte_off << 10) | (rn << 5) | rt


def enc_ldrb_reg(rt: int, rn: int, rm: int) -> int:
    return 0x38606800 | (rm << 16) | (rn << 5) | rt


def enc_strb_reg(rt: int, rn: int, rm: int) -> int:
    return 0x38206800 | (rm << 16) | (rn << 5) | rt


def enc_ldrb_post(rt: int, rn: int, simm9: int = 1) -> int:
    return 0x38400400 | ((simm9 & 0x1FF) << 12) | (rn << 5) | rt


def enc_strb_post(rt: int, rn: int, simm9: int = 1) -> int:
    return 0x38000400 | ((simm9 & 0x1FF) << 12) | (rn << 5) | rt


def enc_stp(rt1: int, rt2: int, rn: int, byte_off: int = 0, mode: str = "off") -> int:
    assert byte_off % 8 == 0 and -512 <= byte_off <= 504
    imm7 = (byte_off // 8) & 0x7F
    op = {"off": 0xA9000000, "pre": 0xA9800000, "post": 0xA8800000}[mode]
    return op | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1


def enc_ldp(rt1: int, rt2: int, rn: int, byte_off: int = 0, mode: str = "off") -> int:
    assert byte_off % 8 == 0 and -512 <= byte_off <= 504
    imm7 = (byte_off // 8) & 0x7F
    op = {"off": 0xA9400000, "pre": 0xA9C00000, "post": 0xA8C00000}[mode]
    return op | (imm7 << 15) | (rt2 << 10) | (rn << 5) | rt1


class Asm:
    """Two-pass ARM64 mini-assembler with labels and embedded 4-byte-aligned string pool."""

    def __init__(self, base_pc: int):
        self.base_pc = base_pc
        self._ops: list[tuple[str, object]] = []
        self._strings: list[tuple[str, bytes]] = []

    def label(self, name: str) -> None:
        self._ops.append(("label", name))

    def emit(self, word_or_fn: int | Callable[[int, dict[str, int]], int]) -> None:
        self._ops.append(("insn", word_or_fn))

    def emit_many(self, words: list[int]) -> None:
        for w in words:
            self.emit(w)

    def data_str(self, name: str, raw: bytes) -> None:
        self._strings.append((name, raw))

    def b(self, target: str | int) -> None:
        if isinstance(target, int):
            self.emit(lambda pc, _: enc_b(pc, target))
        else:
            self.emit(lambda pc, L: enc_b(pc, L[target]))

    def bl(self, target: str | int) -> None:
        if isinstance(target, int):
            self.emit(lambda pc, _: enc_bl(pc, target))
        else:
            self.emit(lambda pc, L: enc_bl(pc, L[target]))

    def b_cond(self, cond: int, target: str) -> None:
        self.emit(lambda pc, L: enc_b_cond(cond, L[target] - pc))

    def cbz(self, rt: int, target: str, is64: bool = True) -> None:
        self.emit(lambda pc, L: enc_cbz(rt, L[target] - pc, is64))

    def cbnz(self, rt: int, target: str, is64: bool = True) -> None:
        self.emit(lambda pc, L: enc_cbnz(rt, L[target] - pc, is64))

    def adr(self, rd: int, target: str) -> None:
        self.emit(lambda pc, L: enc_adr(pc, rd, L[target]))

    def adrp_add(self, rd: int, addr: int) -> None:
        page = addr & ~0xFFF
        off = addr & 0xFFF
        self.emit(lambda pc, _: enc_adrp(pc, rd, page))
        if off:
            self.emit(enc_add_imm(rd, rd, off, True))

    def build(self, max_end: int) -> tuple[bytes, int, dict[str, int]]:
        # Pass 1: resolve all code + data labels
        labels: dict[str, int] = {}
        pc = self.base_pc
        for kind, val in self._ops:
            if kind == "label":
                assert val not in labels, f"Duplicate label: {val}"
                labels[str(val)] = pc
            else:
                pc += 4
        code_end = pc
        data_blob = bytearray()
        for name, raw in self._strings:
            assert name not in labels, f"Duplicate data label: {name}"
            labels[name] = code_end + len(data_blob)
            padded = raw + b"\x00"
            padded += b"\x00" * ((-len(padded)) & 3)
            data_blob.extend(padded)

        # Pass 2: encode all instructions
        words: list[int] = []
        pc = self.base_pc
        for kind, val in self._ops:
            if kind == "insn":
                w = val(pc, labels) if callable(val) else int(val)
                words.append(w)
                pc += 4
        raw = b"".join(struct.pack("<I", w) for w in words) + bytes(data_blob)
        assert self.base_pc + len(raw) <= max_end, (
            f"Code cave overflow at {self.base_pc:#x}: {len(raw)} > {max_end - self.base_pc}"
        )
        return raw, len(words) * 4, labels


# =============================================================================
# 3. CODE CAVE 1: INTERACTIVE DeviceID HTTP CONSENT POPUP (0x950d00)
# =============================================================================

DEVICEID_PROMPT_MSG = (
    b"Server is asking for your Device ID.\n\n"
    b"(+) - Allow for this session\n"
    b"Any other button - Block for this session"
)
ANSI_RED_BOX = b"\x1b[41;1m"
ANSI_BLUE_BOX = b"\x1b[44;1m"


def build_cave1_deviceid_popup() -> tuple[bytes, int, dict[str, int]]:
    """Assemble Group 3: first-time Allow/Block session modal at 0x950d00."""
    a = Asm(CAVE1_ADDR)

    # 1. Check 64-bit cached session decision at BSS_DEVICEID_STATE (0x1274000)
    a.adrp_add(9, BSS_DEVICEID_STATE)
    a.emit(enc_ldr_uimm(10, 9, 0, True))

    a.emit_many(enc_mov_imm64(11, ALLOW_SENTINEL))
    a.emit(enc_cmp_reg(10, 11, True))
    a.b_cond(COND_EQ, "do_allow")

    a.emit_many(enc_mov_imm64(12, BLOCK_SENTINEL))
    a.emit(enc_cmp_reg(10, 12, True))
    a.b_cond(COND_EQ, "do_block")

    # 2. First time in session: open stack frame (0xc0 bytes), save x29/x30
    #   [sp+0x00]: saved x29, x30
    #   [sp+0x10]: msg std::string (32B)
    #   [sp+0x30]: color std::string (32B)
    #   [sp+0x50]: InputEvent sret buffer (0x40B)
    a.emit(enc_sub_imm(31, 31, 0xC0, True))
    a.emit(enc_stp(29, 30, 31, 0))

    # Fetch Window* via 0x679090; fail closed to BLOCK if NULL
    a.bl(GET_WIN_FN)
    a.cbz(0, "fail_close", True)
    a.emit(enc_ldr_uimm(0, 0, 0, True))
    a.cbz(0, "fail_close", True)

    # Construct msg std::string at [sp+0x10]
    a.adr(1, "msg_str")
    a.emit(enc_movz(2, len(DEVICEID_PROMPT_MSG), 0, True))
    a.emit(enc_stp(1, 2, 31, 0x10))
    a.emit(enc_stp(2, 31, 31, 0x20))

    # Construct red ANSI style std::string at [sp+0x30]
    a.adr(1, "color_str")
    a.emit(enc_movz(2, len(ANSI_RED_BOX), 0, True))
    a.emit(enc_stp(1, 2, 31, 0x30))
    a.emit(enc_stp(2, 31, 31, 0x40))

    # Zero InputEvent buffer [sp+0x50..0x8f]
    for off in (0x50, 0x60, 0x70, 0x80):
        a.emit(enc_stp(31, 31, 31, off))

    # Window::show_popup(win=x0, &msg, &color, wait=1, sret &ev)
    a.emit(enc_add_imm(1, 31, 0x10, True))
    a.emit(enc_add_imm(2, 31, 0x30, True))
    a.emit(enc_movz(3, 1, 0, False))
    a.emit(enc_add_imm(8, 31, 0x50, True))
    a.bl(SHOW_POPUP_FN)

    # Repaint parent window
    a.bl(GET_WIN_FN)
    a.cbz(0, "skip_repaint", True)
    a.emit(enc_ldr_uimm(0, 0, 0, True))
    a.cbz(0, "skip_repaint", True)
    a.emit(enc_movz(1, 1, 0, False))
    a.bl(REPAINT_WIN_FN)

    a.label("skip_repaint")
    # Check if (+) (0x400) was pressed
    a.emit(enc_add_imm(0, 31, 0x50, True))
    a.emit(enc_movz(1, BTN_PLUS, 0, True))
    a.bl(CHECK_BTN_FN)
    a.adrp_add(9, BSS_DEVICEID_STATE)
    a.cbnz(0, "store_allow", False)

    # Fail-closed or non-(+) button -> store BLOCK sentinel and skip retry
    a.label("fail_close")
    a.adrp_add(9, BSS_DEVICEID_STATE)
    a.emit_many(enc_mov_imm64(10, BLOCK_SENTINEL))
    a.emit(enc_str_uimm(10, 9, 0, True))
    a.emit(enc_ldp(29, 30, 31, 0))
    a.emit(enc_add_imm(31, 31, 0xC0, True))
    a.b("do_block")

    # (+) pressed -> store ALLOW sentinel and proceed with original retry
    a.label("store_allow")
    a.emit_many(enc_mov_imm64(10, ALLOW_SENTINEL))
    a.emit(enc_str_uimm(10, 9, 0, True))
    a.emit(enc_ldp(29, 30, 31, 0))
    a.emit(enc_add_imm(31, 31, 0xC0, True))

    a.label("do_allow")
    a.emit(enc_str_uimm(21, 31, 0x70, False))  # Original 0x378f2c: str w21, [sp, #0x70]
    a.emit(enc_str_uimm(31, 31, 0x90, True))   # Original 0x378f30: str xzr, [sp, #0x90]
    a.b(DEVICEID_RETRY_ADDR)

    a.label("do_block")
    a.b(DEVICEID_BLOCK_ADDR)

    a.data_str("msg_str", DEVICEID_PROMPT_MSG)
    a.data_str("color_str", ANSI_RED_BOX)
    return a.build(CAVE1_END)


# =============================================================================
# 4. CODE CAVE 2: YAML PARSER, STARTUP LOADER & MAIN MENU LANGUAGE PICKER
# =============================================================================

YAML_PATH_BYTES = b"sdmc:/switch/DBI/languages.yaml"
MENU_LABEL_BYTES = b"Language"
PICKER_HDR_1 = b"Select Language (Page "
PICKER_HDR_2 = b"\nActive: "
PICKER_FOOTER = b"\nUp/Down: Move | L/R: Page | A: Apply | B: Cancel"
PICKER_MISSING = (
    b"languages.yaml not found.\n\n"
    b"Copy languages.yaml to:\nsdmc:/switch/DBI/languages.yaml"
)
PICKER_APPLIED = (
    b"Language saved to languages.yaml!\n\n"
    b"New language is now active.\n"
    b"Press any button to continue."
)


def build_cave2_yaml_and_menu() -> tuple[bytes, int, dict[str, int]]:
    """Assemble Groups 4 & 5 into Code Cave 2 (0xbe1100..0xbe1fff).

    Exported entry points (returned in `labels`):
      - `yaml_startup_loader`: Hook target for 0x9500e0 (DBIPatcher ensure_loaded)
      - `main_menu_add_hook`:  Hook target for 0x50dbb4 (Main Menu after DBI Settings)
      - `language_picker_cb`:  std::function callback for the "Language" Main Menu button
    """
    a = Asm(CAVE2_ADDR)

    # -------------------------------------------------------------------------
    # Helper 1: fn_streq(x0=s1, x1=s2) -> w0 = 1 if equal else 0
    # Clobbers: x2, x3
    # -------------------------------------------------------------------------
    a.label("fn_streq")
    a.emit(enc_ldrb_post(2, 0, 1))
    a.emit(enc_ldrb_post(3, 1, 1))
    a.emit(enc_cmp_reg(2, 3, False))
    a.b_cond(COND_NE, "streq_no")
    a.cbnz(2, "fn_streq", False)
    a.emit(enc_movz(0, 1, 0, False))
    a.emit(RET)
    a.label("streq_no")
    a.emit(enc_movz(0, 0, 0, False))
    a.emit(RET)

    # -------------------------------------------------------------------------
    # Helper 2: fn_startswith(x0=line_ptr, x1=line_end, x2=prefix_cstr) -> x0 = after_prefix or 0
    # Clobbers: x3, x4, x5
    # -------------------------------------------------------------------------
    a.label("fn_startswith")
    a.emit(enc_mov_reg(3, 0, True))
    a.label("sw_loop")
    a.emit(enc_ldrb_post(4, 2, 1))
    a.cbz(4, "sw_match", False)
    a.emit(enc_cmp_reg(3, 1, True))
    a.b_cond(COND_HS, "sw_fail")
    a.emit(enc_ldrb_post(5, 3, 1))
    a.emit(enc_cmp_reg(5, 4, False))
    a.b_cond(COND_NE, "sw_fail")
    a.b("sw_loop")
    a.label("sw_match")
    a.emit(enc_mov_reg(0, 3, True))
    a.emit(RET)
    a.label("sw_fail")
    a.emit(enc_movz(0, 0, 0, True))
    a.emit(RET)

    # -------------------------------------------------------------------------
    # Helper 3: fn_copy_yaml_val(x0=val_start, x1=line_end, x2=dst, x3=max_len, w4=stop_on_space)
    #   Strips leading spaces/tabs and optional matching quotes; strips trailing
    #   spaces/tabs/\r/quotes. Writes NUL-terminated string into dst.
    #   Returns: x0 = trimmed start ptr, x1 = copied len
    # Clobbers: x5, x6, x7, x8
    # -------------------------------------------------------------------------
    a.label("fn_copy_yaml_val")
    # Skip leading ' ' (0x20) and '\t' (0x09)
    a.label("cyv_lskip")
    a.emit(enc_cmp_reg(0, 1, True))
    a.b_cond(COND_HS, "cyv_empty")
    a.emit(enc_ldrb_uimm(5, 0, 0))
    a.emit(enc_cmp_imm(5, 0x20, False))
    a.b_cond(COND_EQ, "cyv_linc")
    a.emit(enc_cmp_imm(5, 0x09, False))
    a.b_cond(COND_NE, "cyv_lquote")
    a.label("cyv_linc")
    a.emit(enc_add_imm(0, 0, 1, True))
    a.b("cyv_lskip")

    # Strip one leading quote '"' (0x22) or "'" (0x27)
    a.label("cyv_lquote")
    a.emit(enc_movz(6, 0, 0, False))  # w6 = quote char (0 if unquoted)
    a.emit(enc_cmp_imm(5, 0x22, False))
    a.b_cond(COND_EQ, "cyv_hasq")
    a.emit(enc_cmp_imm(5, 0x27, False))
    a.b_cond(COND_NE, "cyv_find_end")
    a.label("cyv_hasq")
    a.emit(enc_mov_reg(6, 5, False))
    a.emit(enc_add_imm(0, 0, 1, True))

    # Find end of value (x7 = end ptr)
    a.label("cyv_find_end")
    a.emit(enc_mov_reg(7, 0, True))
    a.label("cyv_eloop")
    a.emit(enc_cmp_reg(7, 1, True))
    a.b_cond(COND_HS, "cyv_trim_r")
    a.emit(enc_ldrb_uimm(5, 7, 0))
    a.emit(enc_cmp_imm(5, 0x0D, False))  # '\r'
    a.b_cond(COND_EQ, "cyv_trim_r")
    a.cbz(6, "cyv_unq_chk", False)
    # Quoted: stop on closing quote
    a.emit(enc_cmp_reg(5, 6, False))
    a.b_cond(COND_EQ, "cyv_copy")
    a.emit(enc_add_imm(7, 7, 1, True))
    a.b("cyv_eloop")

    a.label("cyv_unq_chk")
    # Unquoted: stop on '#' comment; if w4!=0 also stop on ' ' or '\t'
    a.emit(enc_cmp_imm(5, 0x23, False))  # '#'
    a.b_cond(COND_EQ, "cyv_trim_r")
    a.cbz(4, "cyv_enext", False)
    a.emit(enc_cmp_imm(5, 0x20, False))
    a.b_cond(COND_EQ, "cyv_trim_r")
    a.emit(enc_cmp_imm(5, 0x09, False))
    a.b_cond(COND_EQ, "cyv_trim_r")
    a.label("cyv_enext")
    a.emit(enc_add_imm(7, 7, 1, True))
    a.b("cyv_eloop")

    # Trim trailing spaces/tabs for unquoted values
    a.label("cyv_trim_r")
    a.emit(enc_cmp_reg(7, 0, True))
    a.b_cond(COND_LS, "cyv_copy")
    a.emit(enc_sub_imm(8, 7, 1, True))
    a.emit(enc_ldrb_uimm(5, 8, 0))
    a.emit(enc_cmp_imm(5, 0x20, False))
    a.b_cond(COND_EQ, "cyv_tdec")
    a.emit(enc_cmp_imm(5, 0x09, False))
    a.b_cond(COND_NE, "cyv_copy")
    a.label("cyv_tdec")
    a.emit(enc_mov_reg(7, 8, True))
    a.b("cyv_trim_r")

    # Copy min(x7 - x0, x3) bytes from x0 to x2, NUL terminate
    a.label("cyv_copy")
    a.emit(enc_sub_reg(1, 7, 0, True))  # x1 = len
    a.emit(enc_cmp_reg(1, 3, True))
    a.b_cond(COND_LS, "cyv_cloop_init")
    a.emit(enc_mov_reg(1, 3, True))
    a.label("cyv_cloop_init")
    a.emit(enc_movz(8, 0, 0, True))
    a.label("cyv_cloop")
    a.emit(enc_cmp_reg(8, 1, True))
    a.b_cond(COND_HS, "cyv_cdone")
    a.emit(enc_ldrb_reg(5, 0, 8))
    a.emit(enc_strb_reg(5, 2, 8))
    a.emit(enc_add_imm(8, 8, 1, True))
    a.b("cyv_cloop")
    a.label("cyv_cdone")
    a.emit(enc_strb_reg(31, 2, 8))  # NUL terminator
    a.emit(RET)

    a.label("cyv_empty")
    a.emit(enc_strb_uimm(31, 2, 0))
    a.emit(enc_movz(1, 0, 0, True))
    a.emit(RET)

    # -------------------------------------------------------------------------
    # Helper 4: fn_append_cstr(x0=dst, x1=src_cstr) -> x0 = new dst ptr (at NUL)
    # Clobbers: w2
    # -------------------------------------------------------------------------
    a.label("fn_append_cstr")
    a.emit(enc_ldrb_post(2, 1, 1))
    a.cbz(2, "ac_done", False)
    a.emit(enc_strb_post(2, 0, 1))
    a.b("fn_append_cstr")
    a.label("ac_done")
    a.emit(enc_strb_uimm(31, 0, 0))
    a.emit(RET)

    # -------------------------------------------------------------------------
    # Helper 5: fn_append_u32(x0=dst, w1=val [0..99]) -> x0 = new dst ptr
    # Clobbers: w2, w3, w4
    # -------------------------------------------------------------------------
    a.label("fn_append_u32")
    a.emit(enc_movz(2, 10, 0, False))
    a.emit(enc_udiv(3, 1, 2, False))          # w3 = val / 10
    a.emit(enc_msub(4, 3, 2, 1, False))       # w4 = val % 10
    a.cbz(3, "au_ones", False)
    a.emit(enc_add_imm(3, 3, 0x30, False))
    a.emit(enc_strb_post(3, 0, 1))
    a.label("au_ones")
    a.emit(enc_add_imm(4, 4, 0x30, False))
    a.emit(enc_strb_post(4, 0, 1))
    a.emit(enc_strb_uimm(31, 0, 0))
    a.emit(RET)

    # -------------------------------------------------------------------------
    # Core 1: fn_parse_languages_yaml() -> w0 = lang_count
    #   Reads sdmc:/switch/DBI/languages.yaml into BSS_YAML_STR (caller must free
    #   via STD_STR_DTOR_FN when done!), populates BSS_LANG_TABLE, BSS_LANG_COUNT,
    #   BSS_ACTIVE_IDX, BSS_SEL_VAL_OFF, BSS_SEL_VAL_LEN, BSS_SEL_CODE.
    # -------------------------------------------------------------------------
    a.label("fn_parse_languages_yaml")
    a.emit(enc_stp(29, 30, 31, -0x50, "pre"))
    a.emit(enc_stp(19, 20, 31, 0x10))
    a.emit(enc_stp(21, 22, 31, 0x20))
    a.emit(enc_stp(23, 24, 31, 0x30))
    a.emit(enc_stp(25, 26, 31, 0x40))

    # Reset metadata fields
    a.adrp_add(19, NEW_BSS_BASE)
    a.emit(enc_str_uimm(31, 19, 0x40, False))   # lang_count = 0
    a.emit(enc_movn(0, 0, 0, False))            # w0 = -1
    a.emit(enc_str_uimm(0, 19, 0x44, False))    # active_idx = -1
    a.emit(enc_str_uimm(31, 19, 0x48, True))    # sel_val_off = 0, sel_val_len = 0
    a.emit(enc_strb_uimm(31, 19, 0x50))         # selected_code[0] = 0

    # Read sdmc:/switch/DBI/languages.yaml via unhooked READ_FILE_RAW_FN (0x950564)
    a.emit(enc_movz(0, len(YAML_PATH_BYTES), 0, True))
    a.adr(1, "yaml_path_str")
    a.emit(enc_add_imm(8, 19, 0x10, True))      # &BSS_YAML_STR
    a.bl(READ_FILE_RAW_FN)

    # Load yaml_ptr (x20), yaml_len (x21), yaml_end (x22)
    a.emit(enc_ldr_uimm(20, 19, 0x10, True))
    a.emit(enc_ldr_uimm(21, 19, 0x18, True))
    a.cbz(21, "py_done", True)
    a.emit(enc_add_reg(22, 20, 21, True))       # x22 = yaml_end
    a.emit(enc_mov_reg(23, 20, True))           # x23 = cursor
    a.emit(enc_movz(24, 0, 0, True))            # x24 = lang_count

    # Line loop
    a.label("py_line")
    a.emit(enc_cmp_reg(23, 22, True))
    a.b_cond(COND_HS, "py_match_active")

    # Find end of current line (x25 = ptr to '\n' or yaml_end)
    a.emit(enc_mov_reg(25, 23, True))
    a.label("py_find_nl")
    a.emit(enc_cmp_reg(25, 22, True))
    a.b_cond(COND_HS, "py_got_line")
    a.emit(enc_ldrb_uimm(0, 25, 0))
    a.emit(enc_cmp_imm(0, 0x0A, False))
    a.b_cond(COND_EQ, "py_got_line")
    a.emit(enc_add_imm(25, 25, 1, True))
    a.b("py_find_nl")

    a.label("py_got_line")
    # x26 = line_start (skip leading spaces/tabs)
    a.emit(enc_mov_reg(26, 23, True))
    a.label("py_ltrim")
    a.emit(enc_cmp_reg(26, 25, True))
    a.b_cond(COND_HS, "py_next_line")
    a.emit(enc_ldrb_uimm(0, 26, 0))
    a.emit(enc_cmp_imm(0, 0x20, False))
    a.b_cond(COND_EQ, "py_ltrim_inc")
    a.emit(enc_cmp_imm(0, 0x09, False))
    a.b_cond(COND_NE, "py_check_keys")
    a.label("py_ltrim_inc")
    a.emit(enc_add_imm(26, 26, 1, True))
    a.b("py_ltrim")

    a.label("py_check_keys")
    # Skip comment lines starting with '#'
    a.emit(enc_cmp_imm(0, 0x23, False))
    a.b_cond(COND_EQ, "py_next_line")

    # Check "selected_language:"
    a.emit(enc_mov_reg(0, 26, True))
    a.emit(enc_mov_reg(1, 25, True))
    a.adr(2, "k_selected")
    a.bl("fn_startswith")
    a.cbz(0, "py_chk_code", True)
    a.emit(enc_mov_reg(1, 25, True))
    a.emit(enc_add_imm(2, 19, 0x50, True))      # BSS_SEL_CODE
    a.emit(enc_movz(3, 15, 0, True))
    a.emit(enc_movz(4, 1, 0, False))            # stop on whitespace
    a.bl("fn_copy_yaml_val")
    a.emit(enc_sub_reg(2, 0, 20, True))         # sel_val_off = trimmed_start - yaml_ptr
    a.emit(enc_str_uimm(2, 19, 0x48, False))
    a.emit(enc_str_uimm(1, 19, 0x4C, False))    # sel_val_len
    a.b("py_next_line")

    # Check "- code:"
    a.label("py_chk_code")
    a.emit(enc_mov_reg(0, 26, True))
    a.emit(enc_mov_reg(1, 25, True))
    a.adr(2, "k_code")
    a.bl("fn_startswith")
    a.cbz(0, "py_chk_name", True)
    a.emit(enc_cmp_imm(24, LANG_MAX_ENTRIES, True))
    a.b_cond(COND_HS, "py_next_line")
    # Entry addr = BSS_LANG_TABLE + x24 * LANG_ENTRY_SIZE
    a.emit(enc_movz(5, LANG_ENTRY_SIZE, 0, True))
    a.emit(enc_mul(2, 24, 5, True))
    a.emit(enc_add_imm(6, 19, 0x100, True))
    a.emit(enc_add_reg(2, 6, 2, True))
    # Clear name[0] and file[0]
    a.emit(enc_strb_uimm(31, 2, LANG_OFF_NAME))
    a.emit(enc_strb_uimm(31, 2, LANG_OFF_FILE))
    a.emit(enc_mov_reg(1, 25, True))
    a.emit(enc_movz(3, 15, 0, True))
    a.emit(enc_movz(4, 1, 0, False))
    a.bl("fn_copy_yaml_val")
    a.emit(enc_add_imm(24, 24, 1, True))
    a.b("py_next_line")

    # Check "name:" (requires count > 0)
    a.label("py_chk_name")
    a.cbz(24, "py_next_line", True)
    a.emit(enc_mov_reg(0, 26, True))
    a.emit(enc_mov_reg(1, 25, True))
    a.adr(2, "k_name")
    a.bl("fn_startswith")
    a.cbz(0, "py_chk_file", True)
    a.emit(enc_sub_imm(5, 24, 1, True))
    a.emit(enc_movz(6, LANG_ENTRY_SIZE, 0, True))
    a.emit(enc_mul(2, 5, 6, True))
    a.emit(enc_add_imm(6, 19, 0x100, True))
    a.emit(enc_add_reg(2, 6, 2, True))
    a.emit(enc_add_imm(2, 2, LANG_OFF_NAME, True))
    a.emit(enc_mov_reg(1, 25, True))
    a.emit(enc_movz(3, 47, 0, True))
    a.emit(enc_movz(4, 0, 0, False))            # allow spaces inside name
    a.bl("fn_copy_yaml_val")
    a.b("py_next_line")

    # Check "file:" (requires count > 0)
    a.label("py_chk_file")
    a.emit(enc_mov_reg(0, 26, True))
    a.emit(enc_mov_reg(1, 25, True))
    a.adr(2, "k_file")
    a.bl("fn_startswith")
    a.cbz(0, "py_next_line", True)
    a.emit(enc_sub_imm(5, 24, 1, True))
    a.emit(enc_movz(6, LANG_ENTRY_SIZE, 0, True))
    a.emit(enc_mul(2, 5, 6, True))
    a.emit(enc_add_imm(6, 19, 0x100, True))
    a.emit(enc_add_reg(2, 6, 2, True))
    a.emit(enc_add_imm(2, 2, LANG_OFF_FILE, True))
    a.emit(enc_mov_reg(1, 25, True))
    a.emit(enc_movz(3, 127, 0, True))
    a.emit(enc_movz(4, 0, 0, False))            # allow spaces in paths
    a.bl("fn_copy_yaml_val")

    a.label("py_next_line")
    a.emit(enc_add_imm(23, 25, 1, True))        # advance past '\n'
    a.b("py_line")

    # Store lang_count and find active_idx matching BSS_SEL_CODE
    a.label("py_match_active")
    a.emit(enc_str_uimm(24, 19, 0x40, False))
    a.emit(enc_movz(25, 0, 0, True))            # idx = 0
    a.label("py_mloop")
    a.emit(enc_cmp_reg(25, 24, True))
    a.b_cond(COND_HS, "py_done")
    a.emit(enc_movz(5, LANG_ENTRY_SIZE, 0, True))
    a.emit(enc_mul(0, 25, 5, True))
    a.emit(enc_add_imm(6, 19, 0x100, True))
    a.emit(enc_add_reg(0, 6, 0, True))
    a.emit(enc_add_imm(1, 19, 0x50, True))
    a.bl("fn_streq")
    a.cbnz(0, "py_mfound", False)
    a.emit(enc_add_imm(25, 25, 1, True))
    a.b("py_mloop")
    a.label("py_mfound")
    a.emit(enc_str_uimm(25, 19, 0x44, False))

    a.label("py_done")
    a.emit(enc_ldr_uimm(0, 19, 0x40, False))    # return w0 = lang_count
    a.emit(enc_ldp(25, 26, 31, 0x40))
    a.emit(enc_ldp(23, 24, 31, 0x30))
    a.emit(enc_ldp(21, 22, 31, 0x20))
    a.emit(enc_ldp(19, 20, 31, 0x10))
    a.emit(enc_ldp(29, 30, 31, 0x50, "post"))
    a.emit(RET)

    # -------------------------------------------------------------------------
    # Core 2: yaml_startup_loader(x0=0x20, x1=0x94fd5c, x8=0x1273de0)
    #   Hooked at 0x9500e0 inside DBIPatcher's ensure_loaded().
    # -------------------------------------------------------------------------
    a.label("yaml_startup_loader")
    a.emit(enc_stp(29, 30, 31, -0x30, "pre"))
    a.emit(enc_stp(19, 20, 31, 0x10))
    a.emit(enc_str_uimm(21, 31, 0x20, True))
    a.emit(enc_mov_reg(19, 8, True))            # x19 = &DBIPatcher persist (0x1273de0)
    a.adrp_add(20, NEW_BSS_BASE)

    a.bl("fn_parse_languages_yaml")
    # Check count > 0 and active_idx >= 0
    a.cbz(0, "ysl_fallback", False)
    a.emit(enc_ldrsw_uimm(21, 20, 0x44))        # x21 = active_idx (signed)
    a.emit(enc_cmp_imm(21, 0, True))
    a.b_cond(COND_LT, "ysl_fallback")

    # Free BSS_YAML_STR before loading translation .bin (paths are copied into BSS_LANG_TABLE)
    a.emit(enc_add_imm(0, 20, 0x10, True))
    a.bl(STD_STR_DTOR_FN)

    # Compute &lang_table[active_idx].file
    a.emit(enc_movz(5, LANG_ENTRY_SIZE, 0, True))
    a.emit(enc_mul(21, 21, 5, True))
    a.emit(enc_add_imm(6, 20, 0x100, True))
    a.emit(enc_add_reg(21, 6, 21, True))
    a.emit(enc_add_imm(21, 21, LANG_OFF_FILE, True))  # x21 = file_path_cstr

    # strlen(file_path)
    a.emit(enc_mov_reg(0, 21, True))
    a.bl(STRLEN_FN)
    a.cbz(0, "ysl_russian_native", True)

    # Load selected translation .bin into persist (x19)
    a.emit(enc_mov_reg(1, 21, True))
    a.emit(enc_mov_reg(8, 19, True))
    a.bl(READ_FILE_RAW_FN)
    a.b("ysl_ret")

    # Selected language has file: "" (e.g. Russian original) -> empty SSO persist + retry=30
    a.label("ysl_russian_native")
    a.emit(enc_add_imm(0, 19, 0x10, True))      # SSO local buf = persist + 0x10
    a.emit(enc_str_uimm(0, 19, 0, True))
    a.emit(enc_str_uimm(31, 19, 8, True))       # len = 0
    a.emit(enc_strb_uimm(31, 19, 0x10))         # buf[0] = 0
    a.adrp_add(1, DBIPATCHER_STATE)
    a.emit(enc_movz(2, 30, 0, False))
    a.emit(enc_str_uimm(2, 1, 4, False))        # retry = 30 -> stop re-reading disk
    a.b("ysl_ret")

    # YAML missing or selected_language unmatched -> free yaml_str, load default translation.bin
    a.label("ysl_fallback")
    a.emit(enc_add_imm(0, 20, 0x10, True))
    a.bl(STD_STR_DTOR_FN)
    a.emit(enc_movz(0, 0x20, 0, True))
    a.adrp_add(1, DBIPATCHER_FALLBACK_PATH)
    a.emit(enc_mov_reg(8, 19, True))
    a.bl(READ_FILE_RAW_FN)

    a.label("ysl_ret")
    a.emit(enc_ldr_uimm(21, 31, 0x20, True))
    a.emit(enc_ldp(19, 20, 31, 0x10))
    a.emit(enc_ldp(29, 30, 31, 0x30, "post"))
    a.emit(RET)

    # -------------------------------------------------------------------------
    # Core 3: main_menu_add_hook(x0=MainMenu*, x1=&uptr_settings)
    #   Hooked at 0x50dbb4. Adds original "DBI Settings", then appends "Language".
    #   Preserves all callee-saved registers (x19..x28; x22=MainMenu*, x23=style_base).
    # -------------------------------------------------------------------------
    a.label("main_menu_add_hook")
    a.emit(enc_stp(29, 30, 31, -0x80, "pre"))
    a.emit(enc_stp(19, 20, 31, 0x10))
    # Stack frame:
    #   [sp+0x20..0x3f]: std::string label ("Language", SSO)
    #   [sp+0x40..0x5f]: std::function cb (32B)
    #   [sp+0x60..0x67]: unique_ptr<MenuItem>
    a.emit(enc_mov_reg(19, 0, True))            # x19 = MainMenu*

    # 1. Add original "DBI Settings" item
    a.bl(MAIN_MENU_ADD_FN)

    # 2. Allocate MenuItem (0xc8 bytes)
    a.emit(enc_movz(0, 0xC8, 0, True))
    a.bl(OP_NEW_FN)
    a.emit(enc_mov_reg(20, 0, True))            # x20 = new MenuItem*

    # 3. Build SSO std::string "Language" (len 8) at [sp+0x20]
    a.emit(enc_add_imm(0, 31, 0x30, True))      # inline buf = sp + 0x30
    a.emit(enc_str_uimm(0, 31, 0x20, True))     # _M_p = sp + 0x30
    a.emit(enc_movz(1, len(MENU_LABEL_BYTES), 0, True))
    a.emit(enc_str_uimm(1, 31, 0x28, True))     # _M_string_length = 8
    a.adr(1, "menu_label_str")
    a.bl("fn_append_cstr")                      # copies "Language\0" into [sp+0x30]

    # 4. Build captureless std::function at [sp+0x40]
    a.emit(enc_stp(31, 31, 31, 0x40))           # functor storage = 0
    a.adrp_add(0, STD_FUNC_MGR_FN)
    a.emit(enc_str_uimm(0, 31, 0x50, True))     # _M_manager = 0x4f8eb0
    a.adr(0, "language_picker_cb")
    a.emit(enc_str_uimm(0, 31, 0x58, True))     # _M_invoker = &language_picker_cb

    # 5. MenuItem::MenuItem(x20, &[sp+0x20], &[sp+0x40], x23+0x1a8)
    a.emit(enc_mov_reg(0, 20, True))
    a.emit(enc_add_imm(1, 31, 0x20, True))
    a.emit(enc_add_imm(2, 31, 0x40, True))
    a.emit(enc_add_imm(3, 23, 0x1A8, True))
    a.bl(MENU_ITEM_CTOR_FN)

    # 6. Destroy temporary std::function and std::string
    a.emit(enc_add_imm(0, 31, 0x40, True))
    a.bl(STD_FUNC_DTOR_FN)
    a.emit(enc_add_imm(0, 31, 0x20, True))
    a.bl(STD_STR_DTOR_FN)

    # 7. MainMenu::add_item(x19, &[sp+0x60]) & destroy unique_ptr
    a.emit(enc_str_uimm(20, 31, 0x60, True))
    a.emit(enc_mov_reg(0, 19, True))
    a.emit(enc_add_imm(1, 31, 0x60, True))
    a.bl(MAIN_MENU_ADD_FN)
    a.emit(enc_add_imm(0, 31, 0x60, True))
    a.bl(UPTR_MENU_DTOR_FN)

    a.emit(enc_ldp(19, 20, 31, 0x10))
    a.emit(enc_ldp(29, 30, 31, 0x80, "post"))
    a.emit(RET)

    # -------------------------------------------------------------------------
    # Core 4: language_picker_cb(void* functor) -> bool (w0 = 0, stay in Main Menu)
    #   Reads languages.yaml, shows interactive paged modal, updates languages.yaml
    #   and hot-reloads DBIPatcher on (A).
    # -------------------------------------------------------------------------
    a.label("language_picker_cb")
    a.emit(enc_stp(29, 30, 31, -0xD0, "pre"))
    a.emit(enc_stp(19, 20, 31, 0x10))
    a.emit(enc_stp(21, 22, 31, 0x20))
    a.emit(enc_stp(23, 24, 31, 0x30))
    a.emit(enc_stp(25, 26, 31, 0x40))
    # Stack slots:
    #   [sp+0x50..0x6f]: msg std::string (32B)
    #   [sp+0x70..0x8f]: color std::string (32B)
    #   [sp+0x90..0xcf]: InputEvent sret buffer (0x40B)

    a.adrp_add(19, NEW_BSS_BASE)
    a.bl("fn_parse_languages_yaml")
    a.emit(enc_mov_reg(20, 0, False))           # w20 = count
    a.cbnz(20, "lp_has_langs", False)

    # Missing languages.yaml -> show info popup and exit
    a.bl(GET_WIN_FN)
    a.cbz(0, "lp_exit_free", True)
    a.emit(enc_ldr_uimm(0, 0, 0, True))
    a.cbz(0, "lp_exit_free", True)
    a.adr(1, "picker_missing_str")
    a.emit(enc_movz(2, len(PICKER_MISSING), 0, True))
    a.emit(enc_stp(1, 2, 31, 0x50))
    a.emit(enc_stp(2, 31, 31, 0x60))
    a.adr(1, "blue_box_str")
    a.emit(enc_movz(2, len(ANSI_BLUE_BOX), 0, True))
    a.emit(enc_stp(1, 2, 31, 0x70))
    a.emit(enc_stp(2, 31, 31, 0x80))
    for off in (0x90, 0xA0, 0xB0, 0xC0):
        a.emit(enc_stp(31, 31, 31, off))
    a.emit(enc_add_imm(1, 31, 0x50, True))
    a.emit(enc_add_imm(2, 31, 0x70, True))
    a.emit(enc_movz(3, 1, 0, False))
    a.emit(enc_add_imm(8, 31, 0x90, True))
    a.bl(SHOW_POPUP_FN)
    a.b("lp_repaint_exit")

    a.label("lp_has_langs")
    # w21 = active_idx (signed), w22 = cursor = (active_idx >= 0 ? active_idx : 0)
    a.emit(enc_ldrsw_uimm(21, 19, 0x44))
    a.emit(enc_mov_reg(22, 21, False))
    a.emit(enc_cmp_imm(21, 0, True))
    a.b_cond(COND_GE, "lp_loop")
    a.emit(enc_movz(22, 0, 0, False))

    # --- Modal render + input loop ---
    a.label("lp_loop")
    # Compute page = cursor / 12 (w23), total_pages = (count + 11) / 12 (w24)
    a.emit(enc_movz(2, LANG_PAGE_SIZE, 0, False))
    a.emit(enc_udiv(23, 22, 2, False))          # w23 = page (0-based)
    a.emit(enc_add_imm(3, 20, LANG_PAGE_SIZE - 1, False))
    a.emit(enc_udiv(24, 3, 2, False))           # w24 = total_pages

    # Format popup string into BSS_POPUP_BUF (x25 = write cursor)
    a.adrp_add(25, BSS_POPUP_BUF)
    a.emit(enc_mov_reg(0, 25, True))
    a.adr(1, "picker_hdr1_str")                 # "Select Language (Page "
    a.bl("fn_append_cstr")
    a.emit(enc_add_imm(1, 23, 1, False))        # page + 1
    a.bl("fn_append_u32")
    a.emit(enc_movz(2, ord("/"), 0, False))
    a.emit(enc_strb_post(2, 0, 1))
    a.emit(enc_mov_reg(1, 24, False))           # total_pages
    a.bl("fn_append_u32")
    a.emit(enc_movz(2, ord(")"), 0, False))
    a.emit(enc_strb_post(2, 0, 1))
    a.adr(1, "picker_hdr2_str")                 # "\nActive: "
    a.bl("fn_append_cstr")
    a.emit(enc_add_imm(1, 19, 0x50, True))      # BSS_SEL_CODE
    a.bl("fn_append_cstr")
    a.emit(enc_movz(2, 0x0A, 0, False))         # '\n'
    a.emit(enc_strb_post(2, 0, 1))
    a.emit(enc_strb_post(2, 0, 1))              # blank line
    a.emit(enc_mov_reg(25, 0, True))

    # Render items i in [page*12, min((page+1)*12, count))
    a.emit(enc_movz(2, LANG_PAGE_SIZE, 0, False))
    a.emit(enc_mul(26, 23, 2, False))           # w26 = i = page * 12
    a.emit(enc_add_imm(24, 26, LANG_PAGE_SIZE, False))  # w24 = page_end
    a.emit(enc_cmp_reg(24, 20, False))
    a.b_cond(COND_LS, "lp_item_loop")
    a.emit(enc_mov_reg(24, 20, False))          # clamp to count

    a.label("lp_item_loop")
    a.emit(enc_cmp_reg(26, 24, False))
    a.b_cond(COND_HS, "lp_footer")

    # Prefix: " > " if i == cursor else "   "
    a.emit(enc_mov_reg(0, 25, True))
    a.emit(enc_movz(2, 0x20, 0, False))
    a.emit(enc_strb_post(2, 0, 1))
    a.emit(enc_cmp_reg(26, 22, False))
    a.b_cond(COND_NE, "lp_not_cur")
    a.emit(enc_movz(2, ord(">"), 0, False))
    a.label("lp_not_cur")
    a.emit(enc_strb_post(2, 0, 1))
    a.emit(enc_movz(2, 0x20, 0, False))
    a.emit(enc_strb_post(2, 0, 1))

    # Active marker: "* " if i == active_idx else "  "
    a.emit(enc_cmp_reg(26, 21, False))
    a.b_cond(COND_NE, "lp_not_act")
    a.emit(enc_movz(2, ord("*"), 0, False))
    a.label("lp_not_act")
    a.emit(enc_strb_post(2, 0, 1))
    a.emit(enc_movz(2, 0x20, 0, False))
    a.emit(enc_strb_post(2, 0, 1))

    # Append lang_table[i].name + " [" + lang_table[i].code + "]\n"
    a.emit(enc_movz(5, LANG_ENTRY_SIZE, 0, True))
    a.emit(enc_mul(6, 26, 5, True))
    a.emit(enc_add_imm(7, 19, 0x100, True))
    a.emit(enc_add_reg(6, 7, 6, True))          # x6 = &lang_table[i]
    a.emit(enc_add_imm(1, 6, LANG_OFF_NAME, True))
    a.bl("fn_append_cstr")
    a.emit(enc_movz(2, 0x20, 0, False))
    a.emit(enc_strb_post(2, 0, 1))
    a.emit(enc_movz(2, ord("["), 0, False))
    a.emit(enc_strb_post(2, 0, 1))
    # Recompute &lang_table[i].code (x6 preserved across fn_append_cstr!)
    a.emit(enc_mov_reg(1, 6, True))
    a.bl("fn_append_cstr")
    a.emit(enc_movz(2, ord("]"), 0, False))
    a.emit(enc_strb_post(2, 0, 1))
    a.emit(enc_movz(2, 0x0A, 0, False))
    a.emit(enc_strb_post(2, 0, 1))
    a.emit(enc_mov_reg(25, 0, True))

    a.emit(enc_add_imm(26, 26, 1, False))
    a.b("lp_item_loop")

    # Append footer & compute total byte length
    a.label("lp_footer")
    a.emit(enc_mov_reg(0, 25, True))
    a.adr(1, "picker_footer_str")
    a.bl("fn_append_cstr")
    a.adrp_add(1, BSS_POPUP_BUF)
    a.emit(enc_sub_reg(2, 0, 1, True))          # x2 = total len

    # Build msg std::string at [sp+0x50] & blue box color at [sp+0x70]
    a.emit(enc_stp(1, 2, 31, 0x50))
    a.emit(enc_stp(2, 31, 31, 0x60))
    a.adr(1, "blue_box_str")
    a.emit(enc_movz(2, len(ANSI_BLUE_BOX), 0, True))
    a.emit(enc_stp(1, 2, 31, 0x70))
    a.emit(enc_stp(2, 31, 31, 0x80))
    for off in (0x90, 0xA0, 0xB0, 0xC0):
        a.emit(enc_stp(31, 31, 31, off))

    # Show modal
    a.bl(GET_WIN_FN)
    a.cbz(0, "lp_exit_free", True)
    a.emit(enc_ldr_uimm(0, 0, 0, True))
    a.cbz(0, "lp_exit_free", True)
    a.emit(enc_add_imm(1, 31, 0x50, True))
    a.emit(enc_add_imm(2, 31, 0x70, True))
    a.emit(enc_movz(3, 1, 0, False))
    a.emit(enc_add_imm(8, 31, 0x90, True))
    a.bl(SHOW_POPUP_FN)

    # Check B (Cancel)
    a.emit(enc_add_imm(0, 31, 0x90, True))
    a.emit(enc_movz(1, BTN_B, 0, True))
    a.bl(CHECK_BTN_FN)
    a.cbnz(0, "lp_repaint_exit", False)

    # Check A (Apply selected language)
    a.emit(enc_add_imm(0, 31, 0x90, True))
    a.emit(enc_movz(1, BTN_A, 0, True))
    a.bl(CHECK_BTN_FN)
    a.cbnz(0, "lp_apply", False)

    # Check Down (0x88000 = 0x8000 | 0x80000)
    a.emit(enc_add_imm(0, 31, 0x90, True))
    a.emit(enc_movz(1, 0x8000, 0, True))
    a.emit(enc_movk(1, 0x0008, 1, True))
    a.bl(CHECK_BTN_FN)
    a.cbz(0, "lp_chk_up", False)
    a.emit(enc_add_imm(22, 22, 1, False))
    a.emit(enc_cmp_reg(22, 20, False))
    a.b_cond(COND_LO, "lp_loop")
    a.emit(enc_movz(22, 0, 0, False))
    a.b("lp_loop")

    # Check Up (0x22000 = 0x2000 | 0x20000)
    a.label("lp_chk_up")
    a.emit(enc_add_imm(0, 31, 0x90, True))
    a.emit(enc_movz(1, 0x2000, 0, True))
    a.emit(enc_movk(1, 0x0002, 1, True))
    a.bl(CHECK_BTN_FN)
    a.cbz(0, "lp_chk_r", False)
    a.cbnz(22, "lp_up_dec", False)
    a.emit(enc_sub_imm(22, 20, 1, False))
    a.b("lp_loop")
    a.label("lp_up_dec")
    a.emit(enc_sub_imm(22, 22, 1, False))
    a.b("lp_loop")

    # Check R (next page)
    a.label("lp_chk_r")
    a.emit(enc_add_imm(0, 31, 0x90, True))
    a.emit(enc_movz(1, BTN_R, 0, True))
    a.bl(CHECK_BTN_FN)
    a.cbz(0, "lp_chk_l", False)
    a.emit(enc_add_imm(22, 22, LANG_PAGE_SIZE, False))
    a.emit(enc_cmp_reg(22, 20, False))
    a.b_cond(COND_LO, "lp_loop")
    a.emit(enc_movz(22, 0, 0, False))
    a.b("lp_loop")

    # Check L (prev page)
    a.label("lp_chk_l")
    a.emit(enc_add_imm(0, 31, 0x90, True))
    a.emit(enc_movz(1, BTN_L, 0, True))
    a.bl(CHECK_BTN_FN)
    a.cbz(0, "lp_loop", False)
    a.emit(enc_cmp_imm(22, LANG_PAGE_SIZE, False))
    a.b_cond(COND_HS, "lp_l_sub")
    a.emit(enc_sub_imm(22, 20, 1, False))
    a.b("lp_loop")
    a.label("lp_l_sub")
    a.emit(enc_sub_imm(22, 22, LANG_PAGE_SIZE, False))
    a.b("lp_loop")

    # --- Apply selected language (cursor = w22) ---
    a.label("lp_apply")
    # x23 = &lang_table[cursor].code
    a.emit(enc_movz(5, LANG_ENTRY_SIZE, 0, True))
    a.emit(enc_mul(23, 22, 5, True))
    a.emit(enc_add_imm(6, 19, 0x100, True))
    a.emit(enc_add_reg(23, 6, 23, True))

    # Rewrite sdmc:/switch/DBI/languages.yaml via 3-part fwrite if sel_val_off > 0
    a.emit(enc_ldr_uimm(24, 19, 0x48, False))   # x24 = sel_val_off
    a.cbz(24, "lp_skip_write", True)
    a.adr(0, "yaml_path_str")
    a.adr(1, "wb_mode_str")
    a.bl(FOPEN_FN)
    a.cbz(0, "lp_skip_write", True)
    a.emit(enc_mov_reg(25, 0, True))            # x25 = FILE*

    # Part 1: fwrite(yaml_ptr, 1, sel_val_off, fp)
    a.emit(enc_ldr_uimm(0, 19, 0x10, True))
    a.emit(enc_movz(1, 1, 0, True))
    a.emit(enc_mov_reg(2, 24, True))
    a.emit(enc_mov_reg(3, 25, True))
    a.bl(FWRITE_FN)

    # Part 2: fwrite(new_code, 1, strlen(new_code), fp)
    a.emit(enc_mov_reg(0, 23, True))
    a.bl(STRLEN_FN)
    a.emit(enc_mov_reg(2, 0, True))
    a.emit(enc_mov_reg(0, 23, True))
    a.emit(enc_movz(1, 1, 0, True))
    a.emit(enc_mov_reg(3, 25, True))
    a.bl(FWRITE_FN)

    # Part 3: tail_off = sel_val_off + sel_val_len; tail_len = yaml_len - tail_off
    a.emit(enc_ldr_uimm(5, 19, 0x4C, False))    # sel_val_len
    a.emit(enc_add_reg(5, 24, 5, True))         # tail_off
    a.emit(enc_ldr_uimm(6, 19, 0x18, True))     # yaml_len
    a.emit(enc_cmp_reg(6, 5, True))
    a.b_cond(COND_LS, "lp_fclose")
    a.emit(enc_sub_reg(2, 6, 5, True))          # tail_len
    a.emit(enc_ldr_uimm(0, 19, 0x10, True))
    a.emit(enc_add_reg(0, 0, 5, True))          # yaml_ptr + tail_off
    a.emit(enc_movz(1, 1, 0, True))
    a.emit(enc_mov_reg(3, 25, True))
    a.bl(FWRITE_FN)

    a.label("lp_fclose")
    a.emit(enc_mov_reg(0, 25, True))
    a.bl(FCLOSE_FN)

    a.label("lp_skip_write")
    # Free BSS_YAML_STR BEFORE calling ENSURE_LOADED_FN (which re-reads languages.yaml!)
    a.emit(enc_add_imm(0, 19, 0x10, True))
    a.bl(STD_STR_DTOR_FN)

    # Hot-reload DBIPatcher runtime state:
    #   1) Destroy old persist string at 0x1273de0 (if _M_p != NULL)
    a.adrp_add(24, DBIPATCHER_PERSIST)
    a.emit(enc_ldr_uimm(0, 24, 0, True))
    a.cbz(0, "lp_skip_pdtor", True)
    a.emit(enc_mov_reg(0, 24, True))
    a.bl(STD_STR_DTOR_FN)
    a.label("lp_skip_pdtor")
    #   2) Re-init 0x1273de0 as empty SSO string
    a.emit(enc_add_imm(0, 24, 0x10, True))
    a.emit(enc_str_uimm(0, 24, 0, True))
    a.emit(enc_str_uimm(31, 24, 8, True))
    a.emit(enc_strb_uimm(31, 24, 0x10))
    #   3) Reset DBIPatcher state flags at 0x1273dc0 (lock=0, retry=0, magic=0, ptr=0)
    a.adrp_add(25, DBIPATCHER_STATE)
    a.emit(enc_str_uimm(31, 25, 0x00, True))    # lock=0, retry=0
    a.emit(enc_str_uimm(31, 25, 0x10, True))    # magic=0
    a.emit(enc_str_uimm(31, 25, 0x18, True))    # tableptr=0
    #   4) Trigger live reload via ensure_loaded() (0x950078)
    a.bl(ENSURE_LOADED_FN)

    # Show brief confirmation modal
    a.bl(GET_WIN_FN)
    a.cbz(0, "lp_ret_zero", True)
    a.emit(enc_ldr_uimm(0, 0, 0, True))
    a.cbz(0, "lp_ret_zero", True)
    a.adr(1, "picker_applied_str")
    a.emit(enc_movz(2, len(PICKER_APPLIED), 0, True))
    a.emit(enc_stp(1, 2, 31, 0x50))
    a.emit(enc_stp(2, 31, 31, 0x60))
    a.adr(1, "blue_box_str")
    a.emit(enc_movz(2, len(ANSI_BLUE_BOX), 0, True))
    a.emit(enc_stp(1, 2, 31, 0x70))
    a.emit(enc_stp(2, 31, 31, 0x80))
    a.emit(enc_add_imm(1, 31, 0x50, True))
    a.emit(enc_add_imm(2, 31, 0x70, True))
    a.emit(enc_movz(3, 1, 0, False))
    a.emit(enc_add_imm(8, 31, 0x90, True))
    a.bl(SHOW_POPUP_FN)
    # Repaint parent window and return 0 (yaml_str already freed)
    a.bl(GET_WIN_FN)
    a.cbz(0, "lp_ret_zero", True)
    a.emit(enc_ldr_uimm(0, 0, 0, True))
    a.cbz(0, "lp_ret_zero", True)
    a.emit(enc_movz(1, 1, 0, False))
    a.bl(REPAINT_WIN_FN)
    a.b("lp_ret_zero")

    # Cancel / missing path: repaint parent window, free yaml_str, return 0
    a.label("lp_repaint_exit")
    a.bl(GET_WIN_FN)
    a.cbz(0, "lp_exit_free", True)
    a.emit(enc_ldr_uimm(0, 0, 0, True))
    a.cbz(0, "lp_exit_free", True)
    a.emit(enc_movz(1, 1, 0, False))
    a.bl(REPAINT_WIN_FN)

    a.label("lp_exit_free")
    a.emit(enc_add_imm(0, 19, 0x10, True))
    a.bl(STD_STR_DTOR_FN)

    a.label("lp_ret_zero")
    a.emit(enc_movz(0, 0, 0, False))            # return false -> stay in Main Menu
    a.emit(enc_ldp(25, 26, 31, 0x40))
    a.emit(enc_ldp(23, 24, 31, 0x30))
    a.emit(enc_ldp(21, 22, 31, 0x20))
    a.emit(enc_ldp(19, 20, 31, 0x10))
    a.emit(enc_ldp(29, 30, 31, 0xD0, "post"))
    a.emit(RET)

    # Embedded string pool
    a.data_str("yaml_path_str", YAML_PATH_BYTES)
    a.data_str("wb_mode_str", b"wb")
    a.data_str("menu_label_str", MENU_LABEL_BYTES)
    a.data_str("k_selected", b"selected_language:")
    a.data_str("k_code", b"- code:")
    a.data_str("k_name", b"name:")
    a.data_str("k_file", b"file:")
    a.data_str("blue_box_str", ANSI_BLUE_BOX)
    a.data_str("picker_hdr1_str", PICKER_HDR_1)
    a.data_str("picker_hdr2_str", PICKER_HDR_2)
    a.data_str("picker_footer_str", PICKER_FOOTER)
    a.data_str("picker_missing_str", PICKER_MISSING)
    a.data_str("picker_applied_str", PICKER_APPLIED)
    return a.build(CAVE2_END)


# =============================================================================
# 5. BINARY PATCHER ENGINE
# =============================================================================

# Dead inline-immediate serial-loader ranges safe to overwrite with NOPs once
# Group 2 bypass branches are in place (never executed, zero control-flow impact).
DEAD_SERIAL_IMM_RANGES: tuple[tuple[int, int], ...] = (
    (0x09F6A4, 0x09F6C4),  # inline immediate half of hardcoded serial A in build_deviceid_auth
    (0x09FAD8, 0x09FAF8),  # inline immediate half of hardcoded serial B in build_deviceid_auth
    (0x16CBB8, 0x16CBD4),  # inline immediate half of hardcoded serial A in get_console_serial
    (0x16CD2C, 0x16CD4C),  # inline immediate half of hardcoded serial B in get_console_serial
)


def apply_all_patches(raw: bytes, app_name: str = DEFAULT_APP_NAME) -> tuple[bytes, dict[str, int]]:
    """Apply all 6 documented PATCH_GROUPS to a verified DBI 921 NRO binary."""
    sha = hashlib.sha256(raw).hexdigest()
    if sha != EXPECTED_BASE_921_SHA256:
        raise SystemExit(
            f"Unexpected input NRO SHA-256:\n  got     : {sha}\n  expected: {EXPECTED_BASE_921_SHA256}"
        )

    out = bytearray(raw)

    # Pre-flight assertions on exact original bytes before patching
    assert struct.unpack_from("<I", out, NRO_BSS_SIZE_OFF)[0] == OLD_BSS_SIZE
    mod0 = struct.unpack_from("<I", out, NRO_MOD0_PTR_OFF)[0]
    old_bss_end_rel = struct.unpack_from("<i", out, mod0 + 12)[0]
    assert mod0 + old_bss_end_rel == NEW_BSS_BASE
    assert struct.unpack_from("<I", out, SERIAL_SNOOP_HOOK)[0] == 0xF9400680  # ldr x0, [x20, #8]
    assert struct.unpack_from("<I", out, AUTH_SERIAL_HOOK)[0] == 0x910502E0   # add x0, x23, #0x140
    assert struct.unpack_from("<I", out, DEVICEID_HOOK)[0] == 0xB90073F5      # str w21, [sp, #0x70]
    assert struct.unpack_from("<I", out, ENSURE_LOADED_READ)[0] == enc_bl(ENSURE_LOADED_READ, 0x147AE0)
    assert struct.unpack_from("<I", out, MAIN_MENU_ADD_HOOK)[0] == enc_bl(MAIN_MENU_ADD_HOOK, MAIN_MENU_ADD_FN)
    assert all(b == 0 for b in out[CAVE1_ADDR:CAVE1_END]), "Code Cave 1 not empty!"
    assert all(b == 0 for b in out[CAVE2_ADDR:CAVE2_END]), "Code Cave 2 not empty!"

    # --- Group 1: Dedicated BSS Expansion (+16 KiB -> 0x1274000..0x1277fff) ---
    struct.pack_into("<I", out, NRO_BSS_SIZE_OFF, OLD_BSS_SIZE + BSS_GROWTH)
    struct.pack_into("<i", out, mod0 + 12, old_bss_end_rel + BSS_GROWTH)

    # --- Group 2: Serial Privacy & Hardcoded-Serial Removal ---
    struct.pack_into("<I", out, SERIAL_SNOOP_HOOK, enc_b(SERIAL_SNOOP_HOOK, SERIAL_EPILOGUE))
    struct.pack_into("<I", out, AUTH_SERIAL_HOOK, enc_b(AUTH_SERIAL_HOOK, AUTH_AFTER_SERIAL))
    for start, end in DEAD_SERIAL_IMM_RANGES:
        for addr in range(start, end, 4):
            struct.pack_into("<I", out, addr, NOP)

    # --- Group 3: Interactive DeviceID HTTP Consent Popup ---
    cave1_bytes, cave1_code_len, cave1_labels = build_cave1_deviceid_popup()
    struct.pack_into("<I", out, DEVICEID_HOOK, enc_b(DEVICEID_HOOK, CAVE1_ADDR))
    out[CAVE1_ADDR : CAVE1_ADDR + len(cave1_bytes)] = cave1_bytes

    # --- Groups 4 & 5: YAML Startup Loader + Main Menu "Language" Switcher ---
    cave2_bytes, cave2_code_len, cave2_labels = build_cave2_yaml_and_menu()
    out[CAVE2_ADDR : CAVE2_ADDR + len(cave2_bytes)] = cave2_bytes
    struct.pack_into(
        "<I", out, ENSURE_LOADED_READ, enc_bl(ENSURE_LOADED_READ, cave2_labels["yaml_startup_loader"])
    )
    struct.pack_into(
        "<I", out, MAIN_MENU_ADD_HOOK, enc_bl(MAIN_MENU_ADD_HOOK, cave2_labels["main_menu_add_hook"])
    )

    # --- Group 6: NACP App Title ("DBI Multilingual") in NRO ASET section ---
    img_sz = struct.unpack_from("<I", out, NRO_IMAGE_SIZE_OFF)[0]
    assert out[img_sz : img_sz + 4] == b"ASET", "Missing NRO ASET section!"
    nacp_off, nacp_sz = struct.unpack_from("<QQ", out, img_sz + 24)
    assert nacp_sz >= NACP_TITLE_SLOTS * NACP_ENTRY_SIZE
    nacp_abs = img_sz + nacp_off
    title_bytes = app_name.encode("utf-8")
    assert 0 < len(title_bytes) < NACP_TITLE_MAX, f"Invalid app_name length: {len(title_bytes)}"
    title_field = title_bytes.ljust(NACP_TITLE_MAX, b"\x00")
    for slot in range(NACP_TITLE_SLOTS):
        base = nacp_abs + slot * NACP_ENTRY_SIZE
        if out[base : base + NACP_TITLE_MAX].rstrip(b"\x00") or slot == 0:
            out[base : base + NACP_TITLE_MAX] = title_field

    meta = {
        "cave1_total": len(cave1_bytes),
        "cave1_code": cave1_code_len,
        "cave2_total": len(cave2_bytes),
        "cave2_code": cave2_code_len,
        "yaml_startup_loader": cave2_labels["yaml_startup_loader"],
        "main_menu_add_hook": cave2_labels["main_menu_add_hook"],
        "language_picker_cb": cave2_labels["language_picker_cb"],
        "nacp_abs": nacp_abs,
    }
    return bytes(out), meta


# =============================================================================
# 6. YAML CATALOG, PER-LANGUAGE YAML & DBITRNS v3 COMPILER (35 LANGUAGES)
# =============================================================================

TABLE_MAGIC = b"DBITRNS\x00"
TABLE_VERSION = 3
FNV_BASIS = 0x811C9DC5
FNV_PRIME = 0x01000193


def _unescape_csv(s: str) -> str:
    s = s.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)


def _yaml_quote(s: str) -> str:
    """Encode any UTF-8 string (including ANSI escapes/newlines) as a valid YAML double-quoted scalar."""
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20 or o == 0x7F:
            out.append(f"\\x{o:02x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _yaml_unquote(raw: str) -> str:
    """Decode a YAML double-quoted scalar produced by _yaml_quote."""
    s = raw.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    res: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "\\" and i + 1 < n:
            nxt = s[i + 1]
            if nxt == "n":
                res.append("\n"); i += 2
            elif nxt == "r":
                res.append("\r"); i += 2
            elif nxt == "t":
                res.append("\t"); i += 2
            elif nxt == '"':
                res.append('"'); i += 2
            elif nxt == "\\":
                res.append("\\"); i += 2
            elif nxt == "x" and i + 3 < n:
                res.append(chr(int(s[i + 2 : i + 4], 16))); i += 4
            else:
                res.append(nxt); i += 2
        else:
            res.append(s[i]); i += 1
    return "".join(res)


def load_pairs_from_csv(csv_path: Path) -> list[tuple[bytes, bytes]]:
    pairs: list[tuple[bytes, bytes]] = []
    seen: set[bytes] = set()
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            ru = _unescape_csv(row.get("original", "") or "")
            tr = _unescape_csv(row.get("translation", "") or "")
            if not ru or not tr:
                continue
            ru_b, tr_b = ru.encode("utf-8"), tr.encode("utf-8")
            if ru_b == tr_b or ru_b in seen:
                continue
            seen.add(ru_b)
            pairs.append((ru_b, tr_b))
    return pairs


def load_pairs_from_yaml(yaml_path: Path) -> list[tuple[bytes, bytes]]:
    pairs: list[tuple[bytes, bytes]] = []
    seen: set[bytes] = set()
    cur_orig: str | None = None
    for line in yaml_path.read_text(encoding="utf-8").splitlines():
        st = line.strip()
        if st.startswith("- original:"):
            cur_orig = _yaml_unquote(st[len("- original:") :])
        elif st.startswith("translation:") and cur_orig is not None:
            tr = _yaml_unquote(st[len("translation:") :])
            ru_b, tr_b = cur_orig.encode("utf-8"), tr.encode("utf-8")
            if ru_b and tr_b and ru_b != tr_b and ru_b not in seen:
                seen.add(ru_b)
                pairs.append((ru_b, tr_b))
            cur_orig = None
    return pairs


def write_translation_yaml(yaml_path: Path, code: str, name: str, pairs: list[tuple[bytes, bytes]]) -> None:
    lines = [
        f"# DBI 921 Translation Dictionary — {name} ({code})",
        f"# Edit any translation below and run: python3 dbi_patcher.py --rebuild-translations",
        f"code: {code}",
        f"name: {_yaml_quote(name)}",
        "entries:",
    ]
    for ru_b, tr_b in pairs:
        lines.append(f"  - original: {_yaml_quote(ru_b.decode('utf-8'))}")
        lines.append(f"    translation: {_yaml_quote(tr_b.decode('utf-8'))}")
    yaml_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def fnv1a_32(data: bytes) -> int:
    h = FNV_BASIS
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & 0xFFFFFFFF
    return h


def compile_dbitrns_v3(pairs: list[tuple[bytes, bytes]]) -> bytes:
    """Compile (ru_utf8, tr_utf8) pairs into a DBITRNS v3 binary lookup table with FNV-1a index."""
    assert pairs, "Cannot compile empty translation table"
    max_ru = max(len(ru) for ru, _ in pairs)
    max_tr = max(len(tr) for _, tr in pairs)
    ru_off = 4
    tr_off = ru_off + ((max_ru + 3) & ~3)
    entry_sz = tr_off + ((max_tr + 3) & ~3)

    hdr = bytearray(0x20)
    hdr[0:8] = TABLE_MAGIC
    struct.pack_into("<IIIIII", hdr, 8, TABLE_VERSION, len(pairs), entry_sz, ru_off, tr_off, 0)

    buf = bytearray(hdr)
    for ru, tr in pairs:
        ent = bytearray(entry_sz)
        struct.pack_into("<HH", ent, 0, len(ru), len(tr))
        ent[ru_off : ru_off + len(ru)] = ru
        ent[tr_off : tr_off + len(tr)] = tr
        buf.extend(ent)

    nbuckets = 1
    while nbuckets < 2 * len(pairs):
        nbuckets <<= 1
    k_buckets = [0] * nbuckets
    v_buckets = [0] * nbuckets
    for buckets, col in ((k_buckets, 0), (v_buckets, 1)):
        seen: set[bytes] = set()
        for idx, pair in enumerate(pairs):
            s = pair[col]
            if (col == 1 and not s) or s in seen:
                continue
            seen.add(s)
            j = fnv1a_32(s) & (nbuckets - 1)
            while buckets[j]:
                j = (j + 1) & (nbuckets - 1)
            buckets[j] = idx + 1
    buf.extend(struct.pack(f"<I{nbuckets}I{nbuckets}I", nbuckets, *k_buckets, *v_buckets))
    return bytes(buf)


def generate_languages_yaml(selected_code: str = "en") -> str:
    """Generate sdmc:/switch/DBI/languages.yaml catalog for all 35 languages."""
    lines = [
        "# DBI 921 Language Configuration",
        "# Active language is loaded on startup and updated automatically when",
        "# changed via DBI -> Main Menu -> Language.",
        f"selected_language: {selected_code}",
        "",
        "languages:",
    ]
    for code, name, kind in LANGUAGES:
        bin_path = "" if kind == "builtin" else f"sdmc:/switch/DBI/translations/translation_{code}.bin"
        lines.append(f"  - code: {code}")
        lines.append(f"    name: {name}")
        lines.append(f'    file: "{bin_path}"' if not bin_path else f"    file: {bin_path}")
    return "\n".join(lines) + "\n"


def _download_file(url: str, dest: Path, expected_sha256: str | None = None) -> Path:
    """Download a file from upstream GitHub to `dest` (atomic write) with optional SHA-256 check."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "dbi-multilingual-patcher/1.0"})
    print(f"  Downloading {url} ...")
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()
    if expected_sha256 is not None:
        got = hashlib.sha256(data).hexdigest()
        if got != expected_sha256:
            raise SystemExit(
                f"SHA-256 mismatch for {url}:\n  got     : {got}\n  expected: {expected_sha256}"
            )
    tmp.write_bytes(data)
    tmp.replace(dest)
    return dest


def resolve_base_nro(input_path: Path | None, cache_dir: Path, allow_download: bool) -> Path:
    """Locate the base DBI 921 NRO locally, or download & verify it from rashevskyv/DBIPatcher."""
    if input_path is not None:
        if not input_path.exists():
            raise SystemExit(f"Specified --input NRO not found: {input_path}")
        return input_path

    ws = Path(__file__).resolve().parent
    for cand in (cache_dir / "DBI-921.nro", ws / "dbi-analysis" / "base-DBI.nro"):
        if cand.exists():
            if hashlib.sha256(cand.read_bytes()).hexdigest() == EXPECTED_BASE_921_SHA256:
                return cand

    if not allow_download:
        raise SystemExit(
            "Base DBI 921 NRO not found locally and --no-download was specified.\n"
            f"Pass --input <path> or allow downloading from:\n  {UPSTREAM_NRO_URL}"
        )

    return _download_file(
        UPSTREAM_NRO_URL,
        cache_dir / "DBI-921.nro",
        expected_sha256=EXPECTED_BASE_921_SHA256,
    )


def build_all_translations(
    output_dir: Path,
    csv_dirs: list[Path],
    cache_dir: Path,
    from_yaml: bool = False,
    allow_download: bool = True,
) -> dict[str, int]:
    """Build languages.yaml, per-language YAML dictionaries, and DBITRNS v3 .bin tables."""
    tr_dir = output_dir / "translations"
    tr_dir.mkdir(parents=True, exist_ok=True)
    csv_cache = cache_dir / "translations"

    counts: dict[str, int] = {}
    for code, name, kind in LANGUAGES:
        if kind == "builtin":
            counts[code] = 0
            continue
        yaml_file = tr_dir / f"{code}.yaml"
        bin_file = tr_dir / f"translation_{code}.bin"

        if from_yaml:
            if not yaml_file.exists():
                raise SystemExit(f"Missing YAML dictionary for --rebuild-translations: {yaml_file}")
            pairs = load_pairs_from_yaml(yaml_file)
        else:
            csv_file = None
            for d in (*csv_dirs, csv_cache):
                cand = d / f"{code}.csv"
                if cand.exists():
                    csv_file = cand
                    break
            if csv_file is None and kind == "existing" and allow_download:
                csv_file = _download_file(
                    UPSTREAM_CSV_URL_TMPL.format(code=code),
                    csv_cache / f"{code}.csv",
                )
            if csv_file is None:
                raise SystemExit(f"Missing CSV for language '{code}' in {csv_dirs}")
            pairs = load_pairs_from_csv(csv_file)
            write_translation_yaml(yaml_file, code, name, pairs)

        bin_bytes = compile_dbitrns_v3(pairs)
        bin_file.write_bytes(bin_bytes)
        counts[code] = len(pairs)

    # Copy English table as fallback sdmc:/switch/DBI/translation.bin
    shutil.copy2(tr_dir / "translation_en.bin", output_dir / "translation.bin")

    # Write sdmc:/switch/DBI/languages.yaml (default selected_language: en) unless preserving on rebuild
    lang_yaml_path = output_dir / "languages.yaml"
    if not from_yaml or not lang_yaml_path.exists():
        lang_yaml_path.write_text(generate_languages_yaml("en"), encoding="utf-8")

    return counts


# =============================================================================
# 7. OFFLINE UNICORN ARM64 VERIFICATION SUITE (ZERO NETWORKING)
# =============================================================================

def verify_patched_nro(patched: bytes, meta: dict[str, int], output_dir: Path) -> None:
    """Disassemble all patches with Capstone and verify every patch group in offline Unicorn."""
    deps_dir = Path(__file__).resolve().parent / "dbi-analysis" / "python-deps"
    if deps_dir.exists() and str(deps_dir) not in sys.path:
        sys.path.insert(0, str(deps_dir))

    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.arm64_const import (
        UC_ARM64_REG_LR, UC_ARM64_REG_PC, UC_ARM64_REG_SP,
        UC_ARM64_REG_W0, UC_ARM64_REG_W1, UC_ARM64_REG_W2, UC_ARM64_REG_W3,
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X8, UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21,
        UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24, UC_ARM64_REG_X25,
        UC_ARM64_REG_X26, UC_ARM64_REG_X27, UC_ARM64_REG_X28, UC_ARM64_REG_X29,
        UC_ARM64_REG_X30,
    )

    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    # Quick sanity check that every cave instruction disassembles cleanly (no undefined opcodes)
    c1_insns = list(cs.disasm(patched[CAVE1_ADDR : CAVE1_ADDR + meta["cave1_code"]], CAVE1_ADDR))
    c2_insns = list(cs.disasm(patched[CAVE2_ADDR : CAVE2_ADDR + meta["cave2_code"]], CAVE2_ADDR))
    assert len(c1_insns) == meta["cave1_code"] // 4, "Cave 1 contains undecodable instruction!"
    assert len(c2_insns) == meta["cave2_code"] // 4, "Cave 2 contains undecodable instruction!"
    print(f"[PASS] Capstone decode: Cave 1 = {len(c1_insns)} insns ({meta['cave1_total']}B), "
          f"Cave 2 = {len(c2_insns)} insns ({meta['cave2_total']}B)")

    BASE = 0x7100000000
    STACK = 0x7300000000
    HEAP = 0x7400000000
    WIN_MEM = 0x7500000000
    RET_SENTINEL = 0x7200000000

    image_size = struct.unpack_from("<I", patched, NRO_IMAGE_SIZE_OFF)[0]
    bss_sz = struct.unpack_from("<I", patched, NRO_BSS_SIZE_OFF)[0]
    total_mem = (image_size + bss_sz + 0xFFFF) & ~0xFFFF

    def make_vm():
        mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        mu.mem_map(BASE, total_mem)
        mu.mem_write(BASE, patched[:image_size])  # BSS zero-initialized
        mu.mem_map(STACK, 0x40000)
        mu.mem_map(HEAP, 0x400000)                # 4 MiB synthetic heap for std::string / MenuItem
        mu.mem_map(WIN_MEM, 0x4000)
        mu.mem_map(RET_SENTINEL, 0x1000)
        return mu

    def read_cstr(mu, ptr: int, limit: int = 512) -> bytes:
        chunk = bytes(mu.mem_read(ptr, limit))
        nul = chunk.find(b"\x00")
        return chunk if nul < 0 else chunk[:nul]

    # -------------------------------------------------------------------------
    # TEST 1 (Group 2): get_console_serial (0x16c670) — no PRODINFO snoop, no serial swap
    # -------------------------------------------------------------------------
    for test_serial in (b"XAW00000000000", b"XAW10012345678"):
        mu = make_vm()
        events = {"sd_snoop": False, "setcal": False}

        def hook_serial(u, addr, sz, _):
            off = addr - BASE
            if off == 0xACDB80:  # setsysInitialize
                u.reg_write(UC_ARM64_REG_X0, 0)
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off == 0xACE140:  # setsysGetFirmwareVersion (display_version at +0x68)
                u.mem_write(u.reg_read(UC_ARM64_REG_X0) + 0x68, b"19.0.1\x00")
                u.reg_write(UC_ARM64_REG_X0, 0)
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off == 0xACE190:  # setsysGetSerialNumber(char out[0x18])
                u.mem_write(u.reg_read(UC_ARM64_REG_X0), test_serial.ljust(0x18, b"\x00"))
                u.reg_write(UC_ARM64_REG_X0, 0)
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off == 0xACDC20:  # setsysExit
                u.reg_write(UC_ARM64_REG_X0, 0)
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off in (0x1CCB00, 0xACDC70):
                events["sd_snoop"] = True
                u.emu_stop()
            elif off in (0xB4DB00, 0xBC1180):  # operator new / malloc
                n = u.reg_read(UC_ARM64_REG_X0)
                p = alloc_p[0]
                alloc_p[0] = (p + max(n, 16) + 31) & ~15
                u.reg_write(UC_ARM64_REG_X0, p)
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off == 0xB4BD40:  # operator delete
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

        alloc_p = [HEAP + 0x1000]
        mu.hook_add(UC_HOOK_CODE, hook_serial)
        out_model = STACK + 0x10000
        out_ser = STACK + 0x10040
        mu.mem_write(out_model, struct.pack("<QQ", out_model + 0x10, 0) + b"\x00" * 16)
        mu.mem_write(out_ser, struct.pack("<QQ", out_ser + 0x10, 0) + b"\x00" * 16)
        mu.reg_write(UC_ARM64_REG_SP, STACK + 0x20000)
        mu.reg_write(UC_ARM64_REG_X0, out_model)
        mu.reg_write(UC_ARM64_REG_X1, out_ser)
        mu.reg_write(UC_ARM64_REG_LR, RET_SENTINEL)
        mu.emu_start(BASE + 0x16C670, RET_SENTINEL, timeout=1_000_000, count=200_000)
        p, ln = struct.unpack("<QQ", bytes(mu.mem_read(out_ser, 16)))
        got = bytes(mu.mem_read(p, ln))
        assert not events["sd_snoop"], "PRODINFO snoop was NOT bypassed!"
        assert got == test_serial, f"Expected {test_serial!r}, got {got!r}"
    print("[PASS] Group 2a: get_console_serial respects Exosphere blanking & skips PRODINFO/hardcoded swap")

    # Verify build_deviceid_auth jumps directly from 0x9f6a0 -> 0x9f7f0 with x23 = 0xc0c000
    mu = make_vm()
    mu.reg_write(UC_ARM64_REG_SP, STACK + 0x20000)
    mu.reg_write(UC_ARM64_REG_X8, STACK + 0x10000)
    def hook_auth(u, addr, sz, _):
        off = addr - BASE
        if off == 0x16C670:  # stub get_console_serial
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
        elif off == AUTH_AFTER_SERIAL:
            u.emu_stop()
    mu.hook_add(UC_HOOK_CODE, hook_auth)
    mu.emu_start(BASE + 0x9F660, BASE + 0x9FA00, timeout=1_000_000, count=10_000)
    assert mu.reg_read(UC_ARM64_REG_PC) == BASE + AUTH_AFTER_SERIAL
    assert mu.reg_read(UC_ARM64_REG_X23) == BASE + 0xC0C000
    print("[PASS] Group 2b: build_deviceid_auth bypasses hardcoded serial check (x23=0xc0c000 preserved)")

    # -------------------------------------------------------------------------
    # TEST 2 (Group 3): DeviceID HTTP consent popup (ALLOW, BLOCK, NULL-window)
    # -------------------------------------------------------------------------
    for label, btn, win_ok, exp_target, exp_retry in (
        ("ALLOW via (+)", BTN_PLUS, True, DEVICEID_RETRY_ADDR, 1),
        ("BLOCK via (B)", BTN_B, True, DEVICEID_BLOCK_ADDR, 0),
        ("NULL window fail-closed", BTN_PLUS, False, DEVICEID_BLOCK_ADDR, 0),
    ):
        mu = make_vm()
        mu.mem_write(WIN_MEM, struct.pack("<Q", WIN_MEM + 0x100 if win_ok else 0))
        popups = []
        repaints = [0]

        def hook_devid(u, addr, sz, _):
            off = addr - BASE
            if off == GET_WIN_FN:
                u.reg_write(UC_ARM64_REG_X0, WIN_MEM)
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off == SHOW_POPUP_FN:
                mp, ml = struct.unpack("<QQ", bytes(u.mem_read(u.reg_read(UC_ARM64_REG_X1), 16)))
                popups.append(bytes(u.mem_read(mp, ml)))
                u.mem_write(u.reg_read(UC_ARM64_REG_X8), struct.pack("<B7xQ", 1, btn))
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off == REPAINT_WIN_FN:
                repaints[0] += 1
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off in (DEVICEID_RETRY_ADDR, DEVICEID_BLOCK_ADDR):
                u.emu_stop()

        mu.hook_add(UC_HOOK_CODE, hook_devid)
        for _call in range(2):
            sp_in = STACK + 0x20000
            mu.mem_write(sp_in + 0x70, struct.pack("<I", 0))
            mu.reg_write(UC_ARM64_REG_SP, sp_in)
            mu.reg_write(UC_ARM64_REG_X21, 1)
            mu.reg_write(UC_ARM64_REG_X29, 0x2929)
            mu.reg_write(UC_ARM64_REG_X30, 0x3030)
            mu.emu_start(BASE + DEVICEID_HOOK, BASE + DEVICEID_HOOK + 0x1000000, count=50_000)
            assert mu.reg_read(UC_ARM64_REG_PC) - BASE == exp_target
            assert mu.reg_read(UC_ARM64_REG_SP) == sp_in
            assert struct.unpack("<I", bytes(mu.mem_read(sp_in + 0x70, 4)))[0] == exp_retry
        assert len(popups) == (1 if win_ok else 0), f"{label}: unexpected popup count {len(popups)}"
        assert repaints[0] == (1 if win_ok else 0)
    print("[PASS] Group 3: DeviceID popup (ALLOW/BLOCK/NULL + session caching)")

    # -------------------------------------------------------------------------
    # TEST 3 (Group 4): YAML startup loader (en, ar, ru, and missing-YAML fallback)
    # -------------------------------------------------------------------------
    en_bin = (output_dir / "translations" / "translation_en.bin").read_bytes()
    ar_bin = (output_dir / "translations" / "translation_ar.bin").read_bytes()
    yaml_en = (output_dir / "languages.yaml").read_bytes()

    def build_vfs(yaml_bytes: bytes | None) -> dict[str, bytes]:
        vfs = {
            "sdmc:/switch/DBI/translation.bin": en_bin,
            "sdmc:/switch/DBI/translations/translation_en.bin": en_bin,
            "sdmc:/switch/DBI/translations/translation_ar.bin": ar_bin,
            "sdmc:/switch/DBI/translations/translation_de.bin": (
                output_dir / "translations" / "translation_de.bin"
            ).read_bytes(),
        }
        if yaml_bytes is not None:
            vfs["sdmc:/switch/DBI/languages.yaml"] = yaml_bytes
        return vfs

    def attach_vfs_and_alloc(mu, vfs: dict[str, bytes], heap_cursor: list[int], open_files: dict):
        def alloc(size: int) -> int:
            p = heap_cursor[0]
            heap_cursor[0] = (p + max(size, 16) + 15) & ~15
            return p

        def hook_common(u, addr, sz, _):
            off = addr - BASE
            if off == READ_FILE_RAW_FN:
                plen = u.reg_read(UC_ARM64_REG_X0)
                pptr = u.reg_read(UC_ARM64_REG_X1)
                sret = u.reg_read(UC_ARM64_REG_X8)
                path = bytes(u.mem_read(pptr, plen)).decode("utf-8", errors="replace")
                data = vfs.get(path, b"")
                if len(data) <= 15:
                    u.mem_write(sret, struct.pack("<QQ", sret + 0x10, len(data)) + data.ljust(16, b"\x00"))
                else:
                    buf = alloc(len(data) + 1)
                    u.mem_write(buf, data + b"\x00")
                    u.mem_write(sret, struct.pack("<QQQQ", buf, len(data), len(data), 0))
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off == STD_STR_DTOR_FN:
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off == OP_NEW_FN:
                u.reg_write(UC_ARM64_REG_X0, alloc(u.reg_read(UC_ARM64_REG_X0)))
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off == FOPEN_FN:
                path = read_cstr(u, u.reg_read(UC_ARM64_REG_X0)).decode("utf-8")
                mode = read_cstr(u, u.reg_read(UC_ARM64_REG_X1)).decode("utf-8")
                fd = 0x100 + len(open_files)
                open_files[fd] = {"path": path, "mode": mode, "buf": bytearray()}
                u.reg_write(UC_ARM64_REG_X0, fd)
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off == FWRITE_FN:
                ptr = u.reg_read(UC_ARM64_REG_X0)
                size = u.reg_read(UC_ARM64_REG_X1)
                nmemb = u.reg_read(UC_ARM64_REG_X2)
                fd = u.reg_read(UC_ARM64_REG_X3)
                chunk = bytes(u.mem_read(ptr, size * nmemb))
                open_files[fd]["buf"].extend(chunk)
                u.reg_write(UC_ARM64_REG_X0, nmemb)
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
            elif off == FCLOSE_FN:
                fd = u.reg_read(UC_ARM64_REG_X0)
                rec = open_files[fd]
                vfs[rec["path"]] = bytes(rec["buf"])
                u.reg_write(UC_ARM64_REG_X0, 0)
                u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

        mu.hook_add(UC_HOOK_CODE, hook_common)

    for case_name, ybytes, expect_magic, expect_first_bytes in (
        ("default en", yaml_en, b"DBITRANS", en_bin[:32]),
        ("Arabic ar", yaml_en.replace(b"selected_language: en", b"selected_language: ar"), b"DBITRANS", ar_bin[:32]),
        ("Russian ru (native)", yaml_en.replace(b"selected_language: en", b"selected_language: ru"), b"\x00" * 8, None),
        ("missing YAML fallback", None, b"DBITRANS", en_bin[:32]),
    ):
        mu = make_vm()
        vfs = build_vfs(ybytes)
        attach_vfs_and_alloc(mu, vfs, [HEAP + 0x1000], {})
        mu.reg_write(UC_ARM64_REG_SP, STACK + 0x20000)
        mu.reg_write(UC_ARM64_REG_LR, RET_SENTINEL)
        mu.emu_start(BASE + ENSURE_LOADED_FN, RET_SENTINEL, timeout=1_000_000, count=2_000_000)
        magic = bytes(mu.mem_read(BASE + DBIPATCHER_STATE + 0x10, 8))
        tbl_ptr = struct.unpack("<Q", bytes(mu.mem_read(BASE + DBIPATCHER_STATE + 0x18, 8)))[0]
        assert magic == expect_magic, f"{case_name}: magic={magic!r}, expected={expect_magic!r}"
        if expect_first_bytes is not None:
            assert tbl_ptr != 0
            assert bytes(mu.mem_read(tbl_ptr, 32)) == expect_first_bytes
        else:
            retry_cnt = struct.unpack("<I", bytes(mu.mem_read(BASE + DBIPATCHER_STATE + 4, 4)))[0]
            assert tbl_ptr == 0 and retry_cnt >= 30, f"ru should set retry>=30, got {retry_cnt}"
    print("[PASS] Group 4: YAML startup loader (en, ar, ru native, missing-YAML fallback)")

    # -------------------------------------------------------------------------
    # TEST 4 (Group 5a): Main Menu hook appends "Language" right after "DBI Settings"
    # -------------------------------------------------------------------------
    mu = make_vm()
    attach_vfs_and_alloc(mu, build_vfs(yaml_en), [HEAP + 0x1000], {})
    added_items = []
    constructed = []

    def hook_menu(u, addr, sz, _):
        off = addr - BASE
        if off == MAIN_MENU_ADD_FN:
            menu_ptr = u.reg_read(UC_ARM64_REG_X0)
            uptr_ptr = u.reg_read(UC_ARM64_REG_X1)
            item_ptr = struct.unpack("<Q", bytes(u.mem_read(uptr_ptr, 8)))[0]
            added_items.append((menu_ptr, item_ptr))
            u.mem_write(uptr_ptr, struct.pack("<Q", 0))
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
        elif off == MENU_ITEM_CTOR_FN:
            item_p = u.reg_read(UC_ARM64_REG_X0)
            lp, ll = struct.unpack("<QQ", bytes(u.mem_read(u.reg_read(UC_ARM64_REG_X1), 16)))
            lbl = bytes(u.mem_read(lp, ll))
            fn_ptr = u.reg_read(UC_ARM64_REG_X2)
            mgr, inv = struct.unpack("<QQ", bytes(u.mem_read(fn_ptr + 0x10, 16)))
            style = u.reg_read(UC_ARM64_REG_X3)
            constructed.append((item_p, lbl, mgr - BASE, inv - BASE, style))
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
        elif off in (STD_FUNC_DTOR_FN, UPTR_MENU_DTOR_FN):
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

    mu.hook_add(UC_HOOK_CODE, hook_menu)
    fake_menu = HEAP + 0x200
    fake_settings_uptr = STACK + 0x10000
    mu.mem_write(fake_settings_uptr, struct.pack("<Q", 0xCAFEBABE))
    mu.reg_write(UC_ARM64_REG_SP, STACK + 0x20000)
    mu.reg_write(UC_ARM64_REG_X0, fake_menu)
    mu.reg_write(UC_ARM64_REG_X1, fake_settings_uptr)
    mu.reg_write(UC_ARM64_REG_X23, HEAP + 0x500)
    mu.reg_write(UC_ARM64_REG_LR, RET_SENTINEL)
    mu.emu_start(BASE + meta["main_menu_add_hook"], RET_SENTINEL, timeout=1_000_000, count=50_000)
    assert len(added_items) == 2 and added_items[0] == (fake_menu, 0xCAFEBABE)
    assert len(constructed) == 1
    item_p, lbl, mgr_off, inv_off, style_p = constructed[0]
    assert lbl == b"Language"
    assert mgr_off == STD_FUNC_MGR_FN
    assert inv_off == meta["language_picker_cb"]
    assert style_p == HEAP + 0x500 + 0x1A8
    assert added_items[1] == (fake_menu, item_p)
    print("[PASS] Group 5a: Main Menu hook adds 'DBI Settings' followed by 'Language' button")

    # -------------------------------------------------------------------------
    # TEST 5 (Group 5b): Language picker UI -> navigate (R, R, Down -> Arabic `ar`), press A
    #   Verifies:
    #     1. Paginated modal text renders all 3 pages cleanly with '>' cursor & '*' active.
    #     2. Pressing A rewrites sdmc:/switch/DBI/languages.yaml with `selected_language: ar`
    #        while preserving every other line and comment verbatim.
    #     3. DBIPatcher live translation table hot-reloads to Arabic (`ar_bin`).
    # -------------------------------------------------------------------------
    mu = make_vm()
    vfs = build_vfs(yaml_en)
    attach_vfs_and_alloc(mu, vfs, [HEAP + 0x1000], {})
    mu.mem_write(WIN_MEM, struct.pack("<Q", WIN_MEM + 0x100))

    # First boot ensure_loaded with English
    mu.reg_write(UC_ARM64_REG_SP, STACK + 0x20000)
    mu.reg_write(UC_ARM64_REG_LR, RET_SENTINEL)
    mu.emu_start(BASE + ENSURE_LOADED_FN, RET_SENTINEL, timeout=1_000_000, count=2_000_000)
    tbl_before = struct.unpack("<Q", bytes(mu.mem_read(BASE + DBIPATCHER_STATE + 0x18, 8)))[0]
    assert bytes(mu.mem_read(tbl_before, 32)) == en_bin[:32]

    # Now invoke language_picker_cb:
    # Start at index 0 (en) -> R (idx 12) -> R (idx 24, zhtw) -> Down (idx 25, ar!) -> A (Apply) -> A (dismiss confirm)
    btn_script = [BTN_R, BTN_R, BTN_DOWN, BTN_A, BTN_A]
    seen_modals = []

    def hook_picker(u, addr, sz, _):
        off = addr - BASE
        if off == GET_WIN_FN:
            u.reg_write(UC_ARM64_REG_X0, WIN_MEM)
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
        elif off == SHOW_POPUP_FN:
            mp, ml = struct.unpack("<QQ", bytes(u.mem_read(u.reg_read(UC_ARM64_REG_X1), 16)))
            seen_modals.append(bytes(u.mem_read(mp, ml)).decode("utf-8"))
            btn = btn_script.pop(0) if btn_script else BTN_B
            u.mem_write(u.reg_read(UC_ARM64_REG_X8), struct.pack("<B7xQ", 1, btn))
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))
        elif off == REPAINT_WIN_FN:
            u.reg_write(UC_ARM64_REG_PC, u.reg_read(UC_ARM64_REG_LR))

    mu.hook_add(UC_HOOK_CODE, hook_picker)
    mu.reg_write(UC_ARM64_REG_SP, STACK + 0x20000)
    mu.reg_write(UC_ARM64_REG_LR, RET_SENTINEL)
    mu.emu_start(BASE + meta["language_picker_cb"], RET_SENTINEL, timeout=2_000_000, count=5_000_000)

    assert mu.reg_read(UC_ARM64_REG_W0) == 0, "Callback must return 0 (stay in Main Menu)"
    assert len(seen_modals) == 5, f"Expected 4 picker frames + 1 confirmation, got {len(seen_modals)}"
    assert "Select Language (Page 1/3)" in seen_modals[0] and " > * English (US) [en]" in seen_modals[0]
    assert "Select Language (Page 2/3)" in seen_modals[1]
    assert "Select Language (Page 3/3)" in seen_modals[2]
    assert " >   العربية (Arabic) [ar]" in seen_modals[3]
    assert "Language saved to languages.yaml!" in seen_modals[4]

    # Verify languages.yaml was updated cleanly with zero collateral diffs
    updated_yaml = vfs["sdmc:/switch/DBI/languages.yaml"]
    expected_yaml = yaml_en.replace(b"selected_language: en", b"selected_language: ar")
    assert updated_yaml == expected_yaml, "Updated languages.yaml mismatch!"

    # Verify DBIPatcher live translation table hot-reloaded to Arabic!
    tbl_after = struct.unpack("<Q", bytes(mu.mem_read(BASE + DBIPATCHER_STATE + 0x18, 8)))[0]
    assert bytes(mu.mem_read(tbl_after, 32)) == ar_bin[:32], "Live hot-reload did not load Arabic table!"
    print("[PASS] Group 5b: Language picker navigated 3 pages, updated languages.yaml (en -> ar), and hot-reloaded DBITRNS!")

    # Verify Group 6 NACP title metadata
    nacp_abs = meta["nacp_abs"]
    got_title = patched[nacp_abs : nacp_abs + NACP_TITLE_MAX].split(b"\x00", 1)[0].decode("utf-8")
    assert got_title and got_title != "DBI", f"Unexpected NACP title: {got_title!r}"
    print(f"[PASS] Group 6: NACP Homebrew Menu title verified as {got_title!r}")


# =============================================================================
# 8. CLI ENTRY POINT
# =============================================================================

def print_patch_list() -> None:
    print("DBI 921 Patch Registry")
    print("=" * 72)
    for grp in PATCH_GROUPS:
        print(f"\n[{grp.group_id}] {grp.title}")
        print(f"  {grp.summary}")
        for p in grp.patches:
            print(f"  - {p.offset:#08x} ({p.name}): {p.comment}")


def main() -> int:
    ws = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Single-file DBI 921 privacy, DeviceID consent & YAML multi-language patcher."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Optional local base DBI 921 NRO (if omitted, downloads & SHA-256 verifies from rashevskyv/DBIPatcher release 921)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=ws / ".cache",
        help="Cache directory for downloaded upstream NRO & CSVs (default: .cache)",
    )
    parser.add_argument(
        "--no-download",
        action="store_true",
        help="Disable downloading upstream NRO/CSVs from GitHub (require local files only).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ws / "dbi-output",
        help="Output directory for patched DBI.nro, languages.yaml & translations/ (default: dbi-output)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run offline Capstone + Unicorn ARM64 verification across all 6 patch groups.",
    )
    parser.add_argument(
        "--rebuild-translations",
        action="store_true",
        help="Recompile translations/translation_*.bin from edited translations/*.yaml files.",
    )
    parser.add_argument(
        "--app-name",
        type=str,
        default=DEFAULT_APP_NAME,
        help=f"Homebrew Menu NACP application title (default: '{DEFAULT_APP_NAME}')",
    )
    parser.add_argument(
        "--list-patches",
        action="store_true",
        help="Print the documented list of patch groups and exit.",
    )
    args = parser.parse_args()

    if args.list_patches:
        print_patch_list()
        return 0

    args.output_dir.mkdir(parents=True, exist_ok=True)
    csv_dirs = [
        ws / "extra-translations",
        ws / "translations",
        ws / "dbi-analysis" / "source-translations",
        ws / "dbi-analysis" / "extra-translations",
    ]

    if args.rebuild_translations:
        counts = build_all_translations(
            args.output_dir, csv_dirs, args.cache_dir, from_yaml=True, allow_download=False
        )
        print(f"Rebuilt {len(counts) - 1} binary translation tables from YAML in {args.output_dir / 'translations'}")
        return 0

    base_nro = resolve_base_nro(args.input, args.cache_dir, allow_download=not args.no_download)

    print_patch_list()
    print("\n" + "=" * 72)
    print(f"Base NRO   : {base_nro}")
    print("Building 35-language YAML catalog & DBITRNS v3 translation tables...")
    counts = build_all_translations(
        args.output_dir, csv_dirs, args.cache_dir, from_yaml=False, allow_download=not args.no_download
    )
    print(f"  Generated {args.output_dir / 'languages.yaml'} ({len(LANGUAGES)} languages, default: en)")
    print(f"  Generated {len(counts) - 1} YAML dictionaries + DBITRNS v3 .bin tables in {args.output_dir / 'translations'}")

    print(f"\nApplying all 6 patch groups to DBI 921 NRO (NACP title: '{args.app_name}')...")
    raw = base_nro.read_bytes()
    patched, meta = apply_all_patches(raw, app_name=args.app_name)
    out_nro = args.output_dir / "DBI.nro"
    out_nro.write_bytes(patched)
    out_sha = hashlib.sha256(patched).hexdigest()
    print(f"  Wrote {out_nro} ({len(patched):,} bytes, SHA-256: {out_sha})")
    print(f"  Cave 1 used: {meta['cave1_total']} / {CAVE1_END - CAVE1_ADDR} bytes")
    print(f"  Cave 2 used: {meta['cave2_total']} / {CAVE2_END - CAVE2_ADDR} bytes")

    if args.verify:
        print("\nRunning offline Capstone + Unicorn ARM64 verification (zero networking)...")
        verify_patched_nro(patched, meta, args.output_dir)
        print("\nALL VERIFICATION CHECKS PASSED!")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
