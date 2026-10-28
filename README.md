# Smartcard Tool

A cross-platform PC/SC and APDU communication tool with a graphical interface — a friendlier alternative to gscriptor. Send APDUs to smart cards, decode responses and status words, without needing prior PC/SC expertise.

Built with Python, [pyscard](https://pypi.org/project/pyscard/) and PySide6 (Qt).

## Features

- Detect and connect to PC/SC readers on Linux, Windows and macOS
- Send APDUs as hex (tolerant of spacing, case, `0x` prefixes and separators)
- Automatic ISO 7816-4 status word decoding (9000, 61XX, 6A82, ...)
- Color-coded request/response log
- **Automatic card identification on connect** — decodes the ATR, reads EF.DIR and matches applications against well-known AIDs (EMV, OpenPGP, PIV, ePassport, ...)
- **Card inspector** (Inspector tab) — one-click read-only scan of what is on the card, with TLV-decoded application details and a copy-as-SELECT-script helper
- **Read accessible data** (Inspector tab) — after identification, read application metadata, available payment-card records and selected counters without a PIN; browse decoded fields, raw bytes and status words, with Stop and copy-selected-data controls
- **Guided APDU builder** (Console tab) — build commands from presets with plain-language field hints instead of raw hex
- **Status-word aware exchanges** — Console (when enabled) and identification chain GET RESPONSE after 61XX and retry once with corrected Le after 6CXX; Script and Fuzz send each supplied or generated APDU as-is
- **Safe mode** (on by default) — blocks known card-modifying instruction codes in the Console, Script and Fuzz tabs; authentication and unknown commands remain available, so review commands before sending; the Console shows PIN retry countdown banners on 63CX
- **Plain-language failure diagnosis** — distinguishes service-down / no-reader / no-card states and translates PC/SC error codes into fix hints ("Another program is using this reader...", "run `sudo systemctl start pcscd`", ...)
- **Next-step guidance** — after identification, the Inspector shows a "Try next" list of safe, card-type-specific suggestions (also echoed into the Console log)
- **Response TLV decoding** — one click decodes the last response as TLV (FCI, EF.DIR, GET DATA, ...) with a raw fallback view
- **Getting Started tab** — APDUs in five minutes, searchable status-word cheat sheet, glossary, and a guided walkthrough of the app
- **Scripting mode** (Script tab): run gscriptor-style `.gscl` scripts — one APDU in hex per line, `#` comments, optional per-step delay and stop-on-error; open and save scripts
- **Prebuilt script library**: bundled, commented scripts (SELECT MF, EF.DIR, READ BINARY, VERIFY/CHANGE PIN templates, GET DATA, ...) loadable with one double-click
- **Fuzzing mode** (Fuzz tab): deterministic mutation fuzzing of a seed APDU, or protocol-aware generation within valid instruction space; notable-SW highlighting and reproducible RNG seeds

## Setup

### Reading card data

Connect in the Console, open **Inspector**, then choose **Read accessible data** after identification completes. The tree shows each command's response, decoded TLV fields (including account number, name and expiry when returned), and its raw bytes. Select rows and use **Copy selected data** to copy them. Results remain in memory and are cleared on disconnect or card-session changes; the scan does not automatically save a card dump.

For recognized payment applications, the scan uses SELECT, GET RESPONSE, a small GET DATA tag list, and bounded READ RECORD requests. It never sends PIN verification, authentication, GET PROCESSING OPTIONS, GENERATE AC, write, or fuzz commands. It stops probing a file when the card reports it absent or access-denied. Other application types currently return SELECT metadata only.

This is a best-effort view of accessible data, not a complete card image. It does not retrieve private keys, PINs or protected records. Some cards require transaction initialization even to expose otherwise public records; the scanner deliberately does not initialize a transaction. See the scan summary for cancellation, unsupported commands and limits. Returned fields may contain personal card details.

The scan checks SFIs 1–30 and records 1–16. Missing records (`6A83`) are skipped so later records can still be read; file-not-found, denied or unsupported status stops that file. A maximum of 512 physical exchanges includes automatic GET RESPONSE and Le corrections. Reaching any bound is reported; records outside the scan bounds are not probed.

### Installation

```bash
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m app
```

For a `smartcard-tool` launcher command, install the package editable: `pip install -e .`

### Platform notes

- Linux: a running `pcscd` daemon and pcsc-lite are required. Debian/Ubuntu: `sudo apt install pcscd pcsc-tools`. Fedora: `sudo dnf install pcsc-lite pcsc-lite-ccid`.
- Windows: the Smart Card service is built in; nothing extra to install.
- macOS: works with the native PC/SC framework.

### Linux without root or build tools

pyscard has no prebuilt Linux wheels, so `pip install pyscard` requires `swig`, `libpcsclite-dev` and Python dev headers. Without root, extract the distribution's prebuilt `python3-pyscard` package directly into the venv:

```bash
apt-get download python3-pyscard
dpkg -x python3-pyscard_*.deb pyscard-ext
cp -r pyscard-ext/usr/lib/python3/dist-packages/smartcard* .venv/lib/python3.12/site-packages/
```

## Roadmap

- Session trace export
