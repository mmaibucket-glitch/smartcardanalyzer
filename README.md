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
- **Guided APDU builder** (Console tab) — build commands from presets with plain-language field hints instead of raw hex
- **Status-word aware exchanges** — automatic GET RESPONSE chaining after 61XX and Le retry after 6CXX
- **Safe mode** (on by default) — blocks card-modifying commands in the Console, Script and Fuzz tabs; shows PIN retry countdown banners on 63CX; toggleable from both the Console and Fuzz tabs
- **Plain-language failure diagnosis** — distinguishes service-down / no-reader / no-card states and translates PC/SC error codes into fix hints ("Another program is using this reader...", "run `sudo systemctl start pcscd`", ...)
- **Next-step guidance** — after identification, the Inspector shows a "Try next" list of safe, card-type-specific suggestions (also echoed into the Console log)
- **Response TLV decoding** — one click decodes the last response as TLV (FCI, EF.DIR, GET DATA, ...) with a raw fallback view
- **Getting Started tab** — APDUs in five minutes, searchable status-word cheat sheet, glossary, and a guided walkthrough of the app
- **Scripting mode** (Script tab): run gscriptor-style `.gscl` scripts — one APDU in hex per line, `#` comments, optional per-step delay and stop-on-error; open and save scripts
- **Prebuilt script library**: bundled, commented scripts (SELECT MF, EF.DIR, READ BINARY, VERIFY/CHANGE PIN templates, GET DATA, ...) loadable with one double-click
- **Fuzzing mode** (Fuzz tab): deterministic mutation fuzzing of a seed APDU, or protocol-aware generation within valid instruction space; notable-SW highlighting and reproducible RNG seeds

## Setup

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
