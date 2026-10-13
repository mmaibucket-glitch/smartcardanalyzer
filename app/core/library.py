"""Discovery and loading of the bundled prebuilt scripts in the app.library package."""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources

_PACKAGE = "app.library"
_EXTENSION = ".gscl"
_HEADER_PATTERN = re.compile(r"^#\s*(description|category)\s*:\s*(.+?)\s*$", re.IGNORECASE)


@dataclass
class ScriptMeta:
    """One library script: its filename stem, one-line description, and category."""

    name: str
    description: str
    category: str


def list_scripts() -> list[ScriptMeta]:
    """Return metadata for every bundled .gscl script, grouped by category."""
    metas: list[ScriptMeta] = []
    for entry in resources.files(_PACKAGE).iterdir():
        if not entry.is_file() or not entry.name.endswith(_EXTENSION):
            continue
        text = entry.read_text(encoding="utf-8")
        metas.append(
            ScriptMeta(
                name=entry.name[: -len(_EXTENSION)],
                description=_header_value(text, "description"),
                category=_header_value(text, "category") or "general",
            )
        )
    metas.sort(key=lambda meta: (meta.category, meta.name))
    return metas


def load_script_text(name: str) -> str:
    """Return the text of one library script, addressed by filename stem."""
    stem = name[: -len(_EXTENSION)] if name.endswith(_EXTENSION) else name
    if not stem or "/" in stem or "\\" in stem or ".." in stem:
        raise FileNotFoundError(f"Unknown library script: {name!r}")
    entry = resources.files(_PACKAGE).joinpath(f"{stem}{_EXTENSION}")
    if not entry.is_file():
        raise FileNotFoundError(f"Unknown library script: {name!r}")
    return entry.read_text(encoding="utf-8")


def _header_value(text: str, key: str) -> str:
    for line in text.splitlines():
        match = _HEADER_PATTERN.match(line)
        if match and match.group(1).lower() == key:
            return match.group(2).strip()
    return ""
