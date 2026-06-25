"""
Ingest and normalize raw text from an input file.
"""

import re
import unicodedata
from pathlib import Path


MAX_INPUT_BYTES = 500_000  # 500 KB hard cap


def load_and_normalize(path: str) -> str:
    """
    Read a text file and return a normalized string suitable for downstream
    processing.  Raises ValueError on oversized or unreadable input.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    raw_bytes = file_path.read_bytes()
    if len(raw_bytes) > MAX_INPUT_BYTES:
        raise ValueError(
            f"Input file is {len(raw_bytes):,} bytes, exceeding the "
            f"{MAX_INPUT_BYTES:,}-byte limit."
        )

    text = raw_bytes.decode("utf-8", errors="replace")
    text = _normalize_unicode(text)
    text = _collapse_whitespace(text)
    return text


def _normalize_unicode(text: str) -> str:
    # NFC normalization collapses lookalike characters and composed forms
    return unicodedata.normalize("NFC", text)


def _collapse_whitespace(text: str) -> str:
    # Normalize line endings, then collapse runs of blank lines to one
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n{3,}", "\n\n", text)
    # Strip trailing whitespace on each line
    lines = [line.rstrip() for line in text.splitlines()]
    return "\n".join(lines).strip()
