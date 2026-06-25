"""
Deterministic regex-based IOC extraction and deduplication.

Regex-confirmed IOCs carry higher confidence than LLM-only IOCs.
The merge() function reconciles the two sets.
"""

import re
from schemas import IOC, IOCType, ConfidenceLevel

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# RFC-1918 and loopback ranges that are almost never useful threat intel IOCs
_PRIVATE_IP_PATTERNS = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)"
)

_PATTERNS: dict[IOCType, re.Pattern] = {
    IOCType.IPV4: re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    IOCType.URL: re.compile(
        r"https?://[^\s\"'<>(){}\[\]\\,;]+"
    ),
    IOCType.DOMAIN: re.compile(
        # Lookahead/lookbehind keeps us from double-matching URLs
        r"(?<!//)"
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|info|biz|xyz|onion|top|club|site|online|tech|app|dev)\b"
        r"(?![^\s]*?://)",
    ),
    IOCType.SHA256: re.compile(r"\b[0-9a-fA-F]{64}\b"),
    IOCType.SHA1: re.compile(r"\b[0-9a-fA-F]{40}\b"),
    IOCType.MD5: re.compile(r"\b[0-9a-fA-F]{32}\b"),
    IOCType.EMAIL: re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
}

# TLDs that appear in domains but are clearly not threat IOCs
_ALLOWLISTED_DOMAINS = {
    "example.com", "example.org", "example.net",
    "localhost", "internal", "local",
}


def extract_iocs(text: str) -> list[IOC]:
    """Return a deduplicated list of IOCs found by regex."""
    seen: dict[str, IOC] = {}

    # Extract URLs first; domains inside URLs will be skipped below
    url_spans: list[tuple[int, int]] = []

    for m in _PATTERNS[IOCType.URL].finditer(text):
        val = m.group().rstrip(".,;:")
        url_spans.append((m.start(), m.end()))
        key = val.lower()
        if key not in seen:
            seen[key] = IOC(
                value=val,
                ioc_type=IOCType.URL,
                confidence=ConfidenceLevel.HIGH,
                regex_confirmed=True,
                source="regex",
            )

    for m in _PATTERNS[IOCType.IPV4].finditer(text):
        val = m.group()
        if _PRIVATE_IP_PATTERNS.match(val):
            continue
        key = val
        if key not in seen:
            seen[key] = IOC(
                value=val,
                ioc_type=IOCType.IPV4,
                confidence=ConfidenceLevel.HIGH,
                regex_confirmed=True,
                source="regex",
            )

    for m in _PATTERNS[IOCType.DOMAIN].finditer(text):
        # Skip if this position falls inside a URL we already captured
        if any(s <= m.start() < e for s, e in url_spans):
            continue
        val = m.group().lower().rstrip(".")
        if val in _ALLOWLISTED_DOMAINS:
            continue
        if val not in seen:
            seen[val] = IOC(
                value=val,
                ioc_type=IOCType.DOMAIN,
                confidence=ConfidenceLevel.HIGH,
                regex_confirmed=True,
                source="regex",
            )

    # Hashes — longer patterns first so a SHA256 isn't also flagged as MD5
    for ioc_type in (IOCType.SHA256, IOCType.SHA1, IOCType.MD5):
        for m in _PATTERNS[ioc_type].finditer(text):
            val = m.group().lower()
            if val not in seen:
                seen[val] = IOC(
                    value=val,
                    ioc_type=ioc_type,
                    confidence=ConfidenceLevel.HIGH,
                    regex_confirmed=True,
                    source="regex",
                )

    for m in _PATTERNS[IOCType.EMAIL].finditer(text):
        val = m.group().lower()
        if val not in seen:
            seen[val] = IOC(
                value=val,
                ioc_type=IOCType.EMAIL,
                confidence=ConfidenceLevel.HIGH,
                regex_confirmed=True,
                source="regex",
            )

    return list(seen.values())


def _infer_ioc_type(value: str) -> IOCType | None:
    """Best-effort type inference for LLM-suggested IOC strings."""
    v = value.strip()
    if _PATTERNS[IOCType.IPV4].fullmatch(v):
        return IOCType.IPV4
    if _PATTERNS[IOCType.SHA256].fullmatch(v):
        return IOCType.SHA256
    if _PATTERNS[IOCType.SHA1].fullmatch(v):
        return IOCType.SHA1
    if _PATTERNS[IOCType.MD5].fullmatch(v):
        return IOCType.MD5
    if _PATTERNS[IOCType.URL].match(v):
        return IOCType.URL
    if _PATTERNS[IOCType.EMAIL].fullmatch(v):
        return IOCType.EMAIL
    if _PATTERNS[IOCType.DOMAIN].fullmatch(v):
        return IOCType.DOMAIN
    return None


def merge_with_llm_iocs(
    regex_iocs: list[IOC], llm_candidates: list[str]
) -> list[IOC]:
    """
    Merge regex-confirmed IOCs with LLM-suggested candidates.

    Rules:
    - If LLM candidate already found by regex → mark source="both", keep HIGH confidence.
    - If LLM candidate is regex-valid but not yet in set → add as MEDIUM confidence.
    - If LLM candidate fails regex validation → add as LOW confidence with a note.
    - Deduplicate by normalised value.
    """
    merged: dict[str, IOC] = {ioc.value.lower(): ioc for ioc in regex_iocs}

    for raw in llm_candidates:
        val = raw.strip()
        key = val.lower()

        if key in merged:
            existing = merged[key]
            if existing.source == "regex":
                merged[key] = existing.model_copy(update={"source": "both"})
            continue

        ioc_type = _infer_ioc_type(val)
        if ioc_type is not None:
            merged[key] = IOC(
                value=val,
                ioc_type=ioc_type,
                confidence=ConfidenceLevel.MEDIUM,
                regex_confirmed=True,
                source="llm",
            )
        else:
            # Cannot validate — still record it but flag as low confidence
            merged[key] = IOC(
                value=val,
                ioc_type=IOCType.DOMAIN,  # best guess; analyst must verify
                confidence=ConfidenceLevel.LOW,
                regex_confirmed=False,
                source="llm",
            )

    return list(merged.values())
