"""
Safety checks run before the text reaches the LLM.

Two categories:
  1. Prompt injection — adversarial instructions embedded in the report.
  2. Sensitive data — credentials, keys, or tokens that should not be
     forwarded to an external API without analyst review.

These checks are purely deterministic (regex).  No LLM involvement.
"""

import re
from schemas import SafetyFinding

# ---------------------------------------------------------------------------
# Prompt-injection patterns
# ---------------------------------------------------------------------------
# Phrases that attempt to override, ignore, or hijack LLM system instructions.
_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "ignore-instructions"),
    (r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?", "disregard-instructions"),
    (r"forget\s+(everything|all)\s+(you|i)\s+(know|said|told)", "forget-instructions"),
    (r"you\s+are\s+now\s+(a\s+)?(different|new|evil|hacked)", "persona-override"),
    (r"act\s+as\s+(if\s+you\s+are\s+|an?\s+)?(?:unrestricted|jailbroken|DAN)", "jailbreak-persona"),
    (r"new\s+system\s+prompt\s*:", "system-prompt-injection"),
    (r"<\s*system\s*>", "system-tag-injection"),
    (r"\[\s*INST\s*\]", "instruction-tag-injection"),
    (r"override\s+(the\s+)?(system|safety|content)\s+(prompt|filter|policy)", "override-system"),
    (r"do\s+not\s+follow\s+(your\s+)?(rules|guidelines|instructions)", "bypass-rules"),
    (r"reveal\s+(your\s+)?(system\s+prompt|instructions|prompt)", "prompt-exfiltration"),
    (r"translate\s+the\s+above\s+into", "translation-exfil"),
    (r"repeat\s+(everything|the\s+above|what\s+i\s+said)\s+verbatim", "verbatim-exfil"),
]

# ---------------------------------------------------------------------------
# Sensitive-data patterns
# ---------------------------------------------------------------------------
_SENSITIVE_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, label, severity)
    (
        r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+",
        "plaintext-password",
        "high",
    ),
    (
        r"(?i)(api[_\-\s]?key|apikey)\s*[:=]\s*[A-Za-z0-9\-_]{16,}",
        "api-key",
        "high",
    ),
    (
        r"(?i)(secret[_\-\s]?key|secret)\s*[:=]\s*[A-Za-z0-9\-_/+]{16,}",
        "secret-key",
        "high",
    ),
    (
        r"(?i)(bearer|token)\s+[A-Za-z0-9\-_.~+/]+=*",
        "bearer-token",
        "high",
    ),
    (
        r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        "private-key-pem",
        "high",
    ),
    (
        r"(?i)aws[_\-\s]?(access[_\-\s]?key[_\-\s]?id|secret[_\-\s]?access[_\-\s]?key)\s*[:=]\s*[A-Za-z0-9/+]{16,}",
        "aws-credential",
        "high",
    ),
    (
        r"AKIA[0-9A-Z]{16}",
        "aws-access-key-id",
        "high",
    ),
    (
        r"(?i)(connection[_\-\s]?string|connstr)\s*[:=]\s*\S+",
        "connection-string",
        "medium",
    ),
    (
        r"(?i)ssh-rsa\s+[A-Za-z0-9+/]{40,}",
        "ssh-public-key",
        "medium",
    ),
    (
        r"\b\d{3}-\d{2}-\d{4}\b",
        "ssn-pattern",
        "high",
    ),
]


def _excerpt(text: str, match: re.Match, window: int = 60) -> str:
    start = max(0, match.start() - window)
    end = min(len(text), match.end() + window)
    raw = text[start:end].replace("\n", " ")
    return f"...{raw}..."


def run_safety_checks(text: str) -> list[SafetyFinding]:
    findings: list[SafetyFinding] = []

    for pattern, label in _INJECTION_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            findings.append(
                SafetyFinding(
                    category="prompt_injection",
                    matched_pattern=label,
                    excerpt=_excerpt(text, m),
                    severity="high",
                )
            )

    for pattern, label, severity in _SENSITIVE_PATTERNS:
        for m in re.finditer(pattern, text):
            findings.append(
                SafetyFinding(
                    category="sensitive_data",
                    matched_pattern=label,
                    excerpt=_redact(text, m),
                    severity=severity,
                )
            )

    return findings


def _redact(text: str, match: re.Match, window: int = 40) -> str:
    """Show context but replace the matched value with [REDACTED]."""
    start = max(0, match.start() - window)
    end = min(len(text), match.end() + window)
    prefix = text[start:match.start()].replace("\n", " ")
    suffix = text[match.end():end].replace("\n", " ")
    return f"...{prefix}[REDACTED]{suffix}..."
