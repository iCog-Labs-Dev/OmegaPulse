from __future__ import annotations

import re

# Match whole field names, including vendor/environment prefixes. Values are
# intentionally removed regardless of whether they resemble a known provider key.
_FIELD = r"[A-Za-z0-9_-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)[A-Za-z0-9_-]*"
_PATTERNS = (
    (re.compile(r"(?i)((?:[\"']?)(?:proxy-)?authorization(?:[\"']?)\s*[:=]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|(?:basic|bearer|token)\s+[^\s,;]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?<![\w-])[\"']?" + _FIELD + r"[\"']?\s*[:=]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;&]+)"), r"\1[REDACTED]"),
    # Telegram URLs concatenate 'bot' and the numeric token ID.
    (re.compile(r"(?<![0-9])[0-9]{6,12}:[A-Za-z0-9_-]{20,}"), "[REDACTED]"),
    (re.compile(r"(?<![A-Za-z0-9_-])(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|github_pat_[A-Za-z0-9_]{12,})"), "[REDACTED]"),
    (re.compile(r"(?i)(https?://[^\s/:@]+:)[^\s/@]+(@)"), r"\1[REDACTED]\2"),
)


def redact(text: str) -> str:
    """Best-effort removal of recognizable credentials from one log record."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
