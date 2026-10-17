"""
tiny_input_sanitize v0.1.0
==========================

Zero-dependency, stdlib-only input sanitization for HTTP inputs, agent
tool arguments, and shell-bound strings.

The library is **allowlist-first**: it strips characters or replaces
patterns that are dangerous in the target context, then returns a
`SanitizationResult` containing the cleaned value, a list of applied
rules, and a confidence score (0.0-1.0) indicating how much of the
input was transformed.

It is **not** a substitute for context-aware output encoding (use
`html.escape`, parameterized SQL, `shlex.quote`). It is a fast
front-line filter that catches the obvious cases at the boundary so
deeply-nested code does not have to.

Public API:
    sanitize_text(value, *, context="html", allow=None, deny=None,
                  max_length=None, strip_controls=True) -> SanitizationResult
    sanitize_for_html(value, **kwargs) -> SanitizationResult
    sanitize_for_sql_literal(value, **kwargs) -> SanitizationResult
    sanitize_for_shell_arg(value, **kwargs) -> SanitizationResult
    sanitize_for_filename(value, **kwargs) -> SanitizationResult
    sanitize_for_log(value, **kwargs) -> SanitizationResult
    sanitize_for_jsonpath(value, **kwargs) -> SanitizationResult
    is_safe(value, *, context="html", threshold=0.95) -> bool
    SanitizationResult dataclass
    SanitizationContext enum

Contexts:
    html       - strip <, >, ", ', & and javascript: URLs
    sql        - escape ' and \\ and NUL byte (still use parameterized queries!)
    shell      - strip shell metacharacters ; & | ` $ ( ) > < !
    filename   - strip path separators and reserved names
    log        - strip ANSI escapes, NULs, control chars (preserves \\n \\r \\t)
    jsonpath   - strip $, ., [, ], *, ?, \\, quotes (for use as a path component)

Confidence score:
    1.0  - input was untouched (no rules matched)
    0.0  - entire input was removed (or replaced with placeholder)
    Otherwise: 1.0 - (transformed_chars / input_length)
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional


__version__ = "0.1.0"
__all__ = [
    "SanitizationContext",
    "SanitizationResult",
    "sanitize_text",
    "sanitize_for_html",
    "sanitize_for_sql_literal",
    "sanitize_for_shell_arg",
    "sanitize_for_filename",
    "sanitize_for_log",
    "sanitize_for_jsonpath",
    "is_safe",
]


class SanitizationContext(str, Enum):
    HTML = "html"
    SQL = "sql"
    SHELL = "shell"
    FILENAME = "filename"
    LOG = "log"
    JSONPATH = "jsonpath"


# HTML: < > " ' & plus javascript:/data: URI prefix
_HTML_TAG_RE = re.compile(r"[<>\"\'&]")
_HTML_URI_RE = re.compile(r"(?i)\b(javascript|data|vbscript):")

# SQL: NUL byte plus single quote, double quote, backslash
_SQL_NUL_RE = re.compile(r"\x00")
_SQL_QUOTE_RE = re.compile(r"['\"\\\\]")

# Shell: common metacharacters that should never appear in a single arg.
# Note: this is a back-line, not a full shell parser.
_SHELL_META_RE = re.compile(r"[;&|`$()><\!\n\r\x00]")

# Filename: path separators, NUL, control chars
_FILENAME_BAD_RE = re.compile(r"[\x00-\x1f\x7f/\\:*?\"<>|]")

# Log: ANSI escapes, NUL, control chars except \t \n \r
_LOG_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_LOG_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# JSONPath: path metacharacters used in $-syntax
_JSONPATH_META_RE = re.compile(r"[\$\.\[\]\*\?\\\"']")


# Reserved Windows filenames
_RESERVED_WINDOWS = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


@dataclass
class SanitizationResult:
    """Outcome of a sanitization pass."""
    value: str
    context: "SanitizationContext"
    applied_rules: list = field(default_factory=list)
    original_length: int = 0
    confidence: float = 1.0

    @property
    def is_clean(self) -> bool:
        """True if no transformation was applied."""
        return not self.applied_rules

    @property
    def was_truncated(self) -> bool:
        return "max_length" in self.applied_rules

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "context": self.context.value,
            "applied_rules": list(self.applied_rules),
            "original_length": self.original_length,
            "confidence": round(self.confidence, 3),
            "is_clean": self.is_clean,
            "was_truncated": self.was_truncated,
        }


def _confidence(original: str, transformed: str) -> float:
    if not original:
        return 1.0
    if not transformed:
        return 0.0
    # Diff at codepoint level, not bytes.
    orig_codepoints = list(original)
    trans_codepoints = list(transformed)
    n = min(len(orig_codepoints), len(trans_codepoints))
    prefix = 0
    while prefix < n and orig_codepoints[prefix] == trans_codepoints[prefix]:
        prefix += 1
    suffix = 0
    while (
        suffix < (n - prefix)
        and orig_codepoints[-1 - suffix] == trans_codepoints[-1 - suffix]
    ):
        suffix += 1
    surviving = prefix + suffix
    return max(0.0, min(1.0, surviving / len(orig_codepoints)))


def _apply_deny(value: str, deny, rules: list) -> str:
    """Strip individual characters present in deny."""
    chars = set(deny)
    if not chars:
        return value
    out = []
    for ch in value:
        if ch in chars:
            rules.append("deny_char")
        else:
            out.append(ch)
    return "".join(out)


def _apply_allow(value: str, allow, rules: list) -> str:
    """Strip any character not present in allow."""
    allowed = set(allow)
    if not allowed:
        return value
    out = []
    for ch in value:
        if ch in allowed:
            out.append(ch)
        else:
            rules.append("allow_filter")
    return "".join(out)


def _apply_max_length(value: str, max_length: int, rules: list) -> str:
    if len(value) > max_length:
        rules.append("max_length")
        return value[:max_length]
    return value


def _apply_strip_controls(value: str, rules: list, keep: str = "") -> str:
    out = []
    for ch in value:
        if ord(ch) < 32 or ord(ch) == 127:
            if ch in keep:
                out.append(ch)
            else:
                rules.append("strip_control")
        else:
            out.append(ch)
    return "".join(out)


def _sanitize_html(value: str, rules: list) -> str:
    if _HTML_TAG_RE.search(value):
        rules.append("html_chars")
        # Replace & first to avoid double-escaping
        value = value.replace("&", "&amp;")
        value = value.replace("<", "&lt;")
        value = value.replace(">", "&gt;")
        value = value.replace('"', "&quot;")
        value = value.replace("'", "&#x27;")
    if _HTML_URI_RE.search(value):
        rules.append("html_uri_scheme")
        value = _HTML_URI_RE.sub("about:blank", value)
    return value


def _sanitize_sql(value: str, rules: list) -> str:
    if _SQL_NUL_RE.search(value):
        rules.append("sql_nul")
        value = _SQL_NUL_RE.sub("", value)
    if _SQL_QUOTE_RE.search(value):
        rules.append("sql_quote")
        # Escape single quote by doubling (SQL standard).
        value = value.replace("'", "''")
        # Backslash escape: double it.
        value = value.replace("\\", "\\\\")
    return value


def _sanitize_shell(value: str, rules: list) -> str:
    if _SHELL_META_RE.search(value):
        rules.append("shell_meta")
        value = _SHELL_META_RE.sub("", value)
    return value


def _sanitize_filename(value: str, rules: list) -> str:
    # Strip path components - only the basename survives.
    if "/" in value or "\\" in value:
        rules.append("filename_path_separator")
        value = value.replace("\\", "/").split("/")[-1]
    if _FILENAME_BAD_RE.search(value):
        rules.append("filename_bad_char")
        value = _FILENAME_BAD_RE.sub("_", value)
    # Reserved names on Windows: prefix with _
    base = value.split(".")[0].upper()
    if base in _RESERVED_WINDOWS:
        rules.append("filename_reserved")
        value = "_" + value
    # Strip leading dots and trailing whitespace
    if value.startswith("."):
        rules.append("filename_leading_dot")
        value = value.lstrip(".")
    if value != value.rstrip():
        rules.append("filename_trailing_space")
        value = value.rstrip()
    if not value:
        rules.append("filename_empty")
        value = "untitled"
    return value


def _sanitize_log(value: str, rules: list) -> str:
    if _LOG_ANSI_RE.search(value):
        rules.append("log_ansi")
        value = _LOG_ANSI_RE.sub("", value)
    if _LOG_CTRL_RE.search(value):
        rules.append("log_control")
        value = _LOG_CTRL_RE.sub("?", value)
    return value


def _sanitize_jsonpath(value: str, rules: list) -> str:
    if _JSONPATH_META_RE.search(value):
        rules.append("jsonpath_meta")
        value = _JSONPATH_META_RE.sub("_", value)
    return value


_TRANSFORMS = {
    SanitizationContext.HTML: _sanitize_html,
    SanitizationContext.SQL: _sanitize_sql,
    SanitizationContext.SHELL: _sanitize_shell,
    SanitizationContext.FILENAME: _sanitize_filename,
    SanitizationContext.LOG: _sanitize_log,
    SanitizationContext.JSONPATH: _sanitize_jsonpath,
}


def sanitize_text(
    value: str,
    *,
    context=None,
    allow=None,
    deny=None,
    max_length=None,
    strip_controls: bool = True,
    normalize_unicode: bool = True,
) -> SanitizationResult:
    """Sanitize ``value`` for ``context``.

    Args:
        value: input string.
        context: target context (see SanitizationContext).
        allow: optional iterable of allowed characters.
        deny: optional iterable of denied characters.
        max_length: truncate to at most this many characters.
        strip_controls: drop ASCII control chars except \\t \\n \\r.
        normalize_unicode: apply NFKC normalization before transforms.

    Returns:
        SanitizationResult with cleaned value, list of applied rules,
        original length, and a confidence score.
    """
    if not isinstance(value, str):
        raise TypeError(f"value must be str, got {type(value).__name__}")

    if context is None:
        ctx = SanitizationContext.HTML
    elif isinstance(context, SanitizationContext):
        ctx = context
    else:
        ctx = SanitizationContext(context)

    rules: list = []
    original = value

    if normalize_unicode:
        normalized = unicodedata.normalize("NFKC", value)
        if normalized != value:
            rules.append("normalize_unicode")
            value = normalized

    # Run context-specific transforms first so each context can capture
    # its own signal (e.g. NUL in SQL is "sql_nul", not generic "strip_control").
    transform = _TRANSFORMS.get(ctx)
    if transform is not None:
        value = transform(value, rules)

    if strip_controls:
        keep = "\t\n\r"
        value = _apply_strip_controls(value, rules, keep=keep)

    if deny is not None:
        value = _apply_deny(value, deny, rules)

    if allow is not None:
        value = _apply_allow(value, allow, rules)

    if max_length is not None and max_length >= 0:
        value = _apply_max_length(value, max_length, rules)

    confidence = _confidence(original, value)
    return SanitizationResult(
        value=value,
        context=ctx,
        applied_rules=rules,
        original_length=len(original),
        confidence=confidence,
    )


def sanitize_for_html(value: str, **kwargs) -> SanitizationResult:
    return sanitize_text(value, context=SanitizationContext.HTML, **kwargs)


def sanitize_for_sql_literal(value: str, **kwargs) -> SanitizationResult:
    return sanitize_text(value, context=SanitizationContext.SQL, **kwargs)


def sanitize_for_shell_arg(value: str, **kwargs) -> SanitizationResult:
    return sanitize_text(value, context=SanitizationContext.SHELL, **kwargs)


def sanitize_for_filename(value: str, **kwargs) -> SanitizationResult:
    return sanitize_text(value, context=SanitizationContext.FILENAME, **kwargs)


def sanitize_for_log(value: str, **kwargs) -> SanitizationResult:
    return sanitize_text(value, context=SanitizationContext.LOG, **kwargs)


def sanitize_for_jsonpath(value: str, **kwargs) -> SanitizationResult:
    return sanitize_text(value, context=SanitizationContext.JSONPATH, **kwargs)


def is_safe(value: str, *, context=None, threshold: float = 0.95) -> bool:
    """Return True if sanitizing ``value`` would leave >= ``threshold`` of it intact."""
    result = sanitize_text(value, context=context or SanitizationContext.HTML)
    return result.confidence >= threshold
