# tiny-input-sanitize

**Zero-dependency input sanitization for HTTP, shell, SQL, filenames, logs, and JSONPath.**

Stdlib only. MIT licensed. ~380 LOC. 49 tests.

```bash
pip install tiny-input-sanitize
```

---

## Why

Every boundary crossing — HTTP request, shell argument, filename, log line — is an injection risk surface. `tiny-input-sanitize` is a **front-line filter** that catches the obvious cases at the boundary so deeply-nested code does not have to.

It is **not** a substitute for context-aware output encoding (`html.escape`, parameterized SQL, `shlex.quote`). It is the fast pre-check that runs before those.

---

## Supported contexts

| Context | What it does |
|---------|-------------|
| `html` | Escapes `< > " ' &`, blocks `javascript:`/`data:` URI schemes |
| `sql` | Doubles single quotes, doubles backslashes, strips NUL bytes |
| `shell` | Strips shell metacharacters `; & | `` $ ( ) > < ! \n \r \x00` |
| `filename` | Strips path separators, reserved Windows names, bad chars |
| `log` | Strips ANSI escape codes, replaces control chars with `?` |
| `jsonpath` | Replaces `$ . [ ] * ? \ ' "` with `_` |

---

## Quick start

```python
from tiny_input_sanitize import sanitize_for_html, is_safe

# Basic usage
result = sanitize_for_html(user_input)
if not result.is_clean:
    print(f"sanitized: {result.applied_rules}")
safe = result.value

# Quick check
if not is_safe(user_input, context="html"):
    raise ValueError("dangerous input")

# Full control
from tiny_input_sanitize import sanitize_text, SanitizationContext
result = sanitize_text(
    value,
    context=SanitizationContext.HTML,
    allow="abc",          # only these chars survive
    deny="<>",            # strip these chars
    max_length=255,
    strip_controls=True,  # drop ASCII control chars
)
```

---

## Confidence score

Every `SanitizationResult` carries a `confidence` score:

- `1.0` — input was untouched (completely safe)
- `0.0` — entire input was removed
- `(0.0, 1.0)` — fraction of codepoints that survived unchanged

The score uses prefix+suffix common-substring matching against the original, so it is fast and language-agnostic.

---

## Public API

```python
sanitize_text(value, *, context="html", allow=None, deny=None,
              max_length=None, strip_controls=True,
              normalize_unicode=True) -> SanitizationResult

sanitize_for_html(value, **kwargs) -> SanitizationResult
sanitize_for_sql_literal(value, **kwargs) -> SanitizationResult
sanitize_for_shell_arg(value, **kwargs) -> SanitizationResult
sanitize_for_filename(value, **kwargs) -> SanitizationResult
sanitize_for_log(value, **kwargs) -> SanitizationResult
sanitize_for_jsonpath(value, **kwargs) -> SanitizationResult

is_safe(value, *, context="html", threshold=0.95) -> bool

@dataclass SanitizationResult:
    value: str
    context: SanitizationContext
    applied_rules: list[str]
    original_length: int
    confidence: float
    is_clean: bool  # True if no rules were applied
    was_truncated: bool
```

---

## Confidence and allow/deny

The `allow` parameter overrides everything: only listed characters survive. The `deny` parameter strips individual characters. Both compose with the context transform.

```python
# Only alphanumeric + hyphen survive (good for HTTP headers)
sanitize_text(value, allow=set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"))

# Strip NUL and DEL from any input
sanitize_text(value, deny="\x00\x7f")
```
