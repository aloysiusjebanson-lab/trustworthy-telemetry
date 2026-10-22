"""
RFC 8785 JSON Canonicalization Scheme (JCS) — integer-only protocol profile.

The evidence-bundle protocol forbids floating-point numbers, so this module
implements JCS restricted to I-JSON integers (|n| <= 2^53 - 1). For that input
domain the output is byte-identical to a full RFC 8785 implementation:

  * object members sorted by the UTF-16 code units of their names (RFC 8785 §3.2.3)
  * strings escaped exactly like ECMAScript JSON.stringify (RFC 8785 §3.2.2.2):
    only '"', '\\' and U+0000..U+001F are escaped; all other characters are emitted
    as raw UTF-8 (no \\uXXXX escaping of non-ASCII, no escaping of '/')
  * integers serialized as plain decimal (ES6 Number.toString for safe integers)
  * no insignificant whitespace

Floats, NaN/Infinity, integers outside the I-JSON safe range, lone surrogates and
duplicate object keys are rejected both when parsing and when canonicalizing.
"""

import json

MAX_SAFE_INTEGER = 2 ** 53 - 1

_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


class CanonicalizationError(ValueError):
    pass


def _serialize_string(s):
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise CanonicalizationError("Lone surrogate in string (not I-JSON)")
        esc = _SHORT_ESCAPES.get(cp)
        if esc is not None:
            out.append(esc)
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_sort_key(name):
    return name.encode("utf-16-be")


def _serialize(value, out):
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"Integer outside I-JSON safe range: {value}")
        out.append(str(value))
    elif isinstance(value, float):
        raise CanonicalizationError(f"Floating-point number not permitted in protocol data: {value!r}")
    elif isinstance(value, str):
        out.append(_serialize_string(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise CanonicalizationError(f"Object member name must be a string: {k!r}")
        out.append("{")
        for i, k in enumerate(sorted(value, key=_utf16_sort_key)):
            if i:
                out.append(",")
            out.append(_serialize_string(k))
            out.append(":")
            _serialize(value[k], out)
        out.append("}")
    else:
        raise CanonicalizationError(f"Unsupported type in protocol data: {type(value).__name__}")


def canonicalize(value):
    """Returns the RFC 8785 canonical UTF-8 bytes of value."""
    out = []
    _serialize(value, out)
    return "".join(out).encode("utf-8")


def _reject_duplicates(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise CanonicalizationError(f"Duplicate JSON key: {k}")
        d[k] = v
    return d


def _reject_float(token):
    raise CanonicalizationError(f"Floating-point number not permitted in protocol data: {token}")


def _reject_constant(token):
    raise CanonicalizationError(f"Non-finite number not permitted: {token}")


def _check_ranges(value):
    if isinstance(value, bool) or value is None or isinstance(value, str):
        if isinstance(value, str):
            for ch in value:
                if 0xD800 <= ord(ch) <= 0xDFFF:
                    raise CanonicalizationError("Lone surrogate in string (not I-JSON)")
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"Integer outside I-JSON safe range: {value}")
    elif isinstance(value, list):
        for item in value:
            _check_ranges(item)
    elif isinstance(value, dict):
        for k, v in value.items():
            _check_ranges(k)
            _check_ranges(v)


def loads(text):
    """Strict protocol JSON parser: rejects duplicate keys, floats, NaN/Infinity,
    unsafe integers and lone surrogates."""
    value = json.loads(text, object_pairs_hook=_reject_duplicates,
                       parse_float=_reject_float, parse_constant=_reject_constant)
    _check_ranges(value)
    return value


def load_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return loads(f.read())
