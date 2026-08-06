"""Encoding-robust text reading for lockfiles (Stage 1).

Lockfiles are routinely produced by tooling that emits UTF-16 / UTF-32 rather than UTF-8.
The classic case: ``pip freeze > requirements.txt`` under **Windows PowerShell 5.1**, whose
``>`` redirection writes **UTF-16 LE with a BOM**. Reading such a file as UTF-8 yields
NUL-interleaved garbage that every line-based parser silently drops — producing a false
"0 dependencies / CLEAN" audit, a dangerous silent under-report for a security gate.

:func:`read_text` sniffs the byte-order mark and decodes accordingly (UTF-8/16/32, big or
little endian), with a conservative NUL-density fallback for BOM-less UTF-16, and defaults
to UTF-8 otherwise. Every lockfile parser reads through this helper so the fix is uniform.
"""

from __future__ import annotations

import codecs
from pathlib import Path

__all__ = ["decode_bytes", "read_text"]


def decode_bytes(raw: bytes, *, errors: str = "replace") -> str:
    """Decode *raw* lockfile bytes to text, detecting the encoding from a BOM.

    Order matters: the UTF-32 LE BOM (``FF FE 00 00``) begins with the UTF-16 LE BOM
    (``FF FE``), so UTF-32 must be tested first. ``decode('utf-16'|'utf-32')`` consumes the
    BOM and resolves endianness; ``utf-8-sig`` strips a UTF-8 BOM. ``errors='replace'`` keeps
    a corrupt file from crashing the walk — a correctly-encoded file decodes cleanly with no
    replacement characters.
    """
    if raw.startswith(codecs.BOM_UTF32_LE) or raw.startswith(codecs.BOM_UTF32_BE):
        return raw.decode("utf-32", errors=errors)
    if raw.startswith(codecs.BOM_UTF8):
        return raw.decode("utf-8-sig", errors=errors)
    if raw.startswith(codecs.BOM_UTF16_LE) or raw.startswith(codecs.BOM_UTF16_BE):
        return raw.decode("utf-16", errors=errors)
    # No BOM. Some tools emit BOM-less UTF-16; a real UTF-8 lockfile never contains NUL
    # bytes, so NUL density in the head is a reliable tell. Guess endianness from whether
    # the NULs sit on odd offsets (little-endian: ``a\x00``) or even ones (big-endian:
    # ``\x00a``).
    head = raw[:4096]
    if b"\x00" in head:
        even_nul = head[0::2].count(0)
        odd_nul = head[1::2].count(0)
        if odd_nul > even_nul:
            return raw.decode("utf-16-le", errors=errors)
        if even_nul > odd_nul:
            return raw.decode("utf-16-be", errors=errors)
    return raw.decode("utf-8", errors=errors)


def read_text(path: "str | Path", *, errors: str = "replace") -> str:
    """Read *path* as text, auto-detecting UTF-8/16/32 (see :func:`decode_bytes`).

    Raises ``OSError`` if the file cannot be read (callers already handle that), but never
    raises ``UnicodeDecodeError`` — decoding uses ``errors='replace'``.
    """
    return decode_bytes(Path(path).read_bytes(), errors=errors)
