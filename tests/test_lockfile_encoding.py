"""Encoding-robustness tests for Stage-1 lockfile reading.

Regression coverage for the silent "0 dependencies / CLEAN" failure caused by a UTF-16
lockfile (the classic `pip freeze > requirements.txt` under Windows PowerShell) being read
as UTF-8. Covers the shared reader (text_io) and the parsers that use it.
"""

from __future__ import annotations

import codecs

import pytest

from safesc.tools.index.core.text_io import decode_bytes, read_text


_SAMPLE = "requests==2.31.0\nflask==3.0.0\n"


class TestDecodeBytes:
    def test_plain_utf8(self):
        assert decode_bytes(_SAMPLE.encode("utf-8")) == _SAMPLE

    def test_utf8_bom_stripped(self):
        assert decode_bytes(codecs.BOM_UTF8 + _SAMPLE.encode("utf-8")) == _SAMPLE

    def test_utf16_le_bom(self):
        assert decode_bytes(codecs.BOM_UTF16_LE + _SAMPLE.encode("utf-16-le")) == _SAMPLE

    def test_utf16_be_bom(self):
        assert decode_bytes(codecs.BOM_UTF16_BE + _SAMPLE.encode("utf-16-be")) == _SAMPLE

    def test_utf16_native_bom_roundtrip(self):
        # "utf-16" adds a BOM in the platform's endianness; decode must recover the text.
        assert decode_bytes(_SAMPLE.encode("utf-16")) == _SAMPLE

    def test_utf32_le_bom(self):
        assert decode_bytes(codecs.BOM_UTF32_LE + _SAMPLE.encode("utf-32-le")) == _SAMPLE

    def test_utf32_be_bom(self):
        assert decode_bytes(codecs.BOM_UTF32_BE + _SAMPLE.encode("utf-32-be")) == _SAMPLE

    def test_bomless_utf16_le_detected_by_nul_density(self):
        # No BOM, but NULs on odd offsets → little-endian UTF-16.
        assert decode_bytes(_SAMPLE.encode("utf-16-le")) == _SAMPLE

    def test_bomless_utf16_be_detected_by_nul_density(self):
        assert decode_bytes(_SAMPLE.encode("utf-16-be")) == _SAMPLE

    def test_never_raises_on_garbage(self):
        # errors="replace": invalid bytes decode without raising.
        assert isinstance(decode_bytes(b"\xff\x00\xfe\x01rubbish"), str)


class TestRequirementsEncoding:
    def _parse(self, path):
        from safesc.tools.index.ecosystems.python.parsers.requirements import parse
        return parse(path)

    @pytest.mark.parametrize(
        "raw",
        [
            codecs.BOM_UTF16_LE + _SAMPLE.encode("utf-16-le"),   # UTF-16 LE + BOM (PowerShell)
            codecs.BOM_UTF16_BE + _SAMPLE.encode("utf-16-be"),   # UTF-16 BE + BOM
            _SAMPLE.encode("utf-16"),                             # UTF-16 native + BOM
            _SAMPLE.encode("utf-16-le"),                          # BOM-less UTF-16 LE
        ],
    )
    def test_utf16_requirements_parsed(self, tmp_path, raw):
        path = tmp_path / "requirements.txt"
        path.write_bytes(raw)
        deps = self._parse(path)
        assert {d.name for d in deps} == {"requests", "flask"}


class TestTomlEncoding:
    def test_utf16_uv_lock_parsed(self, tmp_path):
        toml = (
            'version = 1\n'
            '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
        )
        path = tmp_path / "uv.lock"
        path.write_bytes(codecs.BOM_UTF16_LE + toml.encode("utf-16-le"))
        from safesc.tools.index.ecosystems.python.parsers.uv import parse
        deps = parse(path)
        assert [d.name for d in deps] == ["requests"]


def test_read_text_missing_file_raises_oserror(tmp_path):
    with pytest.raises(OSError):
        read_text(tmp_path / "does-not-exist.txt")
