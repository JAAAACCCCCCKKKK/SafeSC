"""tools/source.py — materialising a dependency's source safely, offline."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from safesc.tools.source import artifact_url_candidates, fetch_source
from tests.helpers import dep


def _tarball(files: dict[str, str], *, evil: bool = False) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        if evil:
            info = tarfile.TarInfo("../../escape.txt")
            info.size = 1
            tf.addfile(info, io.BytesIO(b"x"))
    return buf.getvalue()


def test_artifact_urls_per_ecosystem():
    assert artifact_url_candidates(dep("@scope/pkg", "1.2.3")) == ["https://registry.npmjs.org/@scope/pkg/-/pkg-1.2.3.tgz"]
    assert artifact_url_candidates(dep("serde", "1.0.0", "rust")) == ["https://static.crates.io/crates/serde/serde-1.0.0.crate"]
    assert artifact_url_candidates(dep("github.com/BurntSushi/toml", "v1.3.2", "go")) == [
        "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.3.2.zip"]
    assert artifact_url_candidates(dep("org.yaml:snakeyaml", "2.2", "java"))[0].endswith("/org/yaml/snakeyaml/2.2/snakeyaml-2.2-sources.jar")
    files = [{"packagetype": "bdist_wheel", "url": "https://f/w.whl"}, {"packagetype": "sdist", "url": "https://f/s.tar.gz"}]
    assert artifact_url_candidates(dep("x", "1", "python"), pypi_files=files) == ["https://f/s.tar.gz", "https://f/w.whl"]
    assert artifact_url_candidates(dep("x", "1", artifact_url="https://lock/x.tgz"))[0] == "https://lock/x.tgz"


def test_fetch_extracts_once_and_reuses(tmp_path):
    calls = []

    def download(url: str, dest: Path) -> bool:
        calls.append(url)
        dest.write_bytes(_tarball({"package/index.js": "module.exports = 1\n"}))
        return True

    d = dep("left-pad", "1.3.0")
    ws = fetch_source(d, base_dir=tmp_path, downloader=download, allow_clone=False)
    assert ws.origin == "artifact" and (ws.root / "package" / "index.js").is_file()
    again = fetch_source(d, base_dir=tmp_path, downloader=download, allow_clone=False)
    assert again.root == ws.root and len(calls) == 1


def test_traversal_archive_is_refused(tmp_path):
    def download(url: str, dest: Path) -> bool:
        dest.write_bytes(_tarball({"package/a.js": "1"}, evil=True))
        return True

    assert fetch_source(dep("evil", "1.0.0"), base_dir=tmp_path, downloader=download, allow_clone=False) is None
    assert not (tmp_path.parent / "escape.txt").exists()


def test_nothing_fetchable_returns_none(tmp_path):
    assert fetch_source(dep("x", "1"), base_dir=tmp_path, downloader=lambda u, d: False, allow_clone=False) is None
