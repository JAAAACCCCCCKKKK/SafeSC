"""Suite-wide isolation.

Fetched dependency sources are cached across runs under ``SAFESC_WORKDIR`` (default: the
system temp dir), keyed by artifact identity. Shared between tests and between local runs,
that cache let a stale workspace stand in for a fixture file missing from the checkout, so
a test passed locally and failed in CI. Every test gets its own.
"""

import pytest


@pytest.fixture(autouse=True)
def _isolated_workdir(tmp_path_factory, monkeypatch):
    monkeypatch.setenv("SAFESC_WORKDIR", str(tmp_path_factory.mktemp("safesc-workdir")))
