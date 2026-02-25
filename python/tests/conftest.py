"""Shared fixtures for the AgenticIdentity test suite."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

PASSPHRASE = "correct-horse-battery-staple"


@pytest.fixture()
def tmp_dir():
    """Yield a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)
