import json
import subprocess
import sys
from pathlib import Path

import pytest

from pcap_analyzer import knowledge
from pcap_analyzer.config import Settings

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def english(monkeypatch):
    """Most tests read English text. Tests of other languages set their own."""
    monkeypatch.setenv("PCAP_ANALYZER_LANGUAGE", "en")
    knowledge.set_language(None)


@pytest.fixture(scope="session")
def samples(tmp_path_factory):
    out = tmp_path_factory.mktemp("samples")
    subprocess.run([sys.executable, ROOT / "tools/gen_samples.py", out], check=True, capture_output=True)
    return out


@pytest.fixture(scope="session")
def truth(samples):
    return json.loads((samples / "truth.json").read_text())


@pytest.fixture
def settings(tmp_path):
    return Settings(workdir=tmp_path / "work", max_size_mb=100, ttl_days=7)
