"""Settings, all taken from environment variables so every install type works the same."""
import os
from dataclasses import dataclass, field
from pathlib import Path


def _default_workdir():
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "pcap-analyzer"


@dataclass
class Settings:
    workdir: Path = field(default_factory=lambda: Path(os.environ.get("PCAP_ANALYZER_WORKDIR", _default_workdir())))
    max_size_mb: int = field(default_factory=lambda: int(os.environ.get("PCAP_ANALYZER_MAX_SIZE_MB", "100")))
    ttl_days: int = field(default_factory=lambda: int(os.environ.get("PCAP_ANALYZER_TTL_DAYS", "7")))
    tshark: str = field(default_factory=lambda: os.environ.get("PCAP_ANALYZER_TSHARK", "tshark"))
