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
    keep_capture: bool = field(default_factory=lambda: os.environ.get("PCAP_ANALYZER_KEEP_CAPTURE", "1") != "0")
    max_jobs: int = field(default_factory=lambda: int(os.environ.get("PCAP_ANALYZER_MAX_JOBS", "2")))
    analysis_timeout_s: int = field(default_factory=lambda: int(os.environ.get("PCAP_ANALYZER_ANALYSIS_TIMEOUT_S", "600")))
    admin_user: str = field(default_factory=lambda: os.environ.get("PCAP_ANALYZER_ADMIN_USER", "admin"))
    admin_password: str | None = field(default_factory=lambda: os.environ.get("PCAP_ANALYZER_ADMIN_PASSWORD"))
    admin_password_hash: str | None = field(default_factory=lambda: os.environ.get("PCAP_ANALYZER_ADMIN_PASSWORD_HASH"))
    trusted_proxies: str | None = field(default_factory=lambda: os.environ.get("PCAP_ANALYZER_TRUSTED_PROXIES") or None)
    behind_proxy: bool = field(default_factory=lambda: os.environ.get("PCAP_ANALYZER_BEHIND_PROXY", "") == "1")
    hsts_s: int = field(default_factory=lambda: int(os.environ.get("PCAP_ANALYZER_HSTS_S", "31536000")))
