import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

from pcap_analyzer import __version__

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import release  # noqa: E402


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path, samples):
    """The real server over HTTPS, started the way the install guide does."""
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext",
                    "subjectAltName=DNS:localhost", "-keyout", tmp_path / "key.pem", "-out", tmp_path / "cert.pem"], check=True, capture_output=True)
    port, password = _free_port(), secrets.token_urlsafe(18)
    env = dict(os.environ, PCAP_ANALYZER_ADMIN_PASSWORD=password, PCAP_ANALYZER_WORKDIR=str(tmp_path / "work"))
    proc = subprocess.Popen([sys.executable, "-m", "pcap_analyzer.cli", "serve", "--port", str(port), "--cert", tmp_path / "cert.pem", "--key", tmp_path / "key.pem"],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"https://localhost:{port}"
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"{url}/healthz", timeout=1, context=ssl.create_default_context(cafile=tmp_path / "cert.pem"))
                break
            except OSError:
                time.sleep(0.1)
        yield url, password, tmp_path / "cert.pem"
    finally:
        proc.terminate()
        proc.wait(10)


def _smoke(url, password, capture, *args):
    return subprocess.run([sys.executable, ROOT / "tools/smoke.py", url, capture, *args], capture_output=True, text=True,
                          env=dict(os.environ, PCAP_ANALYZER_SMOKE_PASSWORD=password))


def test_smoke_walks_a_real_https_server(server, samples):
    url, password, cert = server
    done = _smoke(url, password, samples / "http_scenarios.pcap", "--cafile", cert)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "cookie secure: True" in done.stdout
    assert done.stdout.rstrip().endswith("OK")


def test_smoke_reports_a_wrong_password(server, samples):
    url, _, cert = server
    done = _smoke(url, "wrong", samples / "http_scenarios.pcap", "--cafile", cert)
    assert done.returncode != 0
    assert "FAILED: /login" in done.stderr


def test_smoke_trusts_only_the_given_certificate(server, samples):
    url, password, _ = server
    assert _smoke(url, password, samples / "http_scenarios.pcap").returncode != 0


def test_this_version_can_be_released():
    assert release.problems(f"v{__version__}") == []
    assert release.notes(__version__).startswith("### Added")


def test_release_refuses_another_version():
    assert any("does not match" in p for p in release.problems("v9.9.9"))
    assert release.notes("9.9.9") == ""


def test_workflows_pin_actions_and_keep_write_rights_on_one_job():
    for name in ("test.yml", "release.yml"):
        text = (ROOT / ".github/workflows" / name).read_text()
        assert text.index("permissions:\n  contents: read") < text.index("jobs:")
        for used in re.findall(r"uses: (\S+)", text):
            assert used.startswith("./") or re.search(r"@[0-9a-f]{40}$", used), used
    assert (ROOT / ".github/workflows/test.yml").read_text().count("write") == 0


def test_compose_limits_cpu_memory_and_processes():
    text = (ROOT / "docker/compose.yaml").read_text()
    for line in ("cpus: 2", "mem_limit: 2g", "pids_limit: 256", "/tmp:size=1g", "read_only: true"):
        assert line in text


def test_systemd_unit_limits_the_service():
    text = (ROOT / "linux-glibc2.26-server/pcap-analyzer.service").read_text()
    for line in ("MemoryMax=2G", "CPUQuota=200%", "TasksMax=256", "PrivateTmp=true", "CapabilityBoundingSet=\n"):
        assert line in text


def test_network_policy_covers_the_app_and_is_applied():
    assert "networkpolicy.yaml" in (ROOT / "kubernetes/generic/kustomization.yaml").read_text()
    text = (ROOT / "kubernetes/generic/networkpolicy.yaml").read_text()
    labels = (ROOT / "kubernetes/base/deployment.yaml").read_text()
    assert "app: pcap-analyzer" in text and "app: pcap-analyzer" in labels
    assert "policyTypes: [Ingress, Egress]" in text and "egress:" not in text
