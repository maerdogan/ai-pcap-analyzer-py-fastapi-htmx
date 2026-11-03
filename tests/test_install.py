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
    for line in ("cpus: 2", "mem_limit: 4g", "pids_limit: 256", "/tmp:size=3g", "read_only: true"):
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


def test_image_is_pinned():
    text = (ROOT / "docker/Containerfile").read_text()
    assert re.search(r"^FROM python:[\d.]+-slim@sha256:[0-9a-f]{64}$", text, re.M) and "-c requirements.lock" in text
    assert all("==" in x for x in (ROOT / "requirements.lock").read_text().splitlines() if x and not x.startswith("#"))


def test_issue_templates_warn_about_captures():
    for name in ("bug.yml", "feature.yml"):
        assert "Do not attach" in (ROOT / ".github/ISSUE_TEMPLATE" / name).read_text()


def test_collect_script_parses():
    subprocess.run(["bash", "-n", ROOT / "tools/pcap-collect.sh"], check=True)
    assert subprocess.run([ROOT / "tools/pcap-collect.sh"], capture_output=True).returncode == 2


FAKE_KUBECTL = """#!/bin/sh
echo "$@" >> "$LOG"
case $1 in
  debug) while [ "$1" != "--" ]; do shift; done; shift; [ "$1" = sh ] && [ "$2" = -c ] || exit 9
         cat "$PCAP"; [ -z "$HOLD" ] || exec sleep 30 ;;
  get) echo pod/node-debugger-n1-abcde ;;
esac
"""


def _collect(tmp_path, samples, *args, **env):
    kubectl = tmp_path / "kubectl"
    kubectl.write_text(FAKE_KUBECTL)
    kubectl.chmod(0o755)
    env = dict(os.environ, KUBECTL=str(kubectl), LOG=str(tmp_path / "log"), PCAP=str(samples / "split_headers.pcap"), ATTACH_S="0", **env)
    cmd = [ROOT / "tools/pcap-collect.sh", "--keep", tmp_path / "keep", "--seconds", "20", "--from", "pod:ns/p", "--from", "node:n1", *args]
    return subprocess.Popen(cmd, cwd=tmp_path, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_collect_from_pod_and_node(tmp_path, samples):
    p = _collect(tmp_path, samples)
    _, err = p.communicate(timeout=30)
    assert p.returncode == 0, err
    want = (samples / "split_headers.pcap").read_bytes()
    assert [(f.name, f.read_bytes() == want) for f in sorted((tmp_path / "keep").iterdir())] == [("0-pod_ns_p.pcap", True), ("1-node_n1.pcap", True)]
    log = (tmp_path / "log").read_text()
    assert "--profile=netadmin" in log and "delete pod/node-debugger-n1-abcde" in log.replace("--wait=false ", "")


def test_collect_keeps_the_capture_on_ctrl_c(tmp_path, samples):
    p = _collect(tmp_path, samples, HOLD="1")
    time.sleep(2)
    p.send_signal(2)
    _, err = p.communicate(timeout=15)
    assert p.returncode == 0 and "stopped early" in err, err
    assert len(list((tmp_path / "keep").iterdir())) == 2


def test_collect_keeps_the_capture_when_upload_fails(tmp_path, samples):
    p = _collect(tmp_path, samples, "--url", "http://127.0.0.1:9", PCAP_ANALYZER_TOKEN="x")
    _, err = p.communicate(timeout=30)
    assert p.returncode == 1 and err.count("upload failed") == 2, err
