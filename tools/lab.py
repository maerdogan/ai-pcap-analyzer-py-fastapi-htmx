#!/usr/bin/env python3
"""Real Linux traffic with known delays, captured with tcpdump. No root is needed.

Every host is a network namespace inside one user namespace, so the kernel's own TCP stack
carries the traffic. A small proxy stands in for a load balancer that ends TCP on both sides.

        client ---- proxy ---- server         front.pcap and back.pcap, the two sides of the proxy
        node1 ==== VXLAN or Geneve ==== node2 node.pcap with -i any, uplink.pcap on the outer link

Usage: lab.py output_dir
Writes the captures and truth.json. It stops with exit code 3 where namespaces are not allowed.
"""
import http.client
import http.server
import json
import os
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

LINK_DELAY_MS = 10
PROXY_DELAY_S = 0.05
SERVICE_DELAYS_MS = (20, 150, 400)
PORT = 8080
NAMESPACES = ["unshare", "-Urnmpf", "--mount-proc", "--kill-child"]  # the PID namespace ends whatever is left
LOSS_PERCENT = 8
BODY_BYTES = 300_000
TWO_SIDES_S, POD_S, NODE_S = 9, 16, 4


def run(*cmd, **kw):
    return subprocess.run([str(c) for c in cmd], check=True, capture_output=True, text=True, **kw)


class Host:
    """One network namespace, kept alive by a sleeping process."""

    def __init__(self, name):
        self.name = name
        self.proc = subprocess.Popen(["unshare", "-n", "sleep", "300"])
        time.sleep(0.05)
        self.prefix = ["nsenter", "-t", str(self.proc.pid), "-n"]
        self.sh("ip", "link", "set", "lo", "up")

    def sh(self, *cmd):
        return run(*self.prefix, *cmd)

    def spawn(self, *cmd):
        return subprocess.Popen(self.prefix + [str(c) for c in cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def close(self):
        self.proc.kill()
        self.proc.wait()


def link(a, a_if, a_ip, b, b_if, b_ip, delay_ms=0, loss=0):
    run("ip", "link", "add", "lab-a", "type", "veth", "peer", "name", "lab-b")
    run("ip", "link", "set", "lab-a", "netns", a.proc.pid, "name", a_if)
    run("ip", "link", "set", "lab-b", "netns", b.proc.pid, "name", b_if)
    for host, ifname, ip in ((a, a_if, a_ip), (b, b_if, b_ip)):
        host.sh("ip", "addr", "add", f"{ip}/24", "dev", ifname)
        host.sh("ip", "link", "set", ifname, "up")
        host.sh("ethtool", "-K", ifname, "tso", "off", "gso", "off", "gro", "off") if shutil.which("ethtool") else None
        if delay_ms or loss:
            rule = ["netem", "delay", f"{delay_ms}ms"] + (["loss", f"{loss}%"] if loss else [])
            host.sh("tc", "qdisc", "add", "dev", ifname, "root", *rule)


class Capture:
    """tcpdump with a fixed length. Ubuntu's AppArmor profile refuses signals, so it stops on the first packet after the time ends."""

    def __init__(self, host, interface, path, seconds, poke):
        self.host, self.poke, self.ends = host, poke, time.monotonic() + seconds
        self.proc = host.spawn("tcpdump", "-Z", "root", "-i", interface, "-nn", "-s", "0", "-U", "-G", seconds, "-W", 1, "-w", path)
        time.sleep(0.6)

    def stop(self):
        time.sleep(max(self.ends - time.monotonic(), 0) + 0.2)
        for _ in range(30):
            if self.proc.poll() is not None:
                return
            self.host.sh(sys.executable, "-c", f"import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('{self.poke}', 9))")
            time.sleep(0.1)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        path, _, query = self.path.partition("?")
        args = dict(x.split("=") for x in query.split("&") if x)
        time.sleep(int(args.get("ms", 0)) / 1000)
        body = b"x" * int(args.get("bytes", 200))
        self.send_response(int(args.get("status", 200)))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def serve():
    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    Server(("0.0.0.0", PORT), Handler).serve_forever()


def _relay(src, dst, delay):
    try:
        while data := src.recv(65536):
            time.sleep(delay)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def proxy(target):
    listener = socket.create_server(("0.0.0.0", PORT))
    while True:
        front, _ = listener.accept()
        back = socket.create_connection((target, PORT))
        for s in (front, back):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=_relay, args=(front, back, PROXY_DELAY_S), daemon=True).start()
        threading.Thread(target=_relay, args=(back, front, PROXY_DELAY_S), daemon=True).start()


def client(target, spec):
    """Send requests on one kept-open connection and print what the client measured."""
    conn = http.client.HTTPConnection(target, PORT, timeout=30)
    seen = []
    for uri, with_id in json.loads(spec):
        rid = uuid.uuid4().hex if with_id else None
        started = time.perf_counter()
        conn.request("GET", uri, headers={"X-Request-ID": rid} if rid else {})
        r = conn.getresponse()
        r.read()
        seen.append(dict(uri=uri, status=r.status, seconds=time.perf_counter() - started))
    print(json.dumps(seen))


def wait_port(host, ip):
    probe = f"import socket\nfor _ in range(100):\n    try:\n        socket.create_connection(('{ip}', {PORT}), 1).close(); break\n    except OSError:\n        import time; time.sleep(0.05)\n"
    host.sh(sys.executable, "-c", probe)


def lab(*cmd):
    return [sys.executable, __file__, *cmd]


def requests(with_id):
    return [(f"/api/wait/{ms}?ms={ms}", with_id) for ms in SERVICE_DELAYS_MS for _ in range(5)] + [("/api/oops?status=503", with_id)] * 3


def two_sides(out, truth):
    c, p, s = Host("client"), Host("proxy"), Host("server")
    try:
        link(c, "eth0", "10.70.1.1", p, "front", "10.70.1.2", LINK_DELAY_MS)
        link(p, "back", "10.70.2.2", s, "eth0", "10.70.2.1", LINK_DELAY_MS)
        apps = [s.spawn(*lab("--serve")), p.spawn(*lab("--proxy", "10.70.2.1"))]
        wait_port(c, "10.70.1.2")
        for name, with_id in (("id", True), ("noid", False)):
            caps = [Capture(c, "eth0", out / f"front_{name}.pcap", TWO_SIDES_S, "10.70.1.2"), Capture(s, "eth0", out / f"back_{name}.pcap", TWO_SIDES_S, "10.70.2.2")]
            spec = json.dumps(requests(with_id))
            truth[f"two_sides_{name}"] = json.loads(c.sh(*lab("--client", "10.70.1.2", spec)).stdout)
            for cap in caps:
                cap.stop()
        for app in apps:
            app.kill()
    finally:
        for h in (c, p, s):
            h.close()


def lossy(out, truth):
    c, s = Host("client"), Host("server")
    try:
        link(c, "eth0", "10.70.3.1", s, "eth0", "10.70.3.2", LINK_DELAY_MS, LOSS_PERCENT)
        app = s.spawn(*lab("--serve"))
        wait_port(c, "10.70.3.2")
        cap = Capture(s, "eth0", out / "pod.pcap", POD_S, "10.70.3.1")
        spec = json.dumps([(f"/files/big?bytes={BODY_BYTES}", False)] * 6)
        truth["pod"] = json.loads(c.sh(*lab("--client", "10.70.3.2", spec)).stdout)
        cap.stop()
        app.kill()
    finally:
        c.close()
        s.close()


def tunnelled(out, truth, kind):
    n1, n2 = Host("node1"), Host("node2")
    try:
        link(n1, "eth0", "10.70.4.1", n2, "eth0", "10.70.4.2", LINK_DELAY_MS)
        opts = {"vxlan": ["id", "42", "dstport", "4789", "dev", "eth0"], "geneve": ["id", "42"]}[kind]
        for host, here, there, inner in ((n1, "10.70.4.1", "10.70.4.2", "10.244.1.1"), (n2, "10.70.4.2", "10.70.4.1", "10.244.1.2")):
            host.sh("ip", "link", "add", "pod0", "type", kind, *opts, *(["local", here] if kind == "vxlan" else []), "remote", there)
            host.sh("ip", "addr", "add", f"{inner}/24", "dev", "pod0")
            host.sh("ip", "link", "set", "pod0", "up")
        app = n2.spawn(*lab("--serve"))
        wait_port(n1, "10.244.1.2")
        caps = [Capture(n2, "any", out / f"node_{kind}.pcap", NODE_S, "10.70.4.1"), Capture(n2, "eth0", out / f"uplink_{kind}.pcap", NODE_S, "10.70.4.1")]
        spec = json.dumps([("/api/wait/150?ms=150", False)] * 6)
        truth[f"node_{kind}"] = json.loads(n1.sh(*lab("--client", "10.244.1.2", spec)).stdout)
        for cap in caps:
            cap.stop()
        app.kill()
    finally:
        n1.close()
        n2.close()


def main():
    if sys.argv[1] == "--serve":
        return serve()
    if sys.argv[1] == "--proxy":
        return proxy(sys.argv[2])
    if sys.argv[1] == "--client":
        return client(sys.argv[2], sys.argv[3])
    if not os.environ.get("LAB_INSIDE"):
        probe = subprocess.run(NAMESPACES + ["true"], capture_output=True)
        if probe.returncode or not all(shutil.which(x) for x in ("tcpdump", "ip", "tc", "nsenter")):
            sys.exit(3)
        os.execvpe("unshare", NAMESPACES + [sys.executable, __file__, *sys.argv[1:]], dict(os.environ, LAB_INSIDE="1"))
    out = Path(sys.argv[1]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    truth = dict(link_delay_ms=LINK_DELAY_MS, proxy_delay_s=PROXY_DELAY_S, service_delays_ms=SERVICE_DELAYS_MS, loss_percent=LOSS_PERCENT)
    two_sides(out, truth)
    lossy(out, truth)
    for kind in ("vxlan", "geneve"):
        tunnelled(out, truth, kind)
    (out / "truth.json").write_text(json.dumps(truth, indent=1))
    print(sorted(p.name for p in out.glob("*.pcap")))


if __name__ == "__main__":
    main()
