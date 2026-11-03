"""Ready commands for taking a capture on a Linux server, in a pod or on a worker node."""
import shlex

from .knowledge import t

SAFE_SHARE = 0.95  # the file must stay under the upload limit, so stop a little before it
DEFAULT_SECONDS = 120
DEFAULT_IMAGE = "nicolaka/netshoot"
TUNNEL_PORTS = "udp port 4789 or udp port 6081"  # VXLAN and Geneve


def _bpf(server, port, client):
    parts = [f"host {server}"] if server else []
    if client:
        parts.append(f"host {client}")
    if port:
        parts.append(f"tcp port {port}")
    return " and ".join(parts)


def _tcpdump(interface, bpf, seconds, limit, path=None):
    """Write to a pipe so that `head` stops at the size limit. `timeout` stops it at the time limit."""
    cmd = f"timeout {seconds} tcpdump -i {shlex.quote(interface)} -nn -s 0 -U -w -"
    if bpf:
        cmd += f" {shlex.quote(bpf)}"
    cmd += f" | head -c {limit}"
    return f"{cmd} > {shlex.quote(path)}" if path else cmd


def commands(server=None, port=None, client=None, seconds=DEFAULT_SECONDS, max_mb=1000, interface="any", namespace="default", pod="POD", container="CONTAINER", image=DEFAULT_IMAGE):
    """One entry per capture point, with what it can and cannot show."""
    limit = int(max_mb * 1_000_000 * SAFE_SHARE)
    bpf = _bpf(server, port, client)
    linux = _tcpdump(interface, bpf, seconds, limit, "/tmp/server.pcap")
    inner = _tcpdump("any", bpf, seconds, limit)
    target = f"-n {shlex.quote(namespace)} pod/{shlex.quote(pod)}"
    pod_cmd = (f"kubectl debug {target} --image={shlex.quote(image)} --target={shlex.quote(container)} --attach --quiet -- "
               f"sh -c {shlex.quote(inner)} > pod.pcap")
    return [
        dict(key="linux", title=t("Linux server"), lines=[f"sudo sh -c {shlex.quote(linux)}"],
             text=t("Run this on the server, or on a client you manage. Files stay under the upload limit, and the capture stops after {n} seconds.", n=seconds),
             shows=t("Everything that reaches this machine: its service time, and its side of the network."),
             hides=t("What happened before the traffic got here.")),
        dict(key="pod", title=t("Pod"), lines=[pod_cmd],
             text=t("Run this from a machine with kubectl. It adds a temporary container that shares the pod's network, and saves the capture on your machine. The image must be reachable from the cluster."),
             shows=t("The pod's own view with pod IP addresses and no tunnel headers. This is the cleanest place to measure service time."),
             hides=t("Anything on the node or in the network around the pod.")),
        dict(key="node_pod", title=t("Worker node, pod network"), lines=[
            f"PID=$(sudo crictl inspect --output go-template --template '{{{{.info.pid}}}}' {shlex.quote(container)})",
            f"sudo nsenter -t \"$PID\" -n sh -c {shlex.quote(_tcpdump('any', bpf, seconds, limit, '/tmp/pod.pcap'))}"],
             text=t("Use this when you can reach the node but cannot add a container to the pod. Replace CONTAINER with the container ID from `crictl ps`."),
             shows=t("The same view as inside the pod, without changing the pod."),
             hides=t("Anything on the node or in the network around the pod.")),
        dict(key="node_uplink", title=t("Worker node, outer interface"), lines=[
            f"sudo sh -c {shlex.quote(_tcpdump(interface if interface != 'any' else 'eth0', TUNNEL_PORTS, seconds, limit, '/tmp/uplink.pcap'))}"],
             text=t("Use this to see loss between nodes. Set the interface to the node's real one. An address filter does not work here, because pod traffic is inside the tunnel."),
             shows=t("Pod traffic inside VXLAN or Geneve, and packets lost between nodes. The app reads the addresses inside the tunnel."),
             hides=t("Traffic that stays on one node.")),
        dict(key="keylog", title=t("HTTPS key log"), lines=["SSLKEYLOGFILE=/tmp/keys.log curl https://example.test/"],
             text=t("Encrypted traffic needs its session keys. Set this variable on the client before it connects, then upload the file with the capture. It works with curl, Firefox, Chrome and many other programs."),
             shows=t("URLs and HTTP timing inside HTTPS."),
             hides=t("If TLS ends on NetScaler, the two sides have different keys. Each side needs its own key log.")),
    ]
