# pcap-analyzer

Find out why HTTP requests are slow, from a packet capture.

Upload a PCAP and see where the time went: connection setup, network delay, service time, data transfer, or packet loss. It runs on your own server, needs no internet access, and is designed for captures taken on either side of a load balancer such as NetScaler.

> [!WARNING]
> Do not expose this application to the internet. It is built for private networks, has had no independent security review, and leaves several protections to you. Read [Security](#security) before you deploy it.

## Features

- HTTP/1.1 and HTTP/2 timing per request, grouped by URL shape such as `/users/{id}`
- TCP connection list with the slowest requests of each connection
- Inspection of one traffic pair by source, destination, port, type, URL and size
- Root cause of slow requests in plain language, with next checks and sources from a bundled knowledge base. No AI model is used
- Trust summary for each capture, traffic over time, and a per-server view that shows the odd one out behind a load balancer
- Comparison of two captures, and what a load balancer adds, measured from its two sides
- Ready capture commands for Linux servers, pods and worker nodes, including VXLAN, Geneve and `tcpdump -i any`
- Turkish, English, German and Spanish
- HTTPS decryption with a TLS key log file or RSA key
- Export to CSV, Excel, JSON, PNG, SVG, HTML, HAR and PCAP
- TLS view without a key: versions, ciphers, failed handshakes and certificate end dates
- WebSocket and gRPC handling, gzip captures and captures in several parts
- Limits per URL, a baseline capture, trends across captures, case notes and an activity log
- REST API with tokens ([docs/api.md](docs/api.md)), and `pcap-analyzer check` for CI

See the [usage guide](docs/usage.md).

> **Status: early release.** Tested with synthetic captures on tshark 4.4 and 4.6, with real Linux traffic in a network namespace lab (`tools/lab.py`), and in a Kubernetes pod behind an NGINX Ingress. Compose, systemd and the Linux folder are installed and walked through from start to finish by `tools/check_install.sh`. It has not yet been tested with captures from a production network.

## Quick start

Requires Python 3.11+ and tshark 4.0+.

```bash
pip install .
pcap-analyzer hash-password
export PCAP_ANALYZER_ADMIN_PASSWORD_HASH='PASTE_HASH_HERE'
pcap-analyzer serve
```

Open <http://127.0.0.1:8000> and sign in as `admin`. The same engine works from the command line:

```bash
pcap-analyzer analyze capture.pcap --keylog keys.log --host 10.0.0.5 --port 8080
pcap-analyzer inspect ANALYSIS_ID --src 10.0.0.5 --dst 10.0.0.9 --port 8080
```

Each environment has its own folder. See [docs/install.md](docs/install.md) for install steps and settings, and [Releases](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/releases) for ready images.

| Folder | Environment |
|---|---|
| [kubernetes](kubernetes) | Kubernetes manifests |
| [docker](docker) | Docker or Podman, also the image for Kubernetes |
| [linux-glibc2.26-server](linux-glibc2.26-server/README.md) | Linux with glibc 2.26 or newer, without sudo, Docker or internet |

## Development

```bash
pip install -e ".[dev]"
pytest
```

A tag such as `v0.2.0` runs the tests and every install check, then publishes the image and a GitHub Release from `RELEASE_NOTES.md`. `tools/release.py` refuses a tag that does not match the version.

Tests use synthetic captures from `tools/gen_samples.py`. Their timings are known in advance, and they contain only private IP addresses and fake data.

## Security

Packet captures and TLS keys can contain passwords, session cookies and personal data, so anyone who reaches this application may reach that data. The red boxes below are not part of this project. You must add them yourself.

```mermaid
flowchart TD
    team["Your team"] -->|"VPN or private network"| proxy
    internet["Internet"] -. "must stay blocked" .-> proxy

    subgraph add["You must add"]
        proxy["HTTPS proxy<br/>certificate, IP allowlist,<br/>rate limit, access log"]
        firewall["Firewall or NetworkPolicy<br/>only the proxy reaches port 8000"]
        disk["Encrypted storage<br/>and safe backups"]
        limits["Regular image rebuilds"]
    end

    subgraph has["Included in pcap-analyzer"]
        app["Web app on port 8000<br/>one shared login"]
        tshark["tshark<br/>reads untrusted files"]
        data["Captures and results"]
    end

    proxy --> firewall --> app
    app --> tshark
    app --> data
    data --- disk
    tshark --- limits

    classDef must fill:#fdecea,stroke:#b42335,color:#152130
    classDef have fill:#e0ebf8,stroke:#1a5fb4,color:#152130
    classDef outside fill:#eeeeee,stroke:#666666,color:#152130
    class proxy,firewall,disk,limits must
    class app,tshark,data have
    class team,internet outside
```

### What is not included

| Missing | Why it matters | What you must do |
|---|---|---|
| HTTPS by default | The container serves plain HTTP on port 8000, so the password, captures and TLS keys can be read on the network. | Put an HTTPS proxy in front, or start with `--cert` and `--key`. |
| Protection of port 8000 outside Kubernetes | Whoever reaches the port directly skips your proxy's HTTPS, IP allowlist and logs. | Let only the proxy reach the port, with a firewall. In Kubernetes, `kubernetes/generic` includes a `NetworkPolicy`. Set its controller namespace, and check that your network plugin enforces it. |
| Lockout that cannot be misused | Sign-in stops for 5 minutes after 5 failed logins from one address, or 30 from all addresses. Someone can use this to block logins for a while. Open sessions keep working. Behind a proxy, all users count as one address until you set `PCAP_ANALYZER_TRUSTED_PROXIES`. | Set that variable to your proxy's addresses, add a rate limit at the proxy, and limit who can reach the app. |
| Separate users and an audit log | Everyone shares one login that can read, download and delete every analysis. Nothing records who did it. | Limit who gets the password, change it when someone leaves, and keep access logs at the proxy. |
| Multi-factor login and SSO | One password protects all the data. | Use a long random password, and require a VPN or an authenticating proxy. |
| Encryption at rest | Captures, results and exports are plain files. Kubernetes Secrets are plain in etcd unless you turn on encryption. | Use encrypted disks and encrypted backups, and turn on etcd encryption. |
| Complete masking | Only known header and field names are masked. Raw captures and PCAP exports are never masked. | Treat every result, report and export as sensitive. Set `PCAP_ANALYZER_KEEP_CAPTURE=0` if you do not need PCAP export. |
| Secure wiping | Expired results are removed every hour while the server runs, and you can delete them yourself, but neither wipes the disk. | Rely on encrypted storage for safe disposal. |
| A sandbox for tshark | tshark parses untrusted files and shares the app's permissions and data. A flaw in tshark would expose everything the app can read. | Run it in a non-root container, update tshark often, and analyze only captures from sources you trust. |
| Resource limits in the Linux folder | Compose, systemd and Kubernetes limit CPU and memory, but `linux-glibc2.26-server` has no root to set them, so a large analysis can take the whole server. | Keep `PCAP_ANALYZER_MAX_JOBS` low, or run it on a server with room to spare. |
| Pinned and signed releases | Python dependencies and the base image are not pinned. There are no signed images or vulnerability scans, and bundled JavaScript does not update itself. | Build your own image, scan it, and rebuild it regularly. |

### Before you upload

- Make sure you may capture and analyze this traffic. Captures can hold personal data, so your privacy rules apply, such as KVKK or GDPR.
- Treat a TLS key log like a password, because it decrypts every session it covers. Delete it after use. The app removes its copy after analysis. If a process is killed, the hourly cleanup removes the copy within 7 hours.
- Decompress captures first. Compressed files are refused, because their real size cannot be checked.
- Never commit captures or keys, and never attach them to public issues.
- `kubernetes/vks` is an example from one private lab. Do not reuse its addresses, and replace its self-signed certificate.

## License

[MIT](LICENSE). See [THIRD_PARTY.md](THIRD_PARTY.md) for bundled components.
