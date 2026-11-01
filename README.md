# pcap-analyzer

Find out why HTTP requests are slow, from a packet capture.

Upload a PCAP and see where the time went: connection setup, network delay, service time, data transfer, or packet loss. It runs on your own server, needs no internet access, and is designed for captures taken on either side of a load balancer such as NetScaler.

## Features

- HTTP/1.1 and HTTP/2 timing per request, grouped by URL shape such as `/users/{id}`
- TCP connection list with the slowest requests of each connection
- Inspection of one traffic pair by source, destination, port, type, URL and size
- Root cause of slow requests in plain language
- Comparison of two captures, and matching the same requests seen at two points
- HTTPS decryption with a TLS key log file or RSA key
- Export to CSV, Excel, JSON, PNG, SVG, HTML and PCAP

> **Status: early release.** Tested with synthetic captures on tshark 4.4 and 4.6, and in a Kubernetes pod behind an NGINX Ingress. It has not yet been tested with real NetScaler `nstrace` files.

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

See [docs/install.md](docs/install.md) for Docker, Kubernetes, offline installs and settings.

## Development

```bash
pip install -e ".[dev]"
pytest
```

Tests use synthetic captures from `tools/gen_samples.py`. Their timings are known in advance, and they contain only private IP addresses and fake data.

## Security

Packet captures and TLS keys can contain passwords and personal data. Do not commit them to this repository or attach them to public issues.

TLS keys are removed after analysis. The uploaded capture stays on disk until its retention time ends, so packets can be exported; set `PCAP_ANALYZER_KEEP_CAPTURE=0` to turn that off. Masking of secrets is best effort, so treat results as sensitive. All users share one account and see all analyses. Serve the app over HTTPS.

## License

[MIT](LICENSE). See [THIRD_PARTY.md](THIRD_PARTY.md) for bundled components.
