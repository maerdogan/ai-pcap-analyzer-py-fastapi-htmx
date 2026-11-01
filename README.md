# pcap-analyzer

Find out why HTTP requests are slow, from a packet capture.

Upload a PCAP and see where the time went: connection setup, network delay, service time, data transfer, or packet loss. It runs on your own server, needs no internet access, and is designed for captures taken on either side of a load balancer such as NetScaler.

> **Status: early development.** The analysis engine and command line work. The web interface is not built yet. See [RELEASE_NOTES.md](RELEASE_NOTES.md) for what exists.

## What works today

- HTTP/1.1 and HTTP/2 timing per request, split into send, wait, service and transfer
- TCP connection data: round-trip time, capture point, MSS, how the connection closed
- HTTPS decryption with a TLS key log file or RSA key
- Results saved in DuckDB, so a capture analyzed once opens at once

Planned next: URL grouping, root cause of slow requests, comparison of two captures, a web interface and data export.

## Quick start

Requires Python 3.11+ and tshark 4.0+.

```bash
pip install -e .
pcap-analyzer analyze capture.pcap
pcap-analyzer analyze capture.pcap --keylog keys.log --host 10.0.0.5 --port 8080
```

## Settings

| Environment variable | Default | Meaning |
|---|---|---|
| `PCAP_ANALYZER_WORKDIR` | `~/.local/share/pcap-analyzer` | Where results are saved |
| `PCAP_ANALYZER_MAX_SIZE_MB` | `100` | Largest accepted capture |
| `PCAP_ANALYZER_TTL_DAYS` | `7` | Age at which `purge` removes results |

## Development

```bash
pip install -e ".[dev]"
pytest
```

Tests use synthetic captures from `tools/gen_samples.py`. Their timings are known in advance, and they contain only private IP addresses and fake data.

## Security

Packet captures and TLS keys can contain passwords and personal data. Do not commit them to this repository or attach them to public issues.

## License

[MIT](LICENSE). tshark is a separate program licensed under the GPL.
