# Release notes

All changes made on the same day are one minor version.

## 0.3.0 (2026-11-03)

### Added

- REST API under `/api/v1` with tokens you create and revoke in Preferences. See `docs/api.md`.
- Limits in Preferences: the slow request limit, and targets per URL pattern with a report of what went over.
- Baseline analysis: later analyses list the URLs that got slower, started failing or are new. A Trend page follows one URL across analyses.
- Case number, tags and notes on an analysis, a search over them, and the notes in the HTML report.
- Activity log of sign-ins, uploads, downloads and deletions, with address and time. The login is shared, so it does not name people.
- HAR download of all or filtered requests, with the same masking as the rest of the app.
- Requests of a connection on one time axis, saved as PNG or SVG.
- `pcap-analyzer check` exits with code 2 when an analysis breaks a limit, for CI.
- W3C `traceparent` gives an exact match between two capture points. `PCAP_ANALYZER_REQUEST_ID_HEADER` sets another header name.
- TLS tab: versions, ciphers, ALPN, resumed sessions, unanswered ClientHello, alerts and certificate end dates, without a key.
- WebSocket upgrades are measured on their own, so a long-lived connection no longer counts as slow. gRPC status from HTTP/2 trailers, with a gRPC errors issue.
- gzip captures open, and unpacking stops at the size limit. Several parts of one capture can be joined, with `mergecap` or, where it is missing, with tshark alone.
- tshark runs with CPU and file limits. Where the host allows user namespaces, it also runs without network and sees only its own files. `PCAP_ANALYZER_SANDBOX=0` turns that off.
- `kubernetes/helm/pcap-analyzer` chart, `tools/pcap-collect.sh` to capture from servers, pods and worker nodes at the same time and upload, `docs/usage.md` and `docs/api.md`.
- `requirements.lock`, a pinned base image, a dependency audit in CI, an SBOM in each Release and a signed record of how each image was built.
- `linux-glibc2.17-server` for CentOS 7 and similar hosts.
- `SECURITY.md`, `CONTRIBUTING.md`, issue templates, and exact source locations for GPL components in `THIRD_PARTY.md`.

### Changed

- zstd and lz4 captures stay refused, because their size cannot be limited the same way.
- Analyses saved by 0.2.0 still open. Their TLS tab asks you to analyze the capture again.

## 0.2.0 (2026-11-02)

### Added

- Interface in Turkish, English, German and Spanish. Turkish is the default, and each user can choose another language. Reports and exported column titles follow the choice.
- Bundled knowledge base for explanations. Each cause and issue says what it means, what this capture shows, what to check next and which sources back it. No AI model or outside service is used.
- Capture trust summary: high, medium or low, with the reasons, such as packets the capture missed, one-way traffic or connections cut at either end.
- Load balancer effect from its two sides: median and 95th percentile of added time per URL, kept apart from service time, with match rate and confidence.
- Servers tab with each backend's requests, times, errors and resets. A server out of line with its peers is marked and raises an issue.
- Traffic over time: requests, errors, 95th percentile, retransmissions and open connections. A period chosen on the chart narrows the Inspect tables.
- Capture guide with ready commands for Linux servers, pods and worker nodes.
- Time limit for each analysis and a cancel button. A stopped analysis leaves no files behind and frees its slot for the next one.
- NetScaler reset reason read from the window field of an RST packet, shown when the value is a documented code.
- VXLAN, Geneve and IP-in-IP traffic shows the addresses inside the tunnel.
- `tools/lab.py`: real Linux traffic with known delays, captured without root in network namespaces. The tests compare the results with those delays and with tshark.
- Form tokens tied to the session on everything that changes data. A page from a sibling subdomain can no longer sign you out or delete an analysis.
- HSTS whenever HTTPS is on, with `PCAP_ANALYZER_HSTS_S` to change or end it.
- `NetworkPolicy` in `kubernetes/generic`: only the ingress controller reaches the app, and the pod has no way out.
- CPU, memory and process limits in the Compose file and the systemd unit, and a tighter sandbox in the unit.
- `tools/smoke.py` walks through a running install from sign-in to deletion. `tools/check_install.sh` follows the install guide and runs that walk, and CI does this for Compose, systemd and the Linux folder on three old distributions.
- Release workflow: a `v*` tag runs all tests and install checks, then publishes the image to GitHub Container Registry and a GitHub Release with the image file, the wheel and checksums.
- `PCAP_ANALYZER_LANGUAGE`, `PCAP_ANALYZER_KNOWLEDGE` and `PCAP_ANALYZER_ANALYSIS_TIMEOUT_S`.

### Changed

- New interface: a blue top bar with the views of a capture, a strip of recent captures, a URL search and two-column pages. Each capture, connection and request opens with a scoreboard, and Compare shows the two captures side by side. Errors in Traffic over time now hang below the axis.
- `linux-glibc2.26-server` runs the application from `src/`, so a code update needs no new bundle. Keep the folder next to `src/`.
- All cause, issue, phase, warning and interface text moved to `knowledge/`. `tools/build_knowledge.py` checks it and builds `knowledge.bin`.
- A slow service explanation no longer rules out the network when the capture is not next to the server.
- Requests without a shared ID are matched in two passes, which holds up better when the capture clocks differ.
- Security headers are now on every answer, also on redirects and refusals.
- Compose takes its port from `PCAP_ANALYZER_PORT`.
- GitHub Actions in the workflows are pinned to exact commits.

### Fixed

- On kept-open HTTP/1.1 connections, responses were lost when the body came in its own TCP segment without a line end, so later requests looked unanswered and the first one looked very long. Header reassembly is now off. With headers longer than one segment, the part in later segments is not read.
- Extra copies of packets from `tcpdump -i any` looked like retransmissions and could show false packet loss. They are now removed and counted.
- With shared request IDs, the delay toward B was shown as zero and the whole delay as the way back. Both directions are now estimated, and the total added time is unchanged.
- ICMP errors that quote a TCP header no longer count as packets of that connection.
- The systemd steps in the install guide were missing `sudo`, the rights on the certificate files and `daemon-reload`. The guide also had no way to create a password hash on a host with only the image.

## 0.1.0 (2026-11-01)

### Added

- Analysis engine on tshark, with results saved to one DuckDB file per analysis. The same input reopens the saved result.
- HTTP/1.1 and HTTP/2 timing per request: send, wait, service, first byte, transfer and total.
- HTTPS decryption with a TLS key log file or an RSA private key, with a warning when traffic stays encrypted.
- Round-trip time per side of a connection, capture point detection and service time without network delay.
- Pre-analysis filter by IP or CIDR, port, time range and Wireshark display filter.
- Capture overview, URL groups such as `/users/{id}`, host names, TCP connection list and TCP details per connection.
- Inspection of one traffic pair by source, destination, port, type, URL and size.
- Slowest requests with a time breakdown and a plain explanation of the cause: slow service, network delay, packet loss, slow receiver, delayed ACK, queueing, gateway error, incomplete response and more.
- Masking of secrets in URLs, headers and body previews before anything is saved.
- Web interface with a single admin login, capture upload, history, issues list, response time chart, sortable tables, request content view and saved filters.
- Comparison of two captures with changes per URL and phase, separate filters for each side, and matching of the same requests seen at two points.
- Export of tables to CSV, Excel and JSON, charts to PNG and SVG, a single-file HTML report, and one connection as PCAP.
- Container image, Compose file, Kubernetes manifests, an example overlay with a Gateway API route, systemd unit and install guide.
- Command line: `analyze`, `report`, `connection`, `inspect`, `compare`, `list`, `delete`, `purge`, `serve` and `hash-password`.
- Professional interface layout: side navigation, metrics band, sorted time breakdown and aligned slowest-request tables.
- Synthetic sample generator with known timings, used by the tests.
- Run without sudo, Docker, systemd or internet from `linux-glibc2.26-server`, with Python, its packages and tshark included.
- One folder for each environment: `kubernetes`, `docker` and `linux-glibc2.26-server`.
- Security guidance in the README: what is not included, what operators must add, and a deployment diagram.

### Fixed

- Captures with no TCP events or DNS queries no longer fail while saving results.
- `X-Request-ID` and `Server-Timing` values no longer keep a literal `\r\n` from tshark output.
- Multi-line headers no longer break saving results.
- Two identical analyses running together no longer collide.
- Table icons no longer break under the content security policy.
- The server now refuses to start with an invalid password hash, instead of starting with a login that can never succeed.
- A fake `X-Forwarded-For` header can no longer avoid the login lockout. Forwarded headers are believed only from `PCAP_ANALYZER_TRUSTED_PROXIES`, and all addresses share a limit of 30 failed logins in 5 minutes.
- Compressed captures are refused, because they could unpack past the size limit.
- Expired results are now removed every hour, even when nobody uses the app. Leftover temporary files that can hold captures or TLS keys are removed too.
- Sample generator: the TLS client now verifies the test certificate.
- Sample generator: the high-latency scenario now acknowledges data at the real round-trip time.
