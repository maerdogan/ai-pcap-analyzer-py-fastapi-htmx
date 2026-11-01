# Release notes

All changes made on the same day are one minor version.

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
- Command line: `analyze`, `report`, `connection`, `inspect`, `list`, `delete`, `purge`, `serve` and `hash-password`.
- Synthetic sample generator with known timings, used by the tests.

### Fixed

- Captures with no TCP events or DNS queries no longer fail while saving results.
- `X-Request-ID` and `Server-Timing` values no longer keep a literal `\r\n` from tshark output.
- Multi-line headers no longer break saving results.
- Two identical analyses running together no longer collide.
- Sample generator: the TLS client now verifies the test certificate.
- Sample generator: the high-latency scenario now acknowledges data at the real round-trip time.
