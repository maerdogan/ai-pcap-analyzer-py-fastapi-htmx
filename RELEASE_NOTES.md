# Release notes

Each new feature is a minor version. Each bug fix is a patch version.

## 0.8.3 (2026-11-01)

### Fixed

- Sample generator: the high-latency scenario now acknowledges data at the real round-trip time.

## 0.8.2 (2026-11-01)

### Fixed

- `X-Request-ID` and `Server-Timing` values no longer keep a literal `\r\n` from tshark output.

## 0.8.1 (2026-11-01)

### Fixed

- Captures with no TCP events or DNS queries no longer fail while saving results.

## 0.8.0 (2026-11-01)

### Added

- Command line: `pcap-analyzer analyze`, `list`, `delete` and `purge`.

## 0.7.0 (2026-11-01)

### Added

- Pre-analysis filter by IP or CIDR, port, time range and Wireshark display filter. IP and port filters keep both directions of a connection.

## 0.6.0 (2026-11-01)

### Added

- Round-trip time per side of a connection, capture point detection, and service time that excludes network delay. Service time stays empty when it cannot be measured.

## 0.5.0 (2026-11-01)

### Added

- HTTP/2 analysis with separate timing for each stream on a connection.

## 0.4.0 (2026-11-01)

### Added

- HTTPS decryption with a TLS key log file or an RSA private key, with a warning when traffic stays encrypted. Key files are removed after analysis.

## 0.3.0 (2026-11-01)

### Added

- HTTP/1.1 timing: request send, wait, first byte, transfer and total. Requests and responses are paired in order, so pipelined traffic stays correct.

## 0.2.0 (2026-11-01)

### Added

- Analysis engine on tshark with TCP connection and event data, saved to one DuckDB file per analysis. The same input reopens the saved result. Size limit and retention are configurable.

## 0.1.1 (2026-11-01)

### Fixed

- Sample generator: the TLS client now verifies the test certificate instead of skipping verification.

## 0.1.0 (2026-11-01)

### Added

- Synthetic sample generator (`tools/gen_samples.py`) for HTTP, HTTPS, HTTP/2, NetScaler-style two-sided traffic and 100 MB performance captures. Expected values are written to `truth.json`.
