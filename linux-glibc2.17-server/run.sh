#!/usr/bin/env bash
# Runs ../linux-glibc2.26-server with the last DuckDB that works on glibc 2.17. The commands are the same.
set -euo pipefail
HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
export PCAP_ANALYZER_MIN_GLIBC=2.17
PCAP_ANALYZER_DUCKDB_WHEEL=$(ls "$HERE"/duckdb-*.whl)
export PCAP_ANALYZER_DUCKDB_WHEEL
exec "$HERE/../linux-glibc2.26-server/run.sh" "$@"
