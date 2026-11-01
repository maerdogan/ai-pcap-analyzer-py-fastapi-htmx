#!/usr/bin/env bash
# Build bundle/ on a Linux x86_64 machine with internet. Needs curl, tar and sha256sum, but not sudo.
# The bundle holds Python, the Python packages, this application and tshark.
set -euo pipefail
trap 'echo "error: build-bundle.sh stopped at line $LINENO with status $?" >&2' ERR

HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
ROOT=$(dirname "$HERE")
PBS_TAG=20261026
PYTHON=3.13.18
DUCKDB=1.5.6 # Newer versions need glibc 2.27. Update MIN_GLIBC in run.sh when this changes.
ALPINE=v3.24 # Source of tshark
PART_SIZE=45m # GitHub warns about files over 50 MB

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
OUT=$WORK/out/runtime
mkdir -p "$OUT/tshark/bin" "$OUT/tshark/lib" "$OUT/tshark/share" "$WORK/src"

echo "Downloading Python $PYTHON..."
file=cpython-$PYTHON+$PBS_TAG-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz
base=https://github.com/astral-sh/python-build-standalone/releases/download/$PBS_TAG
curl -fsSL -o "$WORK/$file" "$base/${file//+/%2B}"
curl -fsSL -o "$WORK/SHA256SUMS" "$base/SHA256SUMS"
(cd "$WORK" && grep " $file\$" SHA256SUMS | sha256sum -c -)
tar xzf "$WORK/$file" -C "$OUT"

echo "Installing the application and Python packages..."
cp -r "$ROOT/pyproject.toml" "$ROOT/README.md" "$ROOT/LICENSE" "$ROOT/src" "$WORK/src/"
"$OUT/python/bin/python3" -m pip install -q --no-warn-script-location "duckdb==$DUCKDB" "$WORK/src"

echo "Installing tshark..."
T=$WORK/alpine
mkdir "$T"
"$OUT/python/bin/python3" "$HERE/fetch-tshark.py" "$ALPINE" "$T"
cp -a "$T/usr/bin/tshark" "$OUT/tshark/bin/tshark.real"
find "$T" -maxdepth 3 -name '*.so*' -path '*/lib/*' \( -type f -o -type l \) -exec cp -a {} "$OUT/tshark/lib/" \;
ln -sf ld-musl-x86_64.so.1 "$OUT/tshark/lib/libc.musl-x86_64.so.1"
# Alpine links liblua into a subfolder, so these links break when copied. Replace them with the file.
for link in "$OUT"/tshark/lib/*; do
  [[ -e $link ]] || cp -L --remove-destination "$T/usr/lib/$(basename "$link")" "$link"
done
cp -r "$T/usr/share/wireshark" "$OUT/tshark/share/"
rm -rf "$OUT/tshark/share/wireshark/doc"
# tshark runs through Alpine's musl loader, so it finds its libraries wherever the folder is.
cat >"$OUT/tshark/bin/tshark" <<'EOF'
#!/bin/sh
dir=$(dirname "$(readlink -f "$0")")/..
exec "$dir/lib/ld-musl-x86_64.so.1" --library-path "$dir/lib" "$dir/bin/tshark.real" "$@"
EOF
chmod +x "$OUT/tshark/bin/tshark"

echo "Checking the runtime from another path..."
mkdir "$WORK/moved"
cp -r "$OUT" "$WORK/moved/runtime"
TEST=$WORK/moved/runtime
env -i PATH="$TEST/tshark/bin:/usr/bin:/bin" WIRESHARK_DATA_DIR="$TEST/tshark/share/wireshark" tshark --version | head -1
env -i "$TEST/python/bin/python3" -c "import duckdb, fastapi, openpyxl, uvicorn, pcap_analyzer.cli; print('duckdb', duckdb.__version__)"
if [[ -f $ROOT/samples/http_scenarios.pcap ]]; then
  env -i HOME="$WORK" PATH="$TEST/tshark/bin:/usr/bin:/bin" WIRESHARK_DATA_DIR="$TEST/tshark/share/wireshark" \
    PCAP_ANALYZER_WORKDIR="$WORK/data" "$TEST/python/bin/python3" -m pcap_analyzer.cli analyze "$ROOT/samples/http_scenarios.pcap" | head -5
fi

echo "Writing bundle/..."
mkdir -p "$HERE/bundle"
rm -f "$HERE"/bundle/runtime-linux-x86_64.tar.gz.part-* "$HERE/bundle/runtime.sha256"
tar czf - -C "$WORK/out" runtime | split -b "$PART_SIZE" -d - "$HERE/bundle/runtime-linux-x86_64.tar.gz.part-"
(cd "$HERE/bundle" && sha256sum runtime-linux-x86_64.tar.gz.part-* >runtime.sha256)
du -sh "$HERE/bundle"
ls -la "$HERE/bundle"
