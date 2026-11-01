#!/usr/bin/env bash
# Build bundle/ on a Linux x86_64 machine with internet. Needs curl, tar and sha256sum, but not sudo.
# The bundle holds Python, the Python packages, this application and tshark.
set -euo pipefail

HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
ROOT=$(dirname "$HERE")
PBS_TAG=20261026
PYTHON=3.13.18
DUCKDB=1.5.6 # Newer versions need glibc 2.27. Update MIN_GLIBC in run.sh when this changes.
PART_SIZE=90m # GitHub refuses files over 100 MB

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
OUT=$WORK/out/runtime
mkdir -p "$OUT/tshark/bin" "$OUT/tshark/lib" "$OUT/tshark/share" "$WORK/mamba" "$WORK/src"

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
curl -fsSL https://micro.mamba.pm/api/micromamba/linux-64/latest | tar xjf - -C "$WORK/mamba" bin/micromamba
MAMBA_ROOT_PREFIX=$WORK/mamba/root "$WORK/mamba/bin/micromamba" create -y -q -p "$WORK/ts" \
  -c conda-forge --override-channels wireshark

# Keep tshark and the libraries it loads. glibc itself stays the host's.
cp -L "$WORK/ts/bin/tshark" "$OUT/tshark/bin/"
if ldd "$WORK/ts/bin/tshark" | grep 'not found'; then
  echo "error: tshark has missing libraries" >&2
  exit 1
fi
ldd "$WORK/ts/bin/tshark" | awk '$3 ~ /^\// {print $3}' | while read -r lib; do
  case $(basename "$lib") in
    libc.so* | libm.so* | libdl.so* | librt.so* | libpthread.so* | libresolv.so* | ld-linux*) ;;
    *) cp -L "$lib" "$OUT/tshark/lib/" ;;
  esac
done
cp -r "$WORK/ts/share/wireshark" "$OUT/tshark/share/"
rm -rf "$OUT/tshark/share/wireshark/doc"

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
