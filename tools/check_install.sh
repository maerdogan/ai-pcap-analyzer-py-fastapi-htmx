#!/usr/bin/env bash
# Follow docs/install.md from start to finish on this host, then run tools/smoke.py against the result.
#   check_install.sh compose          needs Docker with Compose
#   check_install.sh systemd          needs root or sudo, and tshark, on a host running systemd
#   check_install.sh bundle IMAGE     runs linux-glibc2.26-server in that image without network, needs Docker
# COMPOSE overrides the Compose command, and PCAP_ANALYZER_PORT the port.
set -euo pipefail

ROOT=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
VERSION=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$ROOT/src/pcap_analyzer/__init__.py")
IMAGE=pcap-analyzer:$VERSION
PORT=${PCAP_ANALYZER_PORT:-8000}
COMPOSE=${COMPOSE:-docker compose}
PYTHON=${PYTHON:-python3}
WORK=$(mktemp -d)
SUDO=
[[ $(id -u) == 0 ]] || SUDO=sudo
export PCAP_ANALYZER_PORT=$PORT PCAP_ANALYZER_SMOKE_PASSWORD=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')

die() { echo "error: $*" >&2; exit 1; }

capture() {
  "$PYTHON" "$ROOT/tools/gen_samples.py" "$WORK/samples" >/dev/null
  CAPTURE=$WORK/samples/http_scenarios.pcap
}

wait_for() {
  for _ in $(seq 1 60); do
    "$PYTHON" -c "import ssl, sys, urllib.request as u; u.urlopen(sys.argv[1], timeout=2, context=ssl.create_default_context(cafile=sys.argv[2] or None))" "$1" "${2:-}" 2>/dev/null && return
    sleep 1
  done
  die "$1 did not answer"
}

compose_stop() {
  (cd "$ROOT/docker" && $COMPOSE down -v) || true
  rm -f "$ROOT/docker/.env"
}

compose() {
  [[ ! -e $ROOT/docker/.env ]] || die "docker/.env exists. This check would replace it"
  (cd "$ROOT" && docker build -f docker/Containerfile -t "$IMAGE" .)
  local hash
  hash=$(printf '%s\n' "$PCAP_ANALYZER_SMOKE_PASSWORD" | docker run --rm -i "$IMAGE" pcap-analyzer hash-password 2>/dev/null)
  trap compose_stop EXIT
  { grep -v '^PCAP_ANALYZER_ADMIN_PASSWORD=' "$ROOT/docker/.env.example"; printf "PCAP_ANALYZER_ADMIN_PASSWORD_HASH='%s'\n" "$hash"; } >"$ROOT/docker/.env"
  (cd "$ROOT/docker" && $COMPOSE up -d --no-build)
  wait_for "http://127.0.0.1:$PORT/healthz"
  capture
  "$PYTHON" "$ROOT/tools/smoke.py" "http://127.0.0.1:$PORT" "$CAPTURE"
}

systemd_check() {
  [[ $PORT == 8000 ]] || die "the unit uses port 8000"
  local wheels=$WORK/wheels hash
  "$PYTHON" -m pip wheel "$ROOT" -w "$wheels"
  $SUDO "$PYTHON" -m venv /opt/pcap-analyzer
  $SUDO /opt/pcap-analyzer/bin/pip install --no-index --find-links "$wheels" ai-pcap-analyzer-py-fastapi-htmx
  $SUDO useradd --system pcap-analyzer
  $SUDO install -d -o pcap-analyzer -m 700 /var/lib/pcap-analyzer
  $SUDO install -m 600 "$ROOT/docker/.env.example" /etc/pcap-analyzer.env
  hash=$(printf '%s\n' "$PCAP_ANALYZER_SMOKE_PASSWORD" | /opt/pcap-analyzer/bin/pcap-analyzer hash-password 2>/dev/null)
  printf "PCAP_ANALYZER_ADMIN_PASSWORD_HASH='%s'\nPCAP_ANALYZER_BEHIND_PROXY=0\n" "$hash" | $SUDO tee -a /etc/pcap-analyzer.env >/dev/null
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
  $SUDO install -d -g pcap-analyzer -m 750 /etc/pcap-analyzer
  $SUDO install -m 644 "$WORK/cert.pem" /etc/pcap-analyzer/cert.pem
  $SUDO install -g pcap-analyzer -m 640 "$WORK/key.pem" /etc/pcap-analyzer/key.pem
  $SUDO cp "$ROOT/linux-glibc2.26-server/pcap-analyzer.service" /etc/systemd/system/
  $SUDO systemctl daemon-reload
  trap '$SUDO systemctl status --no-pager pcap-analyzer || true; $SUDO journalctl -u pcap-analyzer -n 30 --no-pager || true' ERR
  $SUDO systemctl enable --now pcap-analyzer
  wait_for "https://localhost:8000/healthz" "$WORK/cert.pem"
  capture
  "$PYTHON" "$ROOT/tools/smoke.py" https://localhost:8000 "$CAPTURE" --cafile "$WORK/cert.pem"
}

bundle() {
  local image=${1:?give an image, such as ubuntu:18.04} run=${2:-linux-glibc2.26-server} folder=$ROOT/linux-glibc2.26-server
  capture
  # A real server has tar, as the README asks, but a minimal image may not. Such an image gets the runtime already unpacked.
  mkdir "$WORK/unpacked"
  cat "$folder"/bundle/runtime-linux-x86_64.tar.gz.part-* | tar xzf - -C "$WORK/unpacked"
  cp "$folder/bundle/runtime.sha256" "$WORK/unpacked/runtime/.bundle.sha256"
  chmod -R a+rX "$WORK"
  docker run --rm --network none --user 1000:1000 --tmpfs /tmp:exec,mode=1777 -e HOME=/tmp -e PCAP_ANALYZER_SMOKE_PASSWORD -e RUN="$run" \
    -v "$ROOT:/repo:ro" -v "$WORK:/work:ro" "$image" sh -c '
    set -e
    getconf GNU_LIBC_VERSION
    mkdir /tmp/repo
    cp -r /repo/src /repo/tools /repo/linux-glibc2.26-server /repo/linux-glibc2.17-server /tmp/repo/
    cd /tmp/repo/linux-glibc2.26-server
    rm -rf runtime data .env
    command -v tar >/dev/null || cp -a /work/unpacked/runtime .
    printf "%s\n" "$PCAP_ANALYZER_SMOKE_PASSWORD" | ../$RUN/run.sh password 2>&1 | grep -v -i "getpass\|echo\|stream"
    ../$RUN/run.sh start
    runtime/python/bin/python3 ../tools/smoke.py http://127.0.0.1:8000 /work/samples/http_scenarios.pcap
    runtime/tshark/bin/tshark --version | head -1
    runtime/python/bin/python3 -c "import duckdb; print(\"duckdb\", duckdb.__version__)"
    ../$RUN/run.sh stop'
}

case ${1:-} in
  compose) compose ;;
  systemd) systemd_check ;;
  bundle) bundle "${2:-}" "${3:-linux-glibc2.26-server}" ;;
  *) sed -n '2,6p' "$0"; exit 2 ;;
esac
rm -rf "$WORK"
echo "Install check passed: $*"
