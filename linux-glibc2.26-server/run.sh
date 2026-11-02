#!/usr/bin/env bash
# Run pcap-analyzer as a normal user, without sudo, Docker or systemd.
# Python, the Python packages and tshark come from bundle/. The application itself runs from ../src,
# so a code change needs no new bundle.
set -euo pipefail
umask 077

HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
SRC=$(dirname "$HERE")/src
RUNTIME=$HERE/runtime
PIDFILE=$HERE/pcap-analyzer.pid
LOG=$HERE/pcap-analyzer.log
ENV_FILE=$HERE/.env
MIN_GLIBC=${PCAP_ANALYZER_MIN_GLIBC:-2.26}

die() { echo "error: $*" >&2; exit 1; }

check_host() {
  [[ $(uname -m) == x86_64 ]] || die "the bundle supports x86_64 only, this host is $(uname -m)"
  local glibc
  glibc=$(getconf GNU_LIBC_VERSION | awk '{print $2}')
  [[ $(printf '%s\n%s\n' "$MIN_GLIBC" "$glibc" | sort -V | head -1) == "$MIN_GLIBC" ]] ||
    die "the bundle needs glibc $MIN_GLIBC or newer, this host has $glibc"
}

unpack() {
  ls "$HERE"/bundle/runtime-linux-x86_64.tar.gz.part-* >/dev/null 2>&1 ||
    die "bundle/ is empty. Run ./build-bundle.sh on a machine with internet first"
  local unpacked=
  [[ -f $RUNTIME/.bundle.sha256 ]] && unpacked=$(<"$RUNTIME/.bundle.sha256")
  [[ $unpacked == "$(<"$HERE/bundle/runtime.sha256")" ]] && return 0
  command -v tar >/dev/null || die "tar is needed to unpack the runtime"
  echo "Unpacking the runtime..."
  rm -rf "$RUNTIME"
  cat "$HERE"/bundle/runtime-linux-x86_64.tar.gz.part-* | tar xzf - -C "$HERE"
  cp "$HERE/bundle/runtime.sha256" "$RUNTIME/.bundle.sha256"
}

use_older_duckdb() { # linux-glibc2.17-server sets the wheel to put in the runtime
  local wheel=${PCAP_ANALYZER_DUCKDB_WHEEL:-} site
  [[ -n $wheel && ! -f $RUNTIME/.older-duckdb ]] || return 0
  site=$("$RUNTIME/python/bin/python3" -c "import site; print(site.getsitepackages()[0])")
  rm -rf "$site"/duckdb "$site"/_duckdb* "$site"/duckdb-*
  "$RUNTIME/python/bin/python3" -m zipfile -e "$wheel" "$site"
  touch "$RUNTIME/.older-duckdb"
}

load_env() {
  [[ -f $ENV_FILE ]] || cp "$HERE/env.example" "$ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
  export PATH=$RUNTIME/tshark/bin:$RUNTIME/python/bin:$PATH
  export WIRESHARK_DATA_DIR=$RUNTIME/tshark/share/wireshark
  export PYTHONNOUSERSITE=1
  export PYTHONPATH=$SRC
  export PCAP_ANALYZER_WORKDIR=${PCAP_ANALYZER_WORKDIR:-$HERE/data}
  HOST=${PCAP_ANALYZER_HOST:-127.0.0.1}
  PORT=${PCAP_ANALYZER_PORT:-8000}
  CERT=${PCAP_ANALYZER_CERT:-}
  KEY=${PCAP_ANALYZER_KEY:-}
}

cli() { "$RUNTIME/python/bin/python3" -m pcap_analyzer.cli "$@"; }

running() {
  [[ -f $PIDFILE ]] || return 1
  local pid
  pid=$(cat "$PIDFILE")
  kill -0 "$pid" 2>/dev/null && tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q pcap_analyzer.cli
}

port_busy() {
  local target=$HOST
  [[ $target == 0.0.0.0 ]] && target=127.0.0.1
  "$RUNTIME/python/bin/python3" -c "import socket, sys; sys.exit(socket.socket().connect_ex((sys.argv[1], int(sys.argv[2]))) != 0)" "$target" "$PORT"
}

healthy() {
  local scheme=http target=$HOST
  [[ -n $CERT ]] && scheme=https
  [[ $target == 0.0.0.0 ]] && target=127.0.0.1
  "$RUNTIME/python/bin/python3" - "$scheme://$target:$PORT/healthz" <<'EOF'
import ssl, sys, urllib.request
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    urllib.request.urlopen(sys.argv[1], timeout=2, context=ctx)
except OSError:
    sys.exit(1)
EOF
}

start() {
  running && { echo "Already running with PID $(cat "$PIDFILE")."; return; }
  [[ -n ${PCAP_ANALYZER_ADMIN_PASSWORD_HASH:-}${PCAP_ANALYZER_ADMIN_PASSWORD:-} ]] ||
    die "no admin password yet. Run ./run.sh password first"
  port_busy && die "port $PORT is already in use. Stop that program or change PCAP_ANALYZER_PORT in .env"
  mkdir -p "$PCAP_ANALYZER_WORKDIR"
  local args=(serve --host "$HOST" --port "$PORT")
  [[ -n $CERT ]] && args+=(--cert "$CERT" --key "$KEY")
  local url=http://$HOST:$PORT
  [[ -n $CERT ]] && url=https://$HOST:$PORT
  nohup "$RUNTIME/python/bin/python3" -m pcap_analyzer.cli "${args[@]}" >>"$LOG" 2>&1 </dev/null &
  echo $! >"$PIDFILE"
  for _ in $(seq 1 30); do
    running || break
    if healthy; then
      echo "Started with PID $(cat "$PIDFILE"): $url"
      return
    fi
    sleep 1
  done
  tail -5 "$LOG" >&2
  stop >/dev/null
  die "the server did not start, see $LOG"
}

stop() {
  if running; then
    local pid
    pid=$(cat "$PIDFILE")
    kill "$pid"
    for _ in $(seq 1 15); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    kill -9 "$pid" 2>/dev/null || true
    echo "Stopped."
  else
    echo "Not running."
  fi
  rm -f "$PIDFILE"
}

set_password() {
  local hash tmp
  hash=$(cli hash-password)
  tmp=$(mktemp "$HERE/.env.XXXXXX")
  grep -v '^PCAP_ANALYZER_ADMIN_PASSWORD_HASH=' "$ENV_FILE" >"$tmp" || true
  printf "PCAP_ANALYZER_ADMIN_PASSWORD_HASH='%s'\n" "$hash" >>"$tmp"
  mv "$tmp" "$ENV_FILE"
  echo "Password saved in $ENV_FILE."
}

cmd=${1:-}
case $cmd in
  start | stop | restart | status | logs | password | cli) ;;
  *) echo "usage: $0 start|stop|restart|status|logs|password|cli ARGS"; exit 2 ;;
esac

check_host
[[ -f $SRC/pcap_analyzer/cli.py ]] || die "$SRC is missing. Keep this folder inside the repository, next to src/"
unpack
use_older_duckdb
load_env

case $cmd in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status)
    if running; then echo "Running with PID $(cat "$PIDFILE")."; else echo "Not running."; exit 1; fi ;;
  logs) tail -n 50 "$LOG" ;;
  password) set_password ;;
  cli) shift; cli "$@" ;;
esac
