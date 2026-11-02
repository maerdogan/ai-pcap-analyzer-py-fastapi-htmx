#!/usr/bin/env bash
# Take a capture from one or two places at the same time and upload each one to pcap-analyzer.
#
#   PCAP_ANALYZER_TOKEN=... tools/pcap-collect.sh --url https://pcap.example.internal --filter "port 8080" --seconds 60 \
#     --from local --from ssh:user@host --from pod:namespace/pod
#
# Sources: local, ssh:[user@]host (needs sudo tcpdump there), pod:namespace/pod (uses kubectl debug).
set -euo pipefail

URL="" FILTER="tcp" SECONDS_LIMIT=60 MAX_MB=95 IMAGE=nicolaka/netshoot SOURCES=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --url) URL=${2%/}; shift 2 ;;
    --filter) FILTER=$2; shift 2 ;;
    --seconds) SECONDS_LIMIT=$2; shift 2 ;;
    --max-mb) MAX_MB=$2; shift 2 ;;
    --image) IMAGE=$2; shift 2 ;;
    --from) SOURCES+=("$2"); shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[[ -n $URL && -n ${PCAP_ANALYZER_TOKEN:-} && ${#SOURCES[@]} -gt 0 ]] || { echo "needs --url, --from and PCAP_ANALYZER_TOKEN" >&2; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
TCPDUMP="timeout $SECONDS_LIMIT tcpdump -i any -s 0 -U -w - $FILTER"

capture() { # source, output file. head stops a capture at the size limit.
  case $1 in
    local) sudo sh -c "$TCPDUMP" ;;
    ssh:*) ssh "${1#ssh:}" "sudo sh -c '$TCPDUMP'" ;;
    pod:*)
      local target=${1#pod:}
      kubectl debug -n "${target%%/*}" "pod/${target#*/}" --image="$IMAGE" --attach --quiet -- sh -c "$TCPDUMP" ;;
    *) echo "unknown source: $1" >&2; return 2 ;;
  esac 2>/dev/null | head -c $((MAX_MB * 1024 * 1024)) >"$2" || true
}

for i in "${!SOURCES[@]}"; do
  capture "${SOURCES[$i]}" "$WORK/$i.pcap" &
done
wait

for i in "${!SOURCES[@]}"; do
  name=$(printf '%s' "${SOURCES[$i]}" | tr -c 'A-Za-z0-9.-' '_').pcap
  [[ -s $WORK/$i.pcap ]] || { echo "${SOURCES[$i]}: nothing captured" >&2; continue; }
  printf '%s: ' "${SOURCES[$i]}"
  curl -fsS -H "Authorization: Bearer $PCAP_ANALYZER_TOKEN" -F "capture=@$WORK/$i.pcap;filename=$name" "$URL/api/v1/captures"
  echo
done
