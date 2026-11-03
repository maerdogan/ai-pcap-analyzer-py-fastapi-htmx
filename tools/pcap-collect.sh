#!/usr/bin/env bash
# Take a capture from several places at the same time and upload each one to pcap-analyzer, or keep it with --keep DIR.
#
#   PCAP_ANALYZER_TOKEN=... tools/pcap-collect.sh --url https://pcap.example.internal --filter "port 8080" --seconds 60 \
#     --from local --from ssh:user@host --from pod:namespace/pod --from node:worker-1
#
# Sources: local, ssh:[user@]host (needs sudo without a password there, for timeout), pod:namespace/pod and node:name (use kubectl debug).
set -euo pipefail

URL="" FILTER="tcp" SECONDS_LIMIT=60 MAX_MB=95 IMAGE=nicolaka/netshoot KEEP="" SOURCES=()
KUBECTL=${KUBECTL:-kubectl}
while [[ $# -gt 0 ]]; do
  [[ $# -gt 1 ]] || { echo "$1 needs a value" >&2; exit 2; }
  case $1 in
    --url) URL=${2%/}; shift 2 ;;
    --filter) FILTER=$2; shift 2 ;;
    --seconds) SECONDS_LIMIT=$2; shift 2 ;;
    --max-mb) MAX_MB=$2; shift 2 ;;
    --image) IMAGE=$2; shift 2 ;;
    --from) SOURCES+=("$2"); shift 2 ;;
    --keep) KEEP=$2; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[[ ${#SOURCES[@]} -gt 0 && ( -n $KEEP || ( -n $URL && -n ${PCAP_ANALYZER_TOKEN:-} ) ) ]] || { echo "needs --from, and --keep or --url with PCAP_ANALYZER_TOKEN" >&2; exit 2; }

[[ -z $KEEP ]] || mkdir -p "$KEEP"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
LIMIT=$((MAX_MB * 1024 * 1024)) RC=0
TCPDUMP=(timeout "$SECONDS_LIMIT" tcpdump -i any -s 0 -B 32768 -U -w - "$FILTER") # -B: a pipe is slower than a file, a short burst overflows the default ring

capture() { # source, output file. head stops a capture at the size limit.
  case $1 in
    local) sudo "${TCPDUMP[@]}" ;;
    ssh:*) ssh "${1#ssh:}" "sudo $(printf '%q ' "${TCPDUMP[@]}")" ;;
    pod:*)
      local target=${1#pod:}
      $KUBECTL debug -n "${target%%/*}" "pod/${target#*/}" --image="$IMAGE" --profile=netadmin --attach --quiet -- "${TCPDUMP[@]}" ;;
    node:*)
      $KUBECTL debug "node/${1#node:}" --image="$IMAGE" --profile=sysadmin --attach --quiet -- "${TCPDUMP[@]}" || true
      # kubectl leaves this pod behind
      $KUBECTL get pods -o name | grep "/node-debugger-${1#node:}-" | xargs -r $KUBECTL delete --wait=false ;;
    *) echo "unknown source: $1" >&2; return 2 ;;
  esac 2>"$2.err" | head -c "$LIMIT" >"$2" || true
}

for i in "${!SOURCES[@]}"; do
  capture "${SOURCES[$i]}" "$WORK/$i.pcap" &
done
wait

for i in "${!SOURCES[@]}"; do
  name=$i-$(printf '%s' "${SOURCES[$i]}" | tr -c 'A-Za-z0-9.-' '_').pcap
  size=$(wc -c <"$WORK/$i.pcap")
  [[ $size -gt 24 ]] || { echo "${SOURCES[$i]}: nothing captured: $(tail -n 2 "$WORK/$i.pcap.err" | tr '\n' ' ')" >&2; RC=1; continue; } # 24 bytes is the file header alone
  [[ $size -lt $LIMIT ]] || echo "${SOURCES[$i]}: stopped at --max-mb $MAX_MB, the rest was not captured" >&2
  grep -E '^[1-9][0-9]* packets? dropped by kernel' "$WORK/$i.pcap.err" | sed "s|^|${SOURCES[$i]}: |" >&2 || true
  [[ -z $KEEP ]] || cp "$WORK/$i.pcap" "$KEEP/$name"
  [[ -n $URL ]] || continue
  printf '%s: ' "${SOURCES[$i]}"
  : >"$WORK/reply"
  code=$(curl -sS -o "$WORK/reply" -w '%{http_code}' -H "Authorization: Bearer $PCAP_ANALYZER_TOKEN" -F "capture=@$WORK/$i.pcap;filename=$name" "$URL/api/v1/captures") || true
  cat "$WORK/reply"
  echo
  [[ $code != 2* ]] || continue
  RC=1
  [[ -n $KEEP ]] || cp "$WORK/$i.pcap" "./$name"
  echo "${SOURCES[$i]}: upload failed (HTTP $code), capture is in ${KEEP:-.}/$name" >&2
done
exit $RC
