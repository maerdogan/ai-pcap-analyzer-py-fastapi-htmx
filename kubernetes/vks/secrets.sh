#!/usr/bin/env bash
# Create the admin login and the TLS certificate once. Values stay in the platform secrets folder.
set -euo pipefail
SECRETS=${SECRETS:-/data/vks/runtime/secrets}
CTX=${CTX:-analyzer}
NS=pcap-analyzer
ENV_FILE=$SECRETS/pcap-analyzer-admin.env
CRT=$SECRETS/pcap-analyzer-tls.crt
KEY=$SECRETS/pcap-analyzer-tls.key
PY=${PY:-python3}
umask 077

if [ ! -f "$ENV_FILE" ]; then
  PASSWORD=$(openssl rand -base64 18 | tr -d '/+=')
  printf 'PCAP_ANALYZER_ADMIN_USER=admin\nPCAP_ANALYZER_ADMIN_PASSWORD=%s\n' "$PASSWORD" > "$ENV_FILE"
fi
# shellcheck disable=SC1090
source "$ENV_FILE"

if [ ! -f "$CRT" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj /CN=pcap-analyzer.ubuntu.local \
    -addext "subjectAltName=DNS:pcap-analyzer.ubuntu.local,DNS:pcap-analyzer-gw.ubuntu.local" \
    -keyout "$KEY" -out "$CRT" 2>/dev/null
fi

HASH=$(printf '%s' "$PCAP_ANALYZER_ADMIN_PASSWORD" | "$PY" -c '
import base64, hashlib, secrets, sys
salt = secrets.token_bytes(16)
key = hashlib.scrypt(sys.stdin.read().encode(), salt=salt, n=2**14, r=8, p=1)
print(f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}")')

kubectl --context "$CTX" -n "$NS" create secret generic pcap-analyzer-admin \
  --from-literal=password-hash="$HASH" --dry-run=client -o yaml | kubectl --context "$CTX" apply -f -
kubectl --context "$CTX" -n "$NS" create secret tls pcap-analyzer-tls --cert="$CRT" --key="$KEY" \
  --dry-run=client -o yaml | kubectl --context "$CTX" apply -f -
