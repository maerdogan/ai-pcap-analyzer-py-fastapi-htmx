#!/usr/bin/env bash
# Install Envoy Gateway in namespace pcap-analyzer and open the Gateway API route.
# This adds cluster-wide CRDs, a GatewayClass and RBAC to the analyzer cluster.
# The platform's Gateway API CRDs stay as they are.
set -euo pipefail
export PATH=/data/vks/runtime/bin:$PATH
export KUBECONFIG=${KUBECONFIG:-/data/vks/runtime/kubeconfig.yaml}
HERE=$(cd "$(dirname "$0")" && pwd)
CTX=analyzer
NS=pcap-analyzer
VERSION=v1.9.3
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

helm pull oci://docker.io/envoyproxy/gateway-helm --version "$VERSION" --untar -d "$TMP"
kubectl --context "$CTX" apply --server-side -f "$TMP/gateway-helm/charts/crds/crds/generated/"
helm --kube-context "$CTX" upgrade --install envoy-gateway "$TMP/gateway-helm" -n "$NS" --skip-crds \
  -f "$HERE/envoy-gateway-values.yaml" --wait --timeout 5m
kubectl --context "$CTX" apply -k "$HERE/gateway"
kubectl --context "$CTX" -n "$NS" wait gateway/pcap-analyzer --for=condition=Programmed --timeout=180s
kubectl --context "$CTX" -n "$NS" get gateway pcap-analyzer
