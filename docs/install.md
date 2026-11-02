# Install

Read the [security section](../README.md#security) first. HTTPS, network isolation and encrypted storage are yours to add.

All installs need an admin password, stored as a hash so it stays out of shell history. Each section below shows how to create it.

Everything below works without internet on the target host once the files are copied there.

## Docker or Podman

Each [release](https://github.com/maerdogan/ai-pcap-analyzer-py-fastapi-htmx/releases) has the image on GitHub Container Registry, and the same image as a file for hosts without internet. Take it one of these ways.

From the registry:

```bash
docker pull ghcr.io/maerdogan/ai-pcap-analyzer-py-fastapi-htmx:0.2.0
docker tag ghcr.io/maerdogan/ai-pcap-analyzer-py-fastapi-htmx:0.2.0 pcap-analyzer:0.2.0
```

From the release files, copied to the host:

```bash
sha256sum --check --ignore-missing SHA256SUMS
gunzip -c pcap-analyzer-0.2.0-image-amd64.tar.gz | docker load
```

Or build it yourself:

```bash
docker build -f docker/Containerfile -t pcap-analyzer:0.2.0 .
```

Then create the settings and a password hash:

```bash
cd docker
cp .env.example .env
docker run --rm -it pcap-analyzer:0.3.0 pcap-analyzer hash-password
```

Put the hash in `.env` in single quotes, as `PCAP_ANALYZER_ADMIN_PASSWORD_HASH='...'`, and start it:

```bash
docker compose up -d --no-build
```

Compose publishes port 8000 on localhost only, so put an HTTPS proxy in front of it. Set `PCAP_ANALYZER_PORT` in `.env` to use another port. To serve HTTPS directly, mount a certificate, add `--cert` and `--key` to the command, and set `PCAP_ANALYZER_BEHIND_PROXY=0`.

Compose limits the app to 2 CPUs, 2 GiB of memory, 256 processes and 1 GiB in `/tmp`. A 100 MB capture peaked near 600 MiB, so raise the limits only if you raise `PCAP_ANALYZER_MAX_SIZE_MB` or `PCAP_ANALYZER_MAX_JOBS`.

## Kubernetes

Push the image to your internal registry, then set the image and host names in `kubernetes/generic/`. Create the password hash on any machine with the image:

```bash
docker run --rm -it pcap-analyzer:0.3.0 pcap-analyzer hash-password
```

```bash
kubectl create namespace pcap-analyzer
kubectl -n pcap-analyzer create secret generic pcap-analyzer-admin --from-literal=password-hash='PASTE_HASH_HERE'
kubectl apply -k kubernetes/generic
```

Keep one replica: sessions and running jobs live in memory. The Ingress annotations assume ingress-nginx. Other controllers need their own upload limit of at least 110 MB. `kubernetes/vks` is an example overlay for F5 NGINX Ingress Controller, which uses `nginx.org` annotations.

`kubernetes/generic/networkpolicy.yaml` lets only the namespace `ingress-nginx` reach port 8000, and gives the pod no way out. If your controller runs in another namespace, change the name there, or the app becomes unreachable. It works only where the network plugin enforces policies, and `kubernetes/vks` does not include it.

To use it without an Ingress:

```bash
kubectl -n pcap-analyzer port-forward deploy/pcap-analyzer 8000:8000
```

With Helm, create the same Secret first, then install the chart. `kubernetes/helm/pcap-analyzer/values.yaml` lists the image, storage, Ingress, Gateway and NetworkPolicy settings:

```bash
helm install pcap-analyzer kubernetes/helm/pcap-analyzer -n pcap-analyzer --set image.repository=REGISTRY/pcap-analyzer,image.tag=VERSION
```

In a pod the default seccomp profile refuses namespaces, so tshark runs with Linux Landlock instead, which keeps it away from other analyses. It has no network limit there, and `-n` means it makes no lookups. A kernel without Landlock leaves only the CPU and file size limits.

## Linux server without sudo

[linux-glibc2.26-server](../linux-glibc2.26-server/README.md) runs the app as a normal user from one folder, with Python, its packages and tshark included. It needs no Docker, systemd or internet. For glibc 2.17, such as CentOS 7, use [linux-glibc2.17-server](../linux-glibc2.17-server/README.md).

## Linux server with systemd

Needs Python 3.11+ and tshark 4.0+. Build a package set on a machine with internet and the same OS:

```bash
pip wheel . -w wheels
```

On the target host:

```bash
sudo python3 -m venv /opt/pcap-analyzer
sudo /opt/pcap-analyzer/bin/pip install --no-index --find-links wheels ai-pcap-analyzer-py-fastapi-htmx
sudo useradd --system pcap-analyzer
sudo install -d -o pcap-analyzer -m 700 /var/lib/pcap-analyzer
sudo install -m 600 docker/.env.example /etc/pcap-analyzer.env
/opt/pcap-analyzer/bin/pcap-analyzer hash-password
```

Edit `/etc/pcap-analyzer.env`: put the hash in `PCAP_ANALYZER_ADMIN_PASSWORD_HASH`, in single quotes, and set `PCAP_ANALYZER_BEHIND_PROXY=0` when the app serves HTTPS itself. The unit expects a certificate, so add one or change the unit:

```bash
sudo install -d -g pcap-analyzer -m 750 /etc/pcap-analyzer
sudo install -m 644 cert.pem /etc/pcap-analyzer/cert.pem
sudo install -g pcap-analyzer -m 640 key.pem /etc/pcap-analyzer/key.pem
```

Then start it:

```bash
sudo cp linux-glibc2.26-server/pcap-analyzer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pcap-analyzer
```

The unit runs as the user `pcap-analyzer` with no capabilities and a private `/tmp`, and limits the service to 2 CPUs, 2 GiB of memory and 256 tasks. On Ubuntu, AppArmor lets tshark read only `/tmp`, so the app copies captures there during analysis. It removes them afterward.

## Check an install

`tools/smoke.py` signs in, uploads a capture, opens every page, downloads each export, deletes the analysis and signs out. It stops at the first failure and needs only Python. Use a capture with plain HTTP traffic.

```bash
read -rs PCAP_ANALYZER_SMOKE_PASSWORD && export PCAP_ANALYZER_SMOKE_PASSWORD
python3 tools/smoke.py http://127.0.0.1:8000 capture.pcap
```

With a self-signed certificate, add `--cafile cert.pem`. On a server with only `linux-glibc2.26-server`, run it with `runtime/python/bin/python3`.

`tools/check_install.sh` follows this guide from start to finish and then runs that walk. CI uses it for Compose, systemd, and the Linux folder on Ubuntu 18.04, Rocky Linux 8 and openSUSE Leap 15.0.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `PCAP_ANALYZER_ADMIN_USER` | `admin` | Login name |
| `PCAP_ANALYZER_ADMIN_PASSWORD_HASH` | | Password hash, preferred |
| `PCAP_ANALYZER_ADMIN_PASSWORD` | | Plain password, as the alternative |
| `PCAP_ANALYZER_BEHIND_PROXY` | `0` | `1` when an HTTPS proxy is in front |
| `PCAP_ANALYZER_HSTS_S` | `31536000` | How long browsers must use HTTPS, sent whenever HTTPS is on. `0` tells them to stop. Applies to the host name on every port |
| `PCAP_ANALYZER_REQUEST_ID_HEADER` | `x-request-id` | Header that follows a request through proxies. `traceparent` is read when it is absent |
| `PCAP_ANALYZER_MERGECAP` | `mergecap` | Program that joins parts of a capture |
| `PCAP_ANALYZER_SANDBOX` | on where possible | `0` stops running tshark in its own namespaces |
| `PCAP_ANALYZER_TRUSTED_PROXIES` | | Proxy addresses or networks whose forwarded headers are believed, such as `10.0.0.5,10.1.0.0/16`. When empty, all users behind the proxy share one login lockout |
| `PCAP_ANALYZER_WORKDIR` | `~/.local/share/pcap-analyzer` | Where results are saved |
| `PCAP_ANALYZER_MAX_SIZE_MB` | `100` | Largest accepted capture |
| `PCAP_ANALYZER_TTL_DAYS` | `7` | Days results are kept. The server removes older ones every hour |
| `PCAP_ANALYZER_MAX_JOBS` | `2` | Analyses running at once |
| `PCAP_ANALYZER_KEEP_CAPTURE` | `1` | Keep the capture for PCAP export, `0` to delete it after analysis |
| `PCAP_ANALYZER_LANGUAGE` | `tr` | Default language: `tr`, `en`, `de` or `es`. Each user can choose another in the app |
| `PCAP_ANALYZER_ANALYSIS_TIMEOUT_S` | `600` | Longest analysis in seconds, `0` for no limit |
| `PCAP_ANALYZER_KNOWLEDGE` | | Path of another knowledge file, built with `tools/build_knowledge.py` |
