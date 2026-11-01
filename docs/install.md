# Install

Read the [security section](../README.md#security) first. HTTPS, network isolation, encrypted storage and resource limits are yours to add.

All installs need an admin password. Create a hash and keep it out of shell history:

```bash
pcap-analyzer hash-password
```

Everything below works without internet on the target host once the files are copied there.

## Docker or Podman

On a machine with internet, build and save the image:

```bash
docker build -f docker/Containerfile -t pcap-analyzer:0.1.0 .
docker save pcap-analyzer:0.1.0 | gzip > pcap-analyzer-0.1.0.tar.gz
```

On the target host, load it and start it:

```bash
gunzip -c pcap-analyzer-0.1.0.tar.gz | docker load
cd docker
cp .env.example .env
docker compose up -d --no-build
```

Compose publishes port 8000 on localhost only. Put an HTTPS proxy in front of it. To serve HTTPS directly, mount a certificate, add `--cert` and `--key` to the command, and set `PCAP_ANALYZER_BEHIND_PROXY=0`.

## Kubernetes

Build the image as shown above and push it to your internal registry, then set the image and host names in `kubernetes/generic/`.

```bash
kubectl create namespace pcap-analyzer
kubectl -n pcap-analyzer create secret generic pcap-analyzer-admin --from-literal=password-hash='PASTE_HASH_HERE'
kubectl apply -k kubernetes/generic
```

Keep one replica: sessions and running jobs live in memory. The Ingress annotations assume ingress-nginx. Other controllers need their own upload limit of at least 110 MB. `kubernetes/vks` is an example overlay for F5 NGINX Ingress Controller, which uses `nginx.org` annotations.

To use it without an Ingress:

```bash
kubectl -n pcap-analyzer port-forward deploy/pcap-analyzer 8000:8000
```

## Linux server without sudo

[linux-glibc2.26-server](../linux-glibc2.26-server/README.md) runs the app as a normal user from one folder, with Python, its packages and tshark included. It needs no Docker, systemd or internet.

## Linux server with systemd

Needs Python 3.11+ and tshark 4.0+. Build a package set on a machine with internet and the same OS:

```bash
pip wheel . -w wheels
```

On the target host:

```bash
python3 -m venv /opt/pcap-analyzer
/opt/pcap-analyzer/bin/pip install --no-index --find-links wheels ai-pcap-analyzer-py-fastapi-htmx
sudo useradd --system pcap-analyzer
sudo install -d -o pcap-analyzer -m 700 /var/lib/pcap-analyzer
sudo install -m 600 docker/.env.example /etc/pcap-analyzer.env
```

Edit `/etc/pcap-analyzer.env`, and set `PCAP_ANALYZER_BEHIND_PROXY=0` when the app serves HTTPS itself. Put the password hash in single quotes. The unit expects `/etc/pcap-analyzer/cert.pem` and `key.pem`, so add them or change the unit. Then start it:

```bash
sudo cp linux-glibc2.26-server/pcap-analyzer.service /etc/systemd/system/
sudo systemctl enable --now pcap-analyzer
```

On Ubuntu, AppArmor lets tshark read only `/tmp`, so the app copies captures there during analysis. It removes them afterward.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `PCAP_ANALYZER_ADMIN_USER` | `admin` | Login name |
| `PCAP_ANALYZER_ADMIN_PASSWORD_HASH` | | Password hash, preferred |
| `PCAP_ANALYZER_ADMIN_PASSWORD` | | Plain password, as the alternative |
| `PCAP_ANALYZER_BEHIND_PROXY` | `0` | `1` when an HTTPS proxy is in front |
| `PCAP_ANALYZER_TRUSTED_PROXIES` | | Proxy addresses or networks whose forwarded headers are believed, such as `10.0.0.5,10.1.0.0/16`. When empty, all users behind the proxy share one login lockout |
| `PCAP_ANALYZER_WORKDIR` | `~/.local/share/pcap-analyzer` | Where results are saved |
| `PCAP_ANALYZER_MAX_SIZE_MB` | `100` | Largest accepted capture |
| `PCAP_ANALYZER_TTL_DAYS` | `7` | Days results are kept. The server removes older ones every hour |
| `PCAP_ANALYZER_MAX_JOBS` | `2` | Analyses running at once |
| `PCAP_ANALYZER_KEEP_CAPTURE` | `1` | Keep the capture for PCAP export, `0` to delete it after analysis |
