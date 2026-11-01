# Linux server, glibc 2.26 or newer

Run pcap-analyzer on a Linux server as a normal user. You do not need sudo, Docker, systemd or internet access. Read the [security section](../README.md#security) first.

The server needs Linux x86_64 with glibc 2.26 or newer, `tar` and `gzip`. CentOS 7 and RHEL 7 are too old. `bundle/` includes Python 3.13, every Python package and tshark 4.6, so you do not install them.

Tested with Ubuntu 18.04, Rocky Linux 8 and openSUSE Leap 15.0, in containers without network access. The folder must not be on a disk mounted with `noexec`.

## Start

Copy this folder to the server, then run:

```bash
./run.sh password
```

```bash
./run.sh start
```

Open <http://127.0.0.1:8000> from the server itself, and sign in as `admin`.

| Command | What it does |
|---|---|
| `./run.sh start` | Starts the app in the background |
| `./run.sh stop` | Stops it |
| `./run.sh restart` | Restarts it and reads `.env` again |
| `./run.sh status` | Shows whether it is running |
| `./run.sh logs` | Shows the last 50 log lines |
| `./run.sh password` | Sets the admin password |
| `./run.sh cli analyze capture.pcap` | Runs any `pcap-analyzer` command |

Settings are in `.env`, which the first run creates. Results are saved in `data/`.

## Reach it from other machines

Passwords and TLS keys need HTTPS, so the app refuses other addresses without it. Set these in `.env`, then restart:

```bash
PCAP_ANALYZER_HOST=0.0.0.0
PCAP_ANALYZER_CERT=/home/you/cert.pem
PCAP_ANALYZER_KEY=/home/you/key.pem
```

Limit the port to your team's network with a firewall. The app does not start again after a server reboot, so you need to run `./run.sh start` again.

## Rebuild the bundle

Run this on a Linux x86_64 machine with internet after changing the code, because the app in `bundle/` does not follow the source:

```bash
./build-bundle.sh
```

`pcap-analyzer.service` is an optional unit for installs that do use systemd. See [docs/install.md](../docs/install.md).
