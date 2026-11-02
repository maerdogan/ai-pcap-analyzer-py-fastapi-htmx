# Linux servers with glibc 2.17

For CentOS 7, RHEL 7 and similar x86_64 hosts. Like `linux-glibc2.26-server`, it needs no sudo, Docker, systemd or internet.

```bash
./run.sh password
./run.sh start
```

It uses the runtime in `../linux-glibc2.26-server`, so keep both folders next to `src/`, and replaces DuckDB with version 1.2.2. Newer DuckDB versions need glibc 2.27. Settings, data and logs stay in `../linux-glibc2.26-server`, and the other commands are the same as in its [README](../linux-glibc2.26-server/README.md).

Tested in a `centos:7` container, not on a real server.
