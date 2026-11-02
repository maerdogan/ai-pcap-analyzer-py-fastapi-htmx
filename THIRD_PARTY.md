# Third-party software

These are shipped in `src/pcap_analyzer/web/static/vendor/`:

| Component | Version | License |
|---|---|---|
| [htmx](https://github.com/bigskysoftware/htmx) | 2.0.4 | 0BSD |
| [Apache ECharts](https://github.com/apache/echarts) | 5.6.0 | Apache-2.0 |
| [AG Grid Community](https://github.com/ag-grid/ag-grid) | 32.3.3 | MIT |
| [Archivo](https://github.com/Omnibus-Type/Archivo) font | 5.2.5 | OFL-1.1 |

The container image also includes [Wireshark's tshark](https://www.wireshark.org/), licensed under GPL-2.0-or-later. It runs as a separate program.

`linux-glibc2.26-server/bundle/` includes these, unchanged, as separate programs and libraries. `build-bundle.sh` shows where each one comes from:

- [Python](https://www.python.org/) from [python-build-standalone](https://github.com/astral-sh/python-build-standalone), licensed under PSF-2.0.
- Wireshark's tshark, the libraries it loads and the musl C library, from [Alpine Linux](https://alpinelinux.org/) packages. tshark is licensed under GPL-2.0-or-later, and the libraries have their own licenses. Sources are available from [Alpine aports](https://gitlab.alpinelinux.org/alpine/aports) and from each project.
- The Python packages listed in `pyproject.toml`, and those they need.

`linux-glibc2.17-server/` holds the unchanged DuckDB 1.2.2 wheel from PyPI, licensed under MIT.

Python dependencies are listed in `pyproject.toml`, and `requirements.lock` holds the exact versions.

## Source code for GPL components

| Shipped in | Component | Version | Source |
|---|---|---|---|
| Container image | Debian `tshark`, `wireshark-common` | 4.4.19-0+deb13u1 | [Debian package source](https://deb.debian.org/debian/pool/main/w/wireshark/), or `apt-get source wireshark=4.4.19-0+deb13u1` |
| Container image | Wireshark upstream | 4.4.19 | [wireshark-4.4.19.tar.xz](https://www.wireshark.org/download/src/all-versions/wireshark-4.4.19.tar.xz) |
| `linux-glibc2.26-server/bundle/` | Alpine `tshark` | 4.6.6, Alpine v3.24 | [Alpine aports](https://gitlab.alpinelinux.org/alpine/aports/-/tree/3.24-stable/community/wireshark) |
| `linux-glibc2.26-server/bundle/` | Wireshark upstream | 4.6.6 | [wireshark-4.6.6.tar.xz](https://www.wireshark.org/download/src/all-versions/wireshark-4.6.6.tar.xz) |

If a link stops working, open an issue on this repository and the matching source will be provided for at least three years after that release. The other packages in the image come with their own license files under `/usr/share/doc`.
