# Third-party software

These are shipped in `src/pcap_analyzer/web/static/vendor/`:

| Component | Version | License |
|---|---|---|
| [htmx](https://github.com/bigskysoftware/htmx) | 2.0.4 | 0BSD |
| [Apache ECharts](https://github.com/apache/echarts) | 5.6.0 | Apache-2.0 |
| [AG Grid Community](https://github.com/ag-grid/ag-grid) | 32.3.3 | MIT |
| [Archivo](https://github.com/Omnibus-Type/Archivo) font | 5.2.5 | OFL-1.1 |

The container image also includes [Wireshark's tshark](https://www.wireshark.org/), licensed under GPL-2.0-or-later. It runs as a separate program. Its source is available from the Wireshark project and from Debian.

`legacy-linux-server/bundle/` includes these, unchanged, as separate programs and libraries. `build-bundle.sh` shows where each one comes from:

- [Python](https://www.python.org/) from [python-build-standalone](https://github.com/astral-sh/python-build-standalone), licensed under PSF-2.0.
- Wireshark's tshark and the libraries it loads, from [conda-forge](https://github.com/conda-forge/wireshark-feedstock). tshark is licensed under GPL-2.0-or-later, and the libraries have their own licenses. Sources are available from conda-forge and from each project.
- The Python packages listed in `pyproject.toml`, and those they need.

Python dependencies are listed in `pyproject.toml`.
