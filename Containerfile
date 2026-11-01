FROM python:3.13-slim

RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
    && apt-get update \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && rm -rf /app/src

RUN useradd --uid 10001 --create-home --home-dir /home/analyzer analyzer && mkdir /data && chown analyzer /data
ENV PCAP_ANALYZER_WORKDIR=/data HOME=/tmp
USER 10001
EXPOSE 8000
VOLUME /data
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["pcap-analyzer", "serve", "--host", "0.0.0.0", "--port", "8000"]
