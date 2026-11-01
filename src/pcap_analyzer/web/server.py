"""Start the web server, refusing setups that would send secrets in clear text."""
import ipaddress

import uvicorn

from .app import create_app


def _is_loopback(host):
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def run(settings, host, port, cert=None, key=None):
    if bool(cert) != bool(key):
        raise ValueError("--cert and --key must be given together")
    if not cert and not settings.behind_proxy and not _is_loopback(host):
        raise ValueError("Passwords and TLS keys need HTTPS: give --cert and --key, or set PCAP_ANALYZER_BEHIND_PROXY=1 behind an HTTPS proxy")
    app = create_app(settings, secure_cookie=bool(cert) or settings.behind_proxy)
    uvicorn.run(app, host=host, port=port, ssl_certfile=cert, ssl_keyfile=key, proxy_headers=settings.behind_proxy, log_level="info")
