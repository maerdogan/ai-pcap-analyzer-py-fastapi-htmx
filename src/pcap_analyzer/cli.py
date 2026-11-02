"""Command line entry point."""
import argparse
import getpass
import json
import sys

from . import __version__, compare, engine, reports, tshark
from .config import Settings


def _summary(a):
    m = a.meta
    print(f"{m['filename']}  ({'saved result' if a.cached else 'analyzed'}, id {a.id})")
    print(f"  packets {m['packets']}  connections {m['connections']}  HTTP transactions {m['transactions']}")
    if m["decryption"]:
        print(f"  TLS decryption: {m['decryption']}")
    if m["filter"]:
        print(f"  filter: {m['filter']}")
    for w in m["warnings"]:
        print(f"  warning: {w}")
    print(f"  result: {a.db_path}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pcap-analyzer")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    an = sub.add_parser("analyze", help="analyze a capture")
    an.add_argument("file")
    an.add_argument("--keylog", help="TLS key log file (SSLKEYLOGFILE)")
    an.add_argument("--rsa-key", help="RSA private key, works only for RSA key exchange")
    an.add_argument("--host", action="append", default=[], help="keep traffic of this IP or CIDR, use twice for a pair")
    an.add_argument("--port", type=int)
    an.add_argument("--start", type=float, help="epoch seconds")
    an.add_argument("--end", type=float, help="epoch seconds")
    an.add_argument("--filter", help="Wireshark display filter")
    an.add_argument("--no-cache", action="store_true")
    an.add_argument("--json", action="store_true")
    sub.add_parser("list", help="list saved analyses")
    dl = sub.add_parser("delete", help="delete a saved analysis")
    dl.add_argument("id")
    sub.add_parser("purge", help="delete analyses past their retention time")
    rp = sub.add_parser("report", help="print a report of a saved analysis as JSON")
    rp.add_argument("id")
    rp.add_argument("section", choices=["overview", "urls", "connections", "hosts", "issues", "slowest"])
    cn = sub.add_parser("connection", help="slowest requests of one TCP connection, as JSON")
    cn.add_argument("id")
    cn.add_argument("stream", type=int)
    cn.add_argument("--percent", action="store_true", help="top 10 percent instead of the first 5")
    ins = sub.add_parser("inspect", help="focused view on one traffic pair, as JSON")
    ins.add_argument("id")
    ins.add_argument("--src")
    ins.add_argument("--dst")
    ins.add_argument("--port", type=int)
    ins.add_argument("--kind", choices=["TCP", "TLS", "HTTP", "HTTPS", "HTTP/2", "HTTPS/2"])
    ins.add_argument("--url")
    ins.add_argument("--min-size", type=int)
    ins.add_argument("--size-of", choices=list(reports.SIZE_SQL), default="total")
    cp = sub.add_parser("compare", help="compare two saved analyses, as JSON")
    cp.add_argument("a")
    cp.add_argument("b")
    cp.add_argument("--two-point", action="store_true", help="match the same requests seen at two points, A nearer the client")
    ck = sub.add_parser("check", help="exit with code 2 when an analysis breaks a limit, for CI")
    ck.add_argument("id")
    ck.add_argument("--p95", type=float, help="95th percentile limit in seconds")
    ck.add_argument("--slowest", type=float, help="limit for the slowest request in seconds")
    ck.add_argument("--error-rate", type=float, help="limit for failed requests in percent")
    sv = sub.add_parser("serve", help="start the web interface")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--cert", help="TLS certificate file")
    sv.add_argument("--key", help="TLS private key file")
    sub.add_parser("hash-password", help="create a value for PCAP_ANALYZER_ADMIN_PASSWORD_HASH")
    args = ap.parse_args(argv)
    settings = Settings()
    try:
        if args.cmd == "analyze":
            if len(args.host) > 2:
                ap.error("--host can be given at most twice")
            hosts = args.host + [None, None]
            flt = tshark.Filter(hosts[0], hosts[1], args.port, args.start, args.end, args.filter)
            a = engine.analyze(args.file, args.keylog, args.rsa_key, flt, settings, not args.no_cache)
            print(json.dumps(a.meta, indent=2)) if args.json else _summary(a)
        elif args.cmd == "list":
            for m in engine.list_analyses(settings):
                print(m["id"], m["filename"], m["packets"], m["transactions"])
        elif args.cmd == "delete":
            return 0 if engine.delete(args.id, settings) else 1
        elif args.cmd == "purge":
            print(engine.purge(settings))
        elif args.cmd == "serve":
            from .web.server import run
            run(settings, args.host, args.port, args.cert, args.key)
        elif args.cmd == "hash-password":
            from .web.auth import hash_password
            print(hash_password(getpass.getpass("Password: ")))
        elif args.cmd == "compare":
            a, b = engine.open_analysis(args.a, settings), engine.open_analysis(args.b, settings)
            with a.connect() as da, b.connect() as db:
                out = compare.two_point(da, db) if args.two_point else compare.captures(da, db, reports.Inspect(), reports.Inspect())
            print(json.dumps(out, indent=2, default=str))
        elif args.cmd == "check":
            a = engine.open_analysis(args.id, settings)
            with a.connect() as db:
                out = reports.check(db, args.p95, args.error_rate, args.slowest)
            print(json.dumps(out, indent=2))
            return 2 if out["broken"] else 0
        elif args.cmd in ("report", "connection", "inspect"):
            a = engine.open_analysis(args.id, settings)
            with a.connect() as db:
                if args.cmd == "connection":
                    out = reports.connection_top(db, args.stream, args.percent)
                elif args.cmd == "inspect":
                    out = reports.inspect(db, reports.Inspect(args.src, args.dst, args.port, args.kind, args.url, args.min_size, args.size_of))
                else:
                    out = {"overview": lambda: reports.overview(db, a.meta), "urls": lambda: reports.url_groups(db),
                           "connections": lambda: reports.connections(db), "hosts": lambda: reports.hosts(db),
                           "issues": lambda: reports.issues(db, a.meta), "slowest": lambda: reports.slowest(db)}[args.section]()
            print(json.dumps(out, indent=2, default=str))
    except (tshark.TsharkError, engine.CaptureTooLarge, engine.NotFound, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
