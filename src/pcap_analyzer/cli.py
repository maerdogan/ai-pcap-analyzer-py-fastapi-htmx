"""Command line entry point."""
import argparse
import json
import sys

from . import __version__, engine, tshark
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
    except (tshark.TsharkError, engine.CaptureTooLarge, OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
