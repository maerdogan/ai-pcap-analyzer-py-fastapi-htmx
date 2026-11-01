#!/usr/bin/env python3
"""Download tshark and everything it needs from Alpine Linux into one folder.

Alpine's tshark runs with its own musl C library, so it does not depend on the host's glibc.
Usage: fetch-tshark.py ALPINE_BRANCH TARGET_DIR, or --list instead of TARGET_DIR to only show the packages.
"""
import gzip
import io
import sys
import tarfile
import urllib.request

MIRROR = "https://dl-cdn.alpinelinux.org/alpine"
REPOS = ("main", "community")
ARCH = "x86_64"


def get(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def read_index(branch):
    packages, provides = {}, {}
    for repo in REPOS:
        data = get(f"{MIRROR}/{branch}/{repo}/{ARCH}/APKINDEX.tar.gz")
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            text = tar.extractfile("APKINDEX").read().decode()
        for block in text.split("\n\n"):
            f = dict(line.split(":", 1) for line in block.splitlines() if ":" in line)
            if "P" not in f:
                continue
            pkg = {"name": f["P"], "version": f["V"], "repo": repo, "deps": f.get("D", "").split()}
            packages[f["P"]] = pkg
            for item in f.get("p", "").split():
                provides.setdefault(item.split("=")[0], pkg["name"])
    return packages, provides


def strip_version(dep):
    for sep in ("=", "<", ">", "~"):
        dep = dep.split(sep)[0]
    return dep


def resolve(packages, provides, root):
    wanted, todo = {}, [root]
    while todo:
        dep = todo.pop()
        name = dep if dep in packages else provides.get(dep)
        if name is None:
            raise SystemExit(f"error: no package provides {dep}")
        if name in wanted:
            continue
        wanted[name] = packages[name]
        for dep in packages[name]["deps"]:
            if not dep.startswith("!"):
                todo.append(strip_version(dep))
    return wanted


def extract(data, target):
    # An .apk is several gzip members that together form one tar stream with zero blocks between them.
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data)), ignore_zeros=True) as tar:
        for member in tar:
            if not member.name.startswith((".SIGN", ".PKGINFO", ".pre-", ".post-", ".trigger")):
                tar.extract(member, target, filter="tar")


def main():
    branch, target = sys.argv[1:3]
    packages, provides = read_index(branch)
    wanted = resolve(packages, provides, "tshark")
    for pkg in sorted(wanted.values(), key=lambda p: p["name"]):
        print(f"{pkg['name']} {pkg['version']}")
        if target != "--list":
            extract(get(f"{MIRROR}/{branch}/{pkg['repo']}/{ARCH}/{pkg['name']}-{pkg['version']}.apk"), target)


if __name__ == "__main__":
    main()
