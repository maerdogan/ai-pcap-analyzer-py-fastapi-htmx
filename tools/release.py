#!/usr/bin/env python3
"""Check that a tag can be released, and print its release notes.

Usage: release.py vX.Y.Z
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE_FILES = ("docker/compose.yaml", "kubernetes/base/deployment.yaml")
HEADING = re.compile(r"^## (\S+) \((\d{4}-\d{2}-\d{2})\)$", re.M)


def version():
    return re.search(r'__version__ = "(.+)"', (ROOT / "src/pcap_analyzer/__init__.py").read_text())[1]


def notes(wanted):
    text = (ROOT / "RELEASE_NOTES.md").read_text()
    found = list(HEADING.finditer(text))
    for here, after in zip(found, found[1:] + [None]):
        if here[1] == wanted:
            return text[here.end():after.start() if after else len(text)].strip()
    return ""


def problems(tag):
    current = version()
    found = []
    if tag != f"v{current}":
        found.append(f"the tag {tag} does not match version {current}")
    if not notes(current):
        found.append(f"RELEASE_NOTES.md has no section for {current}")
    for name in IMAGE_FILES:
        tags = re.findall(r"pcap-analyzer:([\w.-]+)", (ROOT / name).read_text())
        if not tags or any(t != current for t in tags):
            found.append(f"{name} does not use the image {current}")
    return found


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    found = problems(sys.argv[1])
    if found:
        sys.exit("\n".join(found))
    print(notes(version()))


if __name__ == "__main__":
    main()
