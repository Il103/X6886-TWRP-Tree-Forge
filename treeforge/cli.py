from __future__ import annotations

import argparse
import sys

from . import __version__
from . import collect, generate, publish, validate


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="twrp-tree-forge",
        description="B E R U's evidence-driven TWRP tree generator (no build)",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("collect", help="collect facts and provenance from a dump")
    sub.add_parser("generate", help="generate a TWRP-only device tree")
    sub.add_parser("validate", help="grade static completeness")
    sub.add_parser("publish", help="create/update an output GitHub repository")
    ns, rest = parser.parse_known_args(argv)
    return {
        "collect": collect.main,
        "generate": generate.main,
        "validate": validate.main,
        "publish": publish.main,
    }[ns.command](rest)


if __name__ == "__main__":
    raise SystemExit(main())
