#!/usr/bin/env python3
"""Hydrate and resolve the stock KeyMint/FBE userspace dependency closure.

This script operates only on the fresh Android 16 dump checkout.  It never
borrows a binary or setting from an older recovery tree.  LFS objects are
hydrated in small batches, then readelf DT_NEEDED entries are followed until
no additional stock library can be found.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from collections import deque
from pathlib import Path
from typing import Iterable

SEED_TERMS = (
    "keymint",
    "keymaster",
    "gatekeeper",
    "keystore",
    "secureclock",
    "sharedsecret",
    "weaver",
    "libtee",
    "teecli",
    "teec",
    "trustonic",
    "trusty",
    "mitee",
    "mtee",
    "mcclient",
    "kmsetkey",
    "rpmb",
)

SEARCH_ROOTS = (
    "vendor/bin",
    "vendor/lib64",
    "vendor/lib",
    "vendor/etc/init",
    "vendor/etc/vintf",
    "odm/bin",
    "odm/lib64",
    "odm/lib",
    "odm/etc/init",
    "odm/etc/vintf",
    "system/system/bin",
    "system/system/lib64",
    "system/system/lib",
    "system_ext/bin",
    "system_ext/lib64",
    "system_ext/lib",
    "product/bin",
    "product/lib64",
    "product/lib",
)

# These are expected to be supplied by the TWRP 14.1 platform.  Everything
# else must either be found in the stock dump or remain an explicit failure.
PLATFORM_LIBRARIES = {
    "ld-android.so",
    "libbase.so",
    "libbinder.so",
    "libbinder_ndk.so",
    "libc++.so",
    "libc.so",
    "libcgrouprc.so",
    "libcrypto.so",
    "libcutils.so",
    "libdl.so",
    "libhardware.so",
    "libhidlbase.so",
    "libandroidicu.so",
    "libjsoncpp.so",
    "liblog.so",
    "libm.so",
    "libprocessgroup.so",
    "libprotobuf-cpp-lite.so",
    "libselinux.so",
    "libutils.so",
    "libz.so",
}


def is_lfs_pointer(path: Path) -> bool:
    try:
        return path.read_bytes()[:80].startswith(b"version https://git-lfs.github.com/spec/v1")
    except OSError:
        return False


def is_seed(root: Path, path: Path) -> bool:
    relative = rel(root, path)
    # TWRP 14.1 supplies generic Android services such as keystore2 and
    # gatekeeperd.  Seed the device/vendor HAL + TEE stack, not an entire
    # second copy of the stock system userspace.
    if relative.startswith("system/system/"):
        return False
    name = path.name.lower()
    return any(term in name for term in SEED_TERMS)


def rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def run_lfs_pull(root: Path, paths: Iterable[Path]) -> list[str]:
    pending = sorted({rel(root, path) for path in paths if path.is_file() and is_lfs_pointer(path)})
    if not pending:
        return []
    if not (root / ".git").is_dir() or not shutil.which("git"):
        return pending
    for offset in range(0, len(pending), 40):
        batch = pending[offset : offset + 40]
        command = ["git", "lfs", "pull", "--include=" + ",".join(batch), "--exclude="]
        result = subprocess.run(command, cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode:
            print("::warning::git lfs could not hydrate crypto batch: " + result.stdout[-500:])
    return [item for item in pending if is_lfs_pointer(root / item)]


def readelf_needed(path: Path) -> list[str]:
    if is_lfs_pointer(path) or not shutil.which("readelf"):
        return []
    result = subprocess.run(
        ["readelf", "-d", str(path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode:
        return []
    return sorted(set(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", result.stdout)))


def partition(path: Path, root: Path) -> str:
    return rel(root, path).split("/", 1)[0]


def library_rank(origin: Path, candidate: Path, root: Path) -> tuple[int, int, str]:
    origin_part = partition(origin, root)
    candidate_part = partition(candidate, root)
    same_partition = 0 if origin_part == candidate_part else 1
    order = {"vendor": 0, "odm": 1, "system_ext": 2, "product": 3, "system": 4}
    origin_64 = "/lib64/" in f"/{rel(root, origin)}/"
    candidate_64 = "/lib64/" in f"/{rel(root, candidate)}/"
    same_bitness = 0 if origin_64 == candidate_64 else 1
    return (same_partition, same_bitness + order.get(candidate_part, 9), rel(root, candidate))


def classify(path: Path) -> str:
    low = path.name.lower()
    for name in ("keymint", "keymaster", "gatekeeper", "secureclock", "sharedsecret", "weaver", "keystore"):
        if name in low:
            return name
    if path.suffix in {".rc", ".xml", ".conf"}:
        return "service-config"
    if "/bin/" in f"/{path.as_posix()}/":
        return "stock-service"
    return "dependency"


def collect(root: Path) -> dict:
    all_files: list[Path] = []
    for root_name in SEARCH_ROOTS:
        base = root / root_name
        if base.is_dir():
            all_files.extend(path for path in base.rglob("*") if path.is_file())

    seeds = sorted({path for path in all_files if is_seed(root, path)})
    run_lfs_pull(root, seeds)

    libraries: dict[str, list[Path]] = {}
    for path in all_files:
        if path.name.endswith(".so"):
            libraries.setdefault(path.name, []).append(path)

    closure: set[Path] = set(seeds)
    queue: deque[Path] = deque(path for path in seeds if path.suffix == ".so" or "/bin/" in f"/{rel(root, path)}/")
    parsed: set[Path] = set()
    dependencies: dict[str, list[str]] = {}
    unresolved: set[str] = set()

    while queue:
        path = queue.popleft()
        if path in parsed:
            continue
        parsed.add(path)
        needed = readelf_needed(path)
        dependencies[rel(root, path)] = needed
        for library in needed:
            candidates = libraries.get(library, [])
            if not candidates:
                if library not in PLATFORM_LIBRARIES:
                    unresolved.add(library)
                continue
            chosen = sorted(candidates, key=lambda item: library_rank(path, item, root))[0]
            if chosen not in closure:
                closure.add(chosen)
                run_lfs_pull(root, [chosen])
                queue.append(chosen)

    remaining_pointers = sorted(rel(root, path) for path in closure if is_lfs_pointer(path))
    copy_files = []
    for path in sorted(closure, key=lambda item: rel(root, item)):
        if not path.is_file() or is_lfs_pointer(path):
            continue
        copy_files.append({
            "path": rel(root, path),
            "role": classify(path),
            "bytes": path.stat().st_size,
        })

    return {
        "schema_version": 1,
        "strategy": "stock-keymint-readelf-dependency-closure",
        "source_android": 16,
        "target_recovery_base": "twrp-14.1",
        "copy_files": copy_files,
        "dependencies": dependencies,
        "unresolved_vendor_libraries": sorted(unresolved),
        "lfs_pointers": remaining_pointers,
        "evidence": {
            "keymint": [item["path"] for item in copy_files if "keymint" in item["path"].lower()],
            "keymaster": [item["path"] for item in copy_files if "keymaster" in item["path"].lower()],
            "gatekeeper": [item["path"] for item in copy_files if "gatekeeper" in item["path"].lower()],
            "secureclock": [item["path"] for item in copy_files if "secureclock" in item["path"].lower()],
            "sharedsecret": [item["path"] for item in copy_files if "sharedsecret" in item["path"].lower()],
            "weaver": [item["path"] for item in copy_files if "weaver" in item["path"].lower()],
            "init_rc": [item["path"] for item in copy_files if item["path"].endswith(".rc")],
            "vintf": [item["path"] for item in copy_files if "/vintf/" in item["path"] and item["path"].endswith(".xml")],
        },
        "seed_count": len(seeds),
        "closure_count": len(copy_files),
        "readelf_available": bool(shutil.which("readelf")),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    root = Path(args.dump).resolve()
    report = collect(root)
    output = Path(args.report).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f">> crypto seeds: {report['seed_count']}")
    print(f">> crypto closure: {report['closure_count']}")
    if report["unresolved_vendor_libraries"]:
        print("::warning::unresolved stock crypto libraries: " + ", ".join(report["unresolved_vendor_libraries"]))
    if report["lfs_pointers"]:
        print("::warning::unhydrated crypto LFS objects: " + ", ".join(report["lfs_pointers"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
