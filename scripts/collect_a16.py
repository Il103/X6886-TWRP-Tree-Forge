#!/usr/bin/env python3
"""Collect X6886 Android 16 facts with recovery-specific parsers.

This wrapper reuses Tree Forge's Collector while correcting two Android 16
cases: bare logical partition names in fs_mgr fstab, and the authority of
modules.load.recovery over normal-boot module lists. It also carries the
init-time KeyMint/Trustonic runtime-reference evidence from the hydration
report into facts.json. No value comes from an older recovery tree.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from treeforge.collect import Collector
from treeforge.common import load_json, read_text, save_json, unique

LOGICAL_NAMES = {
    "system", "system_ext", "product", "vendor", "odm",
    "vendor_dlkm", "odm_dlkm", "system_dlkm",
}
SECURITY_PROPERTY_NAMES = (
    "ro.hardware.gatekeeper", "ro.hardware.keystore", "ro.hardware.keymaster",
    "ro.vendor.mtk_tee_gp_support", "ro.vendor.mtk_tee_support",
    "ro.vendor.mtk_trustonic_tee_support", "ro.vendor.trustonic.tee.support",
)


def parse_fstab_a16(path: Path) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for raw in read_text(path).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        if len(tokens) < 3:
            continue
        android_style = (
            len(tokens) >= 5 and tokens[1].startswith("/") and (
                tokens[0].startswith(("/dev/", "LABEL=", "PARTUUID="))
                or tokens[0] in LOGICAL_NAMES or not tokens[0].startswith("/")
            )
        )
        if android_style:
            device, mount_point, fs_type = tokens[:3]
            mount_flags, fs_mgr_flags, style = tokens[3], tokens[4], "android"
        elif tokens[0].startswith("/"):
            mount_point, fs_type, device = tokens[:3]
            mount_flags, fs_mgr_flags, style = "", " ".join(tokens[3:]), "recovery"
        else:
            continue
        entries.append({
            "mount_point": mount_point, "fs_type": fs_type, "device": device,
            "mount_flags": mount_flags, "fs_mgr_flags": fs_mgr_flags,
            "style": style, "raw": line,
        })
    return entries


def collect_modules_a16(self: Collector) -> dict[str, Any]:
    roots = [
        self.dump / "vendor_boot/ramdisk/lib/modules",
        self.dump / "vendor_boot/recovery_ramdisk/lib/modules",
        self.dump / "vendor_dlkm/lib/modules",
        self.dump / "odm_dlkm/lib/modules",
        self.dump / "system_dlkm/lib/modules",
    ]
    module_files: list[str] = []
    load_files: list[dict[str, Any]] = []
    for root_index, root in enumerate(roots):
        if not root.is_dir():
            continue
        module_files.extend(str(p.relative_to(self.dump)) for p in sorted(root.rglob("*.ko")))
        for load_file in sorted(root.rglob("modules.load*")):
            if not load_file.is_file():
                continue
            self.add_source(load_file)
            names = [
                Path(line.strip()).name for line in read_text(load_file).splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            load_files.append({
                "path": str(load_file.relative_to(self.dump)),
                "modules": unique(names), "root_priority": root_index,
            })

    def priority(item: dict[str, Any]) -> tuple[int, int, int]:
        name = Path(item["path"]).name
        recovery = 2 if name == "modules.load.recovery" else 1 if "recovery" in name else 0
        return recovery, -int(item["root_priority"]), len(item["modules"])

    selected = max(load_files, key=priority) if load_files else None
    recovery_order = list(selected["modules"]) if selected else []
    return {
        "count": len(module_files), "files": unique(module_files),
        "load_files": [{"path": x["path"], "modules": x["modules"]} for x in load_files],
        "recovery_load_file": selected["path"] if selected else None,
        "recovery_load_order": recovery_order, "load_order": recovery_order,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect fresh X6886 Android 16 recovery facts")
    parser.add_argument("--dump", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--source-url", default="")
    parser.add_argument("--source-branch", default="")
    args = parser.parse_args(argv)
    Collector.parse_fstab = staticmethod(parse_fstab_a16)
    Collector.collect_modules = collect_modules_a16
    dump = Path(args.dump).resolve()
    collector = Collector(dump, load_json(args.config), args.source_url, args.source_branch)
    facts = collector.collect()
    hydration_path = dump / "crypto_hydration.json"
    if hydration_path.is_file():
        hydration = load_json(hydration_path)
        runtime_refs = hydration.get("runtime_references")
        if isinstance(runtime_refs, dict):
            facts.setdefault("crypto", {})["runtime_references"] = runtime_refs
    facts["security_properties"] = {
        key: {"value": collector.props[key], "source": collector.prop_source.get(key, "unknown") + ":" + key, "method": "direct"}
        for key in SECURITY_PROPERTY_NAMES if collector.props.get(key)
    }
    facts.setdefault("parser", {})["android16_logical_fstab"] = True
    facts["parser"]["recovery_module_order"] = "modules.load.recovery"
    save_json(args.out, facts)
    print(f">> collected facts: {args.out}")
    print(f">> status: {facts['collection']['status']}")
    selected = facts.get("kernel", {}).get("modules", {}).get("recovery_load_file")
    count = len(facts.get("kernel", {}).get("modules", {}).get("recovery_load_order", []))
    print(f">> recovery module order: {selected or 'missing'} ({count} entries)")
    refs = facts.get("crypto", {}).get("runtime_references", {})
    if refs:
        print(f">> security runtime refs carried: {len(refs.get('resolved', {}))} resolved, "
              f"{len(refs.get('unresolved', []))} unresolved")
    for message in facts["collection"]["warnings"]:
        print("::warning::" + message)
    for message in facts["collection"]["errors"]:
        print("::error::" + message)
    return 2 if facts["collection"]["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
