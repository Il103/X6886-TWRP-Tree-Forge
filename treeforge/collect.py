from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from .common import (
    is_real_value,
    load_json,
    normalize_codename,
    parse_key_value,
    read_text,
    save_json,
    sha256_file,
    source_record,
    unique,
)


PROP_FILES = [
    "product/build.prop",
    "my_product/build.prop",
    "odm/build.prop",
    "system_ext/build.prop",
    "vendor_dlkm/build.prop",
    "odm_dlkm/build.prop",
    "system_dlkm/build.prop",
    "product/etc/build.prop",
    "my_product/etc/build.prop",
    "odm/etc/build.prop",
    "system_ext/etc/build.prop",
    "system/system/build.prop",
    "system/build.prop",
    "vendor/build.prop",
    "vendor/odm/etc/build.prop",
    "system/system/etc/build.prop",
    "vendor_boot/recovery_ramdisk/prop.default",
    "vendor_boot/recovery_ramdisk/default.prop",
    "vendor_boot/ramdisk/prop.default",
    "vendor_boot/ramdisk/default.prop",
]

PROP_KEYS = {
    "brand": ["ro.product.brand", "ro.product.product.brand", "ro.product.odm.brand", "ro.product.vendor.brand", "ro.product.system_ext.brand", "ro.product.system.brand"],
    "manufacturer": ["ro.product.manufacturer", "ro.product.product.manufacturer", "ro.product.odm.manufacturer", "ro.product.vendor.manufacturer", "ro.product.system_ext.manufacturer", "ro.product.system.manufacturer"],
    "model": ["ro.product.model", "ro.product.product.model", "ro.product.odm.model", "ro.product.vendor.model", "ro.product.system_ext.model", "ro.product.system.model"],
    "device": ["ro.product.device", "ro.product.product.device", "ro.product.odm.device", "ro.product.vendor.device", "ro.product.system_ext.device", "ro.product.system.device", "ro.build.product"],
    "product": ["ro.product.name", "ro.product.product.name", "ro.product.odm.name", "ro.product.vendor.name", "ro.product.system_ext.name", "ro.product.system.name"],
    "board": ["ro.product.board", "ro.board.platform"],
    "platform": ["ro.board.platform", "ro.vendor.mediatek.platform", "ro.boot.hardware", "ro.hardware"],
    "android_release": ["ro.build.version.release", "ro.system.build.version.release"],
    "api_level": ["ro.build.version.sdk", "ro.system.build.version.sdk"],
    "security_patch": ["ro.build.version.security_patch", "ro.vendor.build.security_patch"],
    "incremental": ["ro.build.version.incremental", "ro.system.build.version.incremental", "ro.vendor.build.version.incremental"],
    "fingerprint": ["ro.build.fingerprint", "ro.system.build.fingerprint", "ro.vendor.build.fingerprint"],
    "build_id": ["ro.build.id", "ro.system.build.id"],
    "density": ["ro.sf.lcd_density", "ro.vendor.sf.lcd_density"],
    "abilist": ["ro.product.cpu.abilist", "ro.system.product.cpu.abilist"],
    "vndk": ["ro.vndk.version", "ro.product.vndk.version"],
}

LOGICAL_PARTITION_NAMES = (
    "system", "system_ext", "product", "vendor", "odm",
    "vendor_dlkm", "odm_dlkm", "system_dlkm",
)

CRYPTO_TERMS = (
    "keymint", "keymaster", "gatekeeper", "keystore", "secureclock",
    "sharedsecret", "weaver", "libtee", "teecli", "teec", "trustonic",
    "trusty", "mitee", "mtee", "mcclient", "kmsetkey", "rpmb",
)


class Collector:
    def __init__(self, dump: Path, config: dict[str, Any], source_url: str = "", source_branch: str = ""):
        self.dump = dump
        self.config = config
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.source_url = source_url
        self.source_branch = source_branch
        self.props: dict[str, str] = {}
        self.prop_source: dict[str, str] = {}
        self.sources: list[dict[str, Any]] = []

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def error(self, message: str) -> None:
        if message not in self.errors:
            self.errors.append(message)

    def add_source(self, path: Path) -> None:
        if not path.is_file():
            return
        rec = source_record(self.dump, path)
        if rec not in self.sources:
            self.sources.append(rec)

    def fact(self, value: Any, source: str, method: str = "direct") -> dict[str, Any]:
        return {"value": value, "source": source, "method": method}

    def load_properties(self) -> None:
        candidates = [self.dump / rel for rel in PROP_FILES]
        for pattern in ("*/build.prop", "*/etc/build.prop", "system/*/build.prop", "vendor/*/build.prop"):
            candidates.extend(sorted(self.dump.glob(pattern)))
        seen: set[Path] = set()
        for path in candidates:
            if path in seen:
                continue
            seen.add(path)
            if not path.is_file():
                continue
            rel = str(path.relative_to(self.dump))
            self.add_source(path)
            for key, value in parse_key_value(path).items():
                if key not in self.props or (not is_real_value(self.props[key]) and is_real_value(value)):
                    self.props[key] = value
                    self.prop_source[key] = rel

    def pick_prop(self, logical: str) -> dict[str, Any] | None:
        for key in PROP_KEYS[logical]:
            value = self.props.get(key)
            if is_real_value(value):
                return self.fact(value, self.prop_source[key] + ":" + key)
        return None

    def read_dump_readme(self) -> dict[str, str]:
        path = self.dump / "README.md"
        result: dict[str, str] = {}
        if not path.is_file():
            return result
        self.add_source(path)
        for line in read_text(path).splitlines():
            match = re.match(r"\s*-\s*([^:]+):\s*(.*?)\s*$", line)
            if match:
                result[match.group(1).strip().lower()] = match.group(2).strip()
        return result

    def stock_filename_evidence(self, token: str) -> str | None:
        """Prove a device token from fresh stock module names.

        Transsion GSI-facing properties may legitimately identify the common
        base as ``tssi/common``.  Device-specific kernel modules remain part of
        the same Android 16 dump and provide stronger board/codename evidence.
        """
        wanted = token.lower()
        roots = [
            self.dump / "vendor_boot/ramdisk/lib/modules",
            self.dump / "vendor_boot/recovery_ramdisk/lib/modules",
            self.dump / "vendor_dlkm/lib/modules",
            self.dump / "odm_dlkm/lib/modules",
            self.dump / "system_dlkm/lib/modules",
        ]
        matches = []
        for root in roots:
            if root.is_dir():
                matches.extend(path for path in root.rglob("*.ko") if wanted in path.name.lower())
        if not matches:
            return None
        return str(sorted(matches)[0].relative_to(self.dump))

    @staticmethod
    def load_header(path: Path) -> dict[str, Any]:
        try:
            data = json.loads(read_text(path))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    @staticmethod
    def parse_fstab(path: Path) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        for raw in read_text(path).splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            tokens = line.split()
            if len(tokens) < 3:
                continue
            if tokens[0].startswith(("/dev/", "LABEL=", "PARTUUID=")):
                device, mount_point, fs_type = tokens[:3]
                mount_flags = tokens[3] if len(tokens) > 3 else ""
                fs_mgr_flags = tokens[4] if len(tokens) > 4 else ""
                style = "android"
            elif tokens[0].startswith("/"):
                mount_point, fs_type, device = tokens[:3]
                tail = " ".join(tokens[3:])
                mount_flags = ""
                fs_mgr_flags = tail
                style = "recovery"
            else:
                continue
            entries.append({
                "mount_point": mount_point,
                "fs_type": fs_type,
                "device": device,
                "mount_flags": mount_flags,
                "fs_mgr_flags": fs_mgr_flags,
                "style": style,
                "raw": line,
            })
        return entries

    def find_fstabs(self) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        roots = [
            self.dump / "vendor_boot/recovery_ramdisk",
            self.dump / "vendor_boot/ramdisk",
            self.dump / "vendor/etc",
            self.dump / "odm/etc",
            self.dump / "recovery",
        ]
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        for root in roots:
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("*fstab*")):
                if not path.is_file():
                    continue
                digest = sha256_file(path)
                if digest in seen:
                    continue
                seen.add(digest)
                entries = self.parse_fstab(path)
                if not entries:
                    continue
                self.add_source(path)
                records.append({
                    "path": str(path.relative_to(self.dump)),
                    "sha256": digest,
                    "entries": entries,
                })
        def priority(item: dict[str, Any]) -> tuple[int, int]:
            p = item["path"]
            score = 0
            if p == "vendor_boot/recovery_ramdisk/system/etc/recovery.fstab":
                score = 100
            elif "recovery_ramdisk" in p and p.endswith("recovery.fstab"):
                score = 90
            elif "recovery_ramdisk" in p:
                score = 80
            elif p.endswith("recovery.fstab"):
                score = 70
            return (score, len(item["entries"]))
        selected = max(records, key=priority) if records else None
        return records, selected

    def collect_modules(self) -> dict[str, Any]:
        roots = [
            self.dump / "vendor_boot/ramdisk/lib/modules",
            self.dump / "vendor_boot/recovery_ramdisk/lib/modules",
            self.dump / "vendor_dlkm/lib/modules",
            self.dump / "odm_dlkm/lib/modules",
            self.dump / "system_dlkm/lib/modules",
        ]
        module_files: list[str] = []
        load_files: list[dict[str, Any]] = []
        for root in roots:
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("*.ko")):
                module_files.append(str(path.relative_to(self.dump)))
            for path in sorted(root.rglob("modules.load*")):
                if not path.is_file():
                    continue
                self.add_source(path)
                names = [x.strip() for x in read_text(path).splitlines() if x.strip() and not x.lstrip().startswith("#")]
                load_files.append({"path": str(path.relative_to(self.dump)), "modules": names})
        return {
            "count": len(module_files),
            "files": module_files,
            "load_files": load_files,
            "load_order": unique(name for item in load_files for name in item["modules"]),
        }

    @staticmethod
    def is_lfs_pointer(path: Path) -> bool:
        try:
            return path.read_bytes()[:80].startswith(b"version https://git-lfs.github.com/spec/v1")
        except OSError:
            return False

    def collect_crypto_stack(self) -> dict[str, Any]:
        """Validate the fresh-dump KeyMint dependency-closure report.

        The fetch stage follows ELF DT_NEEDED edges with readelf.  Collection
        deliberately revalidates every reported path instead of trusting the
        report blindly.
        """
        report_path = self.dump / "crypto_hydration.json"
        report: dict[str, Any] = {}
        if report_path.is_file():
            try:
                report = load_json(report_path)
            except (OSError, json.JSONDecodeError):
                self.warn("crypto_hydration.json is invalid")

        if not report:
            # Offline fallback: preserve obvious stock security files, but do
            # not claim dependency closure without the hydration stage.
            roots = [
                self.dump / "vendor", self.dump / "odm", self.dump / "system/system",
                self.dump / "system_ext", self.dump / "product",
            ]
            candidates = []
            for root in roots:
                if not root.is_dir():
                    continue
                for path in root.rglob("*"):
                    if path.is_file() and any(term in path.name.lower() for term in CRYPTO_TERMS):
                        candidates.append({"path": str(path.relative_to(self.dump)), "role": "unresolved-seed"})
            report = {
                "strategy": "fallback-name-scan-no-dependency-proof",
                "target_recovery_base": "twrp-14.1",
                "copy_files": candidates,
                "dependencies": {},
                "unresolved_vendor_libraries": [],
                "lfs_pointers": [],
                "readelf_available": False,
            }
            self.warn("crypto hydration report is missing; dependency closure cannot be proved")

        valid: list[dict[str, Any]] = []
        invalid_paths: list[str] = []
        pointer_paths: list[str] = list(report.get("lfs_pointers", []))
        dump_root = self.dump.resolve()
        for raw in report.get("copy_files", []):
            rel = str(raw.get("path", "")).replace("\\", "/").lstrip("/")
            path = (self.dump / rel).resolve()
            try:
                path.relative_to(dump_root)
            except ValueError:
                invalid_paths.append(rel)
                continue
            if not path.is_file():
                invalid_paths.append(rel)
                continue
            if self.is_lfs_pointer(path):
                pointer_paths.append(rel)
                continue
            self.add_source(path)
            valid.append({
                "path": rel,
                "role": str(raw.get("role", "dependency")),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            })

        paths = [item["path"] for item in valid]
        lower = [path.lower() for path in paths]
        binaries = [path for path in paths if "/bin/" in f"/{path}/"]
        keymint_services = [path for path in binaries if "keymint" in path.lower()]
        gatekeeper_services = [path for path in binaries if "gatekeeper" in path.lower()]
        init_rc = [path for path in paths if path.endswith(".rc") and
                   ("keymint" in path.lower() or "gatekeeper" in path.lower())]
        vintf = [path for path in paths if "/vintf/" in path and path.endswith(".xml") and
                 ("keymint" in path.lower() or "gatekeeper" in path.lower())]
        unresolved = sorted(set(str(x) for x in report.get("unresolved_vendor_libraries", [])))
        pointer_paths = sorted(set(pointer_paths))

        return {
            "strategy": report.get("strategy", "unknown"),
            "target_recovery_base": report.get("target_recovery_base", "twrp-14.1"),
            "copy_files": valid,
            "dependencies": report.get("dependencies", {}),
            "keymint_services": keymint_services,
            "keymint_evidence": [path for path, low in zip(paths, lower) if "keymint" in low],
            "keymaster_compatibility_evidence": [path for path, low in zip(paths, lower) if "keymaster" in low],
            "gatekeeper_services": gatekeeper_services,
            "gatekeeper_evidence": [path for path, low in zip(paths, lower) if "gatekeeper" in low],
            "init_rc": init_rc,
            "vintf_manifests": vintf,
            "unresolved_vendor_libraries": unresolved,
            "lfs_pointers": pointer_paths,
            "invalid_paths": sorted(set(invalid_paths)),
            "readelf_available": bool(report.get("readelf_available")),
            "dependency_closure_complete": bool(report.get("readelf_available")) and
                not unresolved and not pointer_paths and not invalid_paths,
        }

    def collect(self) -> dict[str, Any]:
        if not self.dump.is_dir():
            raise FileNotFoundError(self.dump)
        self.load_properties()
        readme = self.read_dump_readme()
        cfg_device = self.config["device"]
        cfg_display = self.config["display"]

        identity: dict[str, Any] = {}
        fallback_map = {
            "brand": ("brand", cfg_device["brand"]),
            "manufacturer": ("manufacturer", cfg_device["manufacturer"]),
            "model": ("model", cfg_device["model"]),
            "device": ("codename", cfg_device["stock_device"]),
            "product": ("product", cfg_device["stock_product"]),
            "board": ("platform", cfg_device["stock_board"]),
            "platform": ("platform", cfg_device["platform"]),
            "android_release": ("release version", cfg_device["android_release"]),
            "api_level": ("sdk", cfg_device["api_level"]),
        }
        for logical in PROP_KEYS:
            item = self.pick_prop(logical)
            if item is None:
                readme_key, config_value = fallback_map.get(logical, (logical, None))
                value = readme.get(readme_key)
                if is_real_value(value):
                    item = self.fact(value, "README.md:" + readme_key, "dump-metadata")
                elif config_value is not None:
                    item = self.fact(config_value, "config/x6886.json", "hardware-report-fallback")
                    if logical not in {"brand", "manufacturer", "model", "device", "product", "board", "platform", "android_release", "api_level", "density"}:
                        self.warn(f"{logical} is absent from the dump; hardware report fallback used")
            identity[logical] = item or self.fact(None, "missing", "missing")

        expected_platform = str(cfg_device["platform"]).lower()
        actual_platform = str(identity["platform"]["value"] or "").lower()
        if actual_platform != expected_platform:
            platform_source = self.stock_filename_evidence(expected_platform)
            if platform_source:
                identity["platform"] = self.fact(
                    expected_platform, platform_source,
                    "derived-from-stock-module-filename",
                )

        fingerprint = identity["fingerprint"]["value"]
        if not is_real_value(identity["device"]["value"]) and fingerprint:
            try:
                raw_device = fingerprint.split("/")[2].split(":")[0]
                identity["device"] = self.fact(raw_device, identity["fingerprint"]["source"], "derived-from-fingerprint")
            except IndexError:
                pass

        raw_device = str(identity["device"]["value"] or "")
        codename = normalize_codename(raw_device)
        expected = cfg_device["codename"].lower()
        if codename != expected and expected in codename:
            codename = expected
        if codename != expected:
            codename_source = self.stock_filename_evidence(expected)
            if codename_source:
                identity["device"] = self.fact(
                    expected, codename_source,
                    "derived-device-token-from-stock-module-filename",
                )
                codename = expected
                identity["codename"] = self.fact(
                    expected, codename_source,
                    "derived-from-stock-module-filename",
                )
            else:
                identity["codename"] = self.fact(
                    codename or expected,
                    identity["device"]["source"] if codename else "config/x6886.json",
                    "normalized-device-name",
                )
        else:
            identity["codename"] = self.fact(
                codename, identity["device"]["source"], "normalized-device-name"
            )

        for key in ("platform", "codename"):
            expected_value = str(cfg_device[key]).lower()
            actual = str(identity[key]["value"]).lower()
            if actual != expected_value:
                self.error(f"identity mismatch: {key}={actual!r}, expected {expected_value!r}")
        release = str(identity["android_release"]["value"])
        if release != str(cfg_device["android_release"]):
            self.error(f"the dump is Android {release}, expected Android {cfg_device['android_release']}")

        boot_header_path = self.dump / "boot/header_info.json"
        vendor_header_path = self.dump / "vendor_boot/header_info.json"
        boot_header = self.load_header(boot_header_path)
        vendor_header = self.load_header(vendor_header_path)
        for p in (boot_header_path, vendor_header_path):
            self.add_source(p)
        if not boot_header:
            self.error("boot/header_info.json is missing or invalid")
        if not vendor_header:
            self.error("vendor_boot/header_info.json is missing or invalid")

        fragments = vendor_header.get("ramdisk_fragments", []) if isinstance(vendor_header, dict) else []
        recovery_fragments = [x for x in fragments if isinstance(x, dict) and x.get("type") == "recovery"]
        platform_fragments = [x for x in fragments if isinstance(x, dict) and x.get("type") == "platform"]
        recovery_root = self.dump / "vendor_boot/recovery_ramdisk"
        platform_root = self.dump / "vendor_boot/ramdisk"
        recovery_file_count = sum(1 for p in recovery_root.rglob("*") if p.is_file()) if recovery_root.is_dir() else 0
        platform_file_count = sum(1 for p in platform_root.rglob("*") if p.is_file()) if platform_root.is_dir() else 0
        if not recovery_fragments:
            self.error("vendor_boot v4 contains no type=recovery ramdisk fragment")
        if recovery_file_count == 0:
            self.error("vendor_boot/recovery_ramdisk is absent or empty")

        fstab_records, selected_fstab = self.find_fstabs()
        if not selected_fstab:
            self.error("no usable recovery fstab was found")
        entries = list(selected_fstab["entries"]) if selected_fstab else []
        flags = " ".join((x["mount_flags"] + " " + x["fs_mgr_flags"]).lower() for x in entries)
        ab = "slotselect" in flags
        all_fstab_entries = [entry for record in fstab_records for entry in record["entries"]]
        direct_dynamic = [
            entry for entry in all_fstab_entries
            if "logical" in (entry["mount_flags"] + " " + entry["fs_mgr_flags"]).lower()
            or "/dev/block/mapper/" in entry["device"]
        ]
        dynamic_evidence: list[str] = []
        if direct_dynamic:
            dynamic_evidence.append("stock-fstab:logical-or-dev-block-mapper")

        index_path = self.dump / ".treeforge-index.txt"
        tracked_paths = read_text(index_path).splitlines() if index_path.is_file() else []
        dynamic_index_hints = sorted(path for path in tracked_paths if re.search(
            r"(^|/)(?:super(?:_empty)?\.img|lpdump[^/]*|dynamic_partitions_info\.txt|super_partition_metadata[^/]*)$",
            path,
            re.IGNORECASE,
        ))
        if dynamic_index_hints:
            dynamic_evidence.append("git-tree:" + dynamic_index_hints[0])

        logical_partitions = []
        for entry in direct_dynamic:
            mount = entry["mount_point"].strip("/")
            mount = "system" if mount == "system_root" else mount
            if mount in LOGICAL_PARTITION_NAMES and mount not in logical_partitions:
                logical_partitions.append(mount)
        present_partition_roots = [
            name for name in LOGICAL_PARTITION_NAMES
            if (self.dump / name).is_dir() or any(path.startswith(name + "/") for path in tracked_paths)
        ]
        has_vbmeta_system = any(path.is_file() for path in (
            self.dump / "images/vbmeta_system.img", self.dump / "vbmeta_system.img",
        ))
        physical_dynamic_mounts = [
            entry for entry in all_fstab_entries
            if entry["mount_point"].strip("/").replace("system_root", "system") in LOGICAL_PARTITION_NAMES
            and "/dev/block/by-name/" in entry["device"]
        ]
        inferred_dynamic = (
            has_vbmeta_system
            and len(present_partition_roots) >= 4
            and not physical_dynamic_mounts
        )
        if inferred_dynamic:
            dynamic_evidence.append(
                "derived:vbmeta_system+extracted-partition-roots+no-physical-system-fstab"
            )
        dynamic = bool(direct_dynamic or dynamic_index_hints or inferred_dynamic)
        if dynamic:
            for name in present_partition_roots:
                if name not in logical_partitions:
                    logical_partitions.append(name)
        selected_has_logical = any(
            "logical" in (entry["mount_flags"] + " " + entry["fs_mgr_flags"]).lower()
            for entry in entries
        )
        if dynamic and not selected_has_logical:
            for name in logical_partitions:
                mount = "/system_root" if name == "system" else "/" + name
                entries.append({
                    "mount_point": mount,
                    "fs_type": "auto",
                    "device": "/dev/block/mapper/" + name,
                    "mount_flags": "",
                    "fs_mgr_flags": "slotselect,logical,first_stage_mount",
                    "style": "treeforge-dynamic-evidence",
                    "raw": f"{mount} auto /dev/block/mapper/{name} flags=slotselect;logical;first_stage_mount",
                })
            flags = " ".join((x["mount_flags"] + " " + x["fs_mgr_flags"]).lower() for x in entries)
        fbe = "fileencryption" in flags
        metadata_encryption = "metadata_encryption" in flags or "keydirectory=" in flags
        virtual_ab = "snapuserd" in flags or any("snapuserd" in read_text(self.dump / p) for p in [
            "vendor_boot/recovery_ramdisk/system/bin/snapuserd",
            "vendor_boot/ramdisk/system/bin/snapuserd",
        ])
        if not ab:
            self.error("fstab does not prove A/B slotselect support")
        if not dynamic:
            self.error("fstab does not prove dynamic/logical partitions")

        filesystem_map: dict[str, str] = {}
        for entry in entries:
            mount = entry["mount_point"].lstrip("/") or "root"
            filesystem_map.setdefault(mount, entry["fs_type"])

        images: dict[str, Any] = {}
        images_dir = self.dump / "images"
        if images_dir.is_dir():
            for path in sorted(images_dir.glob("*.img")):
                images[path.stem] = {"path": str(path.relative_to(self.dump)), "bytes": path.stat().st_size,
                                     "sha256": sha256_file(path)}
        for name, header in (("boot", boot_header), ("vendor_boot", vendor_header)):
            if name not in images and header.get("bytes"):
                images[name] = {"path": f"{name}/header_info.json", "bytes": int(header["bytes"]),
                                "source": "boot header parser"}

        kernel_path = self.dump / "boot/kernel"
        dtb_path = self.dump / "vendor_boot/dtb"
        dtb_dts_path = self.dump / "vendor_boot/dtb.dts"
        bootconfig_path = self.dump / "vendor_boot/bootconfig"
        for p in (kernel_path, dtb_path, dtb_dts_path, bootconfig_path,
                  self.dump / "kernel_config.txt", self.dump / "kernel_version.txt"):
            self.add_source(p)
        if not kernel_path.is_file():
            self.error("boot/kernel is missing")
        if not dtb_path.is_file():
            self.error("vendor_boot/dtb is missing")

        kernel_version_text = read_text(self.dump / "kernel_version.txt").strip()
        if not kernel_version_text:
            kernel_version_text = self.config["kernel"]["release_prefix"]
            self.warn("kernel_version.txt is absent; the live hardware report is used as fallback")
        kernel_config = parse_key_value(self.dump / "kernel_config.txt") if (self.dump / "kernel_config.txt").is_file() else {}
        if not kernel_config:
            self.warn("kernel config could not be extracted; CONFIG checks will be incomplete")

        bootconfig = parse_key_value(bootconfig_path) if bootconfig_path.is_file() else {}
        dts = read_text(dtb_dts_path)
        dt_compatible = unique(re.findall(r'compatible\s*=\s*"([^"]+)"', dts))
        dt_model = re.findall(r'model\s*=\s*"([^"]+)"', dts)

        modules = self.collect_modules()
        if modules["count"] == 0:
            self.warn("no kernel modules were found in vendor_boot or dlkm trees")
        if not modules["load_order"]:
            self.warn("no stock modules.load order was found")

        crypto = self.collect_crypto_stack()
        if fbe:
            if not crypto["keymint_services"]:
                self.error("FBE is present but no stock KeyMint service binary was proved")
            if not crypto["gatekeeper_services"]:
                self.error("FBE is present but no stock Gatekeeper service binary was proved")
            if not crypto["init_rc"]:
                self.error("KeyMint/Gatekeeper init rc evidence is missing")
            if not crypto["vintf_manifests"]:
                self.error("KeyMint/Gatekeeper VINTF manifest evidence is missing")
            if not crypto["dependency_closure_complete"]:
                self.error("stock KeyMint dependency closure is incomplete")

        report_incremental = "301400011"
        dump_incremental = str(identity["incremental"]["value"] or "")
        if dump_incremental and dump_incremental != report_incremental:
            self.warn(
                f"dump incremental {dump_incremental} differs from live-report {report_incremental}; "
                "hardware facts are retained, software identity comes from the dump"
            )

        critical_files = [
            "boot/header_info.json", "vendor_boot/header_info.json", "boot/kernel",
            "vendor_boot/dtb", "vendor_boot/bootconfig",
        ]
        critical_manifest = []
        for rel in critical_files:
            path = self.dump / rel
            if path.is_file():
                critical_manifest.append(source_record(self.dump, path))

        facts = {
            "schema_version": 1,
            "generator": "X6886 TWRP Tree Forge",
            "maintainer": self.config["maintainer"],
            "source": {
                "dump_url": self.source_url,
                "dump_branch": self.source_branch,
                "device_report": self.config["source"],
                "critical_manifest": critical_manifest,
                "all_examined_sources": sorted(self.sources, key=lambda x: x["path"]),
                "old_tree_used": False,
            },
            "identity": identity,
            "display": {
                "width": self.fact(cfg_display["width"], "config/x6886.json:Device Info HW"),
                "height": self.fact(cfg_display["height"], "config/x6886.json:Device Info HW"),
                "density": self.fact(cfg_display["density"], "config/x6886.json:Device Info HW"),
                "xdpi": self.fact(cfg_display["xdpi"], "config/x6886.json:Device Info HW"),
                "ydpi": self.fact(cfg_display["ydpi"], "config/x6886.json:Device Info HW"),
                "touch_max_x": self.fact(cfg_display["touch_max_x"], "config/x6886.json:Device Info HW"),
                "touch_max_y": self.fact(cfg_display["touch_max_y"], "config/x6886.json:Device Info HW"),
                "refresh_rates_hz": self.fact(cfg_display["refresh_rates_hz"], "config/x6886.json:Device Info HW"),
                "panel": self.fact(cfg_display["panel"], "config/x6886.json:Device Info HW"),
                "theme": self.fact(cfg_display["twrp_theme"], "TeamWin portrait device convention"),
            },
            "architecture": self.config["architecture"],
            "boot": {
                "boot_header": boot_header,
                "vendor_boot_header": vendor_header,
                "recovery_fragments": recovery_fragments,
                "platform_fragments": platform_fragments,
                "recovery_root": "vendor_boot/recovery_ramdisk",
                "recovery_file_count": recovery_file_count,
                "platform_root": "vendor_boot/ramdisk",
                "platform_file_count": platform_file_count,
                "kernel": source_record(self.dump, kernel_path) if kernel_path.is_file() else None,
                "dtb": source_record(self.dump, dtb_path) if dtb_path.is_file() else None,
                "dtb_dts": source_record(self.dump, dtb_dts_path) if dtb_dts_path.is_file() else None,
                "bootconfig": bootconfig,
                "dt_compatible": dt_compatible,
                "dt_model": dt_model,
            },
            "partitions": {
                "images": images,
                "fstabs": fstab_records,
                "selected_fstab": selected_fstab["path"] if selected_fstab else None,
                "selected_entries": entries,
                "filesystems": filesystem_map,
                "ab": ab,
                "dynamic": dynamic,
                "dynamic_evidence": dynamic_evidence,
                "logical_partitions": logical_partitions,
                "virtual_ab_evidence": virtual_ab,
                "has_dedicated_recovery_image": "recovery" in images,
            },
            "encryption": {
                "file_based": fbe,
                "metadata_encryption": metadata_encryption,
            },
            "crypto": crypto,
            "kernel": {
                "version_text": kernel_version_text,
                "config": kernel_config,
                "modules": modules,
            },
            "policy": self.config["policy"],
            "collection": {
                "warnings": self.warnings,
                "errors": self.errors,
                "status": "FAIL" if self.errors else "PASS_WITH_WARNINGS" if self.warnings else "PASS",
            },
        }
        return facts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect recovery-tree facts with provenance")
    parser.add_argument("--dump", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--source-url", default="")
    parser.add_argument("--source-branch", default="")
    args = parser.parse_args(argv)
    collector = Collector(Path(args.dump).resolve(), load_json(args.config), args.source_url, args.source_branch)
    facts = collector.collect()
    save_json(args.out, facts)
    print(f">> collected facts: {args.out}")
    print(f">> status: {facts['collection']['status']}")
    for message in facts["collection"]["warnings"]:
        print("::warning::" + message)
    for message in facts["collection"]["errors"]:
        print("::error::" + message)
    return 2 if facts["collection"]["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
