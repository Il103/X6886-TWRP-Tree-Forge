from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from .common import copy_file, load_json, mkdir_clean, read_text, save_json, write_text


def fv(facts: dict[str, Any], group: str, key: str, default: Any = None) -> Any:
    value = facts.get(group, {}).get(key, default)
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value


def mk_list(name: str, values: list[str], append: bool = False) -> str:
    values = [x for x in values if x]
    if not values:
        return ""
    op = "+=" if append else ":="
    lines = [f"{name} {op} \\"]
    for index, item in enumerate(values):
        suffix = " \\" if index + 1 < len(values) else ""
        lines.append(f"    {item}{suffix}")
    return "\n".join(lines)


def shell_safe_version(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "-", value).strip("-")


class Generator:
    def __init__(self, dump: Path, facts: dict[str, Any], config: dict[str, Any], out: Path):
        self.dump = dump
        self.facts = facts
        self.config = config
        self.out = out
        self.copied: list[dict[str, str]] = []
        self.crypto_targets: list[dict[str, str]] = []
        self.notes: list[str] = []
        self.runtime_checks: list[str] = []

    def copy(self, source: Path, relative_target: str, required: bool = False) -> bool:
        if not source.is_file():
            if required:
                raise FileNotFoundError(f"required source is missing: {source}")
            return False
        target = self.out / relative_target
        copy_file(source, target)
        self.copied.append({
            "from": str(source.relative_to(self.dump)),
            "to": relative_target,
        })
        return True

    def identity(self, key: str, default: str = "") -> str:
        return str(fv(self.facts, "identity", key, default) or default)

    def image_size(self, name: str) -> int | None:
        item = self.facts.get("partitions", {}).get("images", {}).get(name)
        if isinstance(item, dict):
            try:
                return int(item.get("bytes"))
            except (TypeError, ValueError):
                return None
        return None

    def copy_prebuilts(self) -> None:
        self.copy(self.dump / "boot/kernel", "prebuilt/kernel", required=True)
        self.copy(self.dump / "vendor_boot/dtb", "prebuilt/dtb.img", required=True)
        self.copy(self.dump / "vendor_boot/dtb.dts", "prebuilt/dtb.dts")
        self.copy(self.dump / "vendor_boot/bootconfig", "prebuilt/bootconfig")
        for candidate in (self.dump / "images/dtbo.img", self.dump / "dtbo.img"):
            if self.copy(candidate, "prebuilt/dtbo.img"):
                break
        for name in ("vbmeta", "vbmeta_system", "vbmeta_vendor", "init_boot"):
            for candidate in (self.dump / f"images/{name}.img", self.dump / f"{name}.img"):
                if self.copy(candidate, f"prebuilt/{name}.img"):
                    break

    def copy_recovery_sources(self) -> None:
        root = self.dump / "vendor_boot/recovery_ramdisk"
        if not root.is_dir():
            raise FileNotFoundError(root)
        safe_names = {
            "recovery.fstab", "twrp.fstab", "fstab.emmc", "ueventd.rc",
            "prop.default", "default.prop",
        }
        final_fstab = Path("recovery/root/system/etc/recovery.fstab")
        for source in sorted(root.rglob("*")):
            if not source.is_file():
                continue
            rel = source.relative_to(root)
            name = source.name
            keep = (
                name in safe_names
                or name.startswith("fstab.")
                or (name.endswith(".rc") and (name.startswith("init") or name.startswith("ueventd")))
                or (source.suffix in {".xml", ".conf"} and len(rel.parts) <= 4)
            )
            if keep:
                target = Path("recovery/root") / rel
                if target != final_fstab:
                    self.copy(source, str(target))

        selected = self.facts["partitions"].get("selected_fstab")
        if selected:
            source = self.dump / selected
            self.copy(source, "_provenance/stock-recovery.fstab", required=True)
            text = read_text(source).rstrip()
            generated = [
                entry["raw"]
                for entry in self.facts["partitions"].get("selected_entries", [])
                if entry.get("style") == "treeforge-dynamic-evidence"
            ]
            if generated:
                text += (
                    "\n\n# Generated from fresh-stock dynamic-partition evidence; "
                    "the untouched source is _provenance/stock-recovery.fstab.\n"
                    + "\n".join(generated)
                )
            write_text(self.out / final_fstab, text + "\n")

        platform_root = self.dump / "vendor_boot/ramdisk"
        for source in sorted(platform_root.rglob("fstab*")) if platform_root.is_dir() else []:
            if source.is_file():
                rel = source.relative_to(platform_root)
                self.copy(source, str(Path("recovery/root/first_stage_ramdisk") / rel.name))

    def copy_modules(self) -> None:
        roots = [
            self.dump / "vendor_boot/ramdisk/lib/modules",
            self.dump / "vendor_boot/recovery_ramdisk/lib/modules",
        ]
        seen: set[str] = set()
        for root in roots:
            if not root.is_dir():
                continue
            for source in sorted(root.rglob("*")):
                if not source.is_file():
                    continue
                if not (source.suffix == ".ko" or source.name.startswith("modules.")):
                    continue
                rel = source.relative_to(root)
                key = str(rel)
                if key in seen:
                    continue
                seen.add(key)
                self.copy(source, str(Path("prebuilt/modules") / rel))
        load_order = self.facts["kernel"]["modules"].get("load_order", [])
        if load_order:
            write_text(self.out / "prebuilt/modules/modules.load.recovery", "\n".join(load_order))
        else:
            modules = sorted(p.name for p in (self.out / "prebuilt/modules").rglob("*.ko")) \
                if (self.out / "prebuilt/modules").is_dir() else []
            if modules:
                write_text(self.out / "prebuilt/modules/modules.load.recovery", "\n".join(modules))
                self.notes.append("No stock modules.load was found; modules.load.recovery is alphabetical and must be reviewed")
                self.runtime_checks.append("Verify early-boot kernel module load order")

    @staticmethod
    def recovery_target_for_dump_path(relative: str) -> str:
        # Android dumps commonly expose /system as system/system.  Recovery
        # needs the runtime path, not the extraction wrapper.
        if relative.startswith("system/system/"):
            relative = relative[len("system/"):]
        return str(Path("recovery/root") / relative)

    def copy_crypto_stack(self) -> None:
        crypto = self.facts.get("crypto", {})
        if not crypto.get("dependency_closure_complete"):
            raise RuntimeError("refusing to generate without a complete stock KeyMint dependency closure")
        for item in crypto.get("copy_files", []):
            relative = str(item["path"])
            target = self.recovery_target_for_dump_path(relative)
            self.copy(self.dump / relative, target, required=True)
            self.crypto_targets.append({
                "from": relative,
                "to": target,
                "role": str(item.get("role", "dependency")),
            })

    def make_board_config(self) -> str:
        brand = str(self.config["device"]["brand"]).lower()
        codename = self.identity("codename", "x6886").lower()
        platform = self.identity("platform", "mt6789")
        arch = self.config["architecture"]
        display = self.config["display"]
        boot = self.facts["boot"]["boot_header"]
        vendor_boot = self.facts["boot"]["vendor_boot_header"]
        header_version = int(vendor_boot.get("header_version") or boot.get("header_version") or 4)
        page_size = int(boot.get("page_size") or vendor_boot.get("page_size") or 4096)
        device_path = f"device/{brand}/{codename}"
        prebuilt = "$(DEVICE_PATH)/prebuilt"
        vendor_cmdline = str(vendor_boot.get("cmdline", "")).strip()
        cmdline = " ".join(x for x in vendor_cmdline.split() if x != "bootconfig")
        bootconfig = self.facts["boot"].get("bootconfig", {})

        images = self.facts["partitions"].get("images", {})
        static_names = [
            x for x in ["boot", "init_boot", "vendor_boot", "dtbo", "vbmeta", "vbmeta_system", "vbmeta_vendor"]
            if x in images or x in {"boot", "vendor_boot"}
        ]
        logical = list(self.facts["partitions"].get("logical_partitions", []))
        for entry in self.facts["partitions"].get("selected_entries", []):
            flags = (entry.get("mount_flags", "") + " " + entry.get("fs_mgr_flags", "")).lower()
            mount = entry.get("mount_point", "").strip("/")
            mount = "system" if mount == "system_root" else mount
            if "logical" in flags and mount and mount not in logical:
                logical.append(mount)
        ab_partitions = []
        for item in static_names + logical:
            if item and item not in ab_partitions:
                ab_partitions.append(item)

        lines = [
            "# Copyright (C) 2026 B E R U",
            "# SPDX-License-Identifier: Apache-2.0",
            "#",
            "# Generated only from the Android 16 dump and verified device report.",
            "# No Android 15 tree or OrangeFox file was used.",
            "",
            f"DEVICE_PATH := {device_path}",
            f"PREBUILT_PATH := {prebuilt}",
            "",
            "# Minimal-manifest build tolerance",
            "ALLOW_MISSING_DEPENDENCIES := true",
            "BUILD_BROKEN_DUP_RULES := true",
            "BUILD_BROKEN_ELF_PREBUILT_PRODUCT_COPY_FILES := true",
            "BUILD_BROKEN_MISSING_REQUIRED_MODULES := true",
            "",
            "# Recovery base: minimal-manifest-twrp twrp-14.1; stock firmware: Android 16",
            "# The source base and stock Android version are intentionally tracked separately.",
            "",
            "# Architecture — Device Info HW evidence",
            f"TARGET_ARCH := {arch['primary']}",
            f"TARGET_ARCH_VARIANT := {arch['variant']}",
            f"TARGET_CPU_ABI := {arch['abi']}",
            "TARGET_CPU_ABI2 :=",
            "TARGET_CPU_VARIANT := generic",
            f"TARGET_CPU_VARIANT_RUNTIME := {arch['big_core']}",
            "TARGET_2ND_ARCH := arm",
            "TARGET_2ND_ARCH_VARIANT := armv8-a",
            "TARGET_2ND_CPU_ABI := armeabi-v7a",
            "TARGET_2ND_CPU_ABI2 := armeabi",
            "TARGET_2ND_CPU_VARIANT := generic",
            f"TARGET_2ND_CPU_VARIANT_RUNTIME := {arch['little_core']}",
            "",
            "# Platform",
            f"TARGET_BOARD_PLATFORM := {platform}",
            f"TARGET_BOOTLOADER_BOARD_NAME := {platform}",
            "TARGET_NO_BOOTLOADER := true",
            "TARGET_USES_UEFI := true",
            "",
            "# Display — exact 1080x2400 / 420 dpi report values",
            f"TARGET_SCREEN_WIDTH := {display['width']}",
            f"TARGET_SCREEN_HEIGHT := {display['height']}",
            f"TARGET_SCREEN_DENSITY := {display['density']}",
            f"TW_THEME := {display['twrp_theme']}",
            "TW_FRAMERATE := 60",
            "TARGET_RECOVERY_PIXEL_FORMAT := RGBX_8888 # RUNTIME VERIFY on first boot",
            "",
            "# Kernel and boot v4",
            f"BOARD_BOOT_HEADER_VERSION := {header_version}",
            f"BOARD_KERNEL_PAGESIZE := {page_size}",
            f"BOARD_FLASH_BLOCK_SIZE := {page_size * 64}",
            "TARGET_KERNEL_ARCH := arm64",
            "TARGET_KERNEL_HEADER_ARCH := arm64",
            "BOARD_KERNEL_IMAGE_NAME := kernel",
            "TARGET_PREBUILT_KERNEL := $(PREBUILT_PATH)/kernel",
            "TARGET_PREBUILT_DTB := $(PREBUILT_PATH)/dtb.img",
            "TARGET_FORCE_PREBUILT_KERNEL := true",
            "BOARD_USES_GENERIC_KERNEL_IMAGE := true",
            "BOARD_RAMDISK_USE_LZ4 := true",
            "BOARD_MKBOOTIMG_ARGS += --header_version $(BOARD_BOOT_HEADER_VERSION)",
            "BOARD_MKBOOTIMG_ARGS += --pagesize $(BOARD_KERNEL_PAGESIZE)",
            "BOARD_MKBOOTIMG_ARGS += --dtb $(TARGET_PREBUILT_DTB)",
            "BOARD_INCLUDE_DTB_IN_BOOTIMG := true",
            "BOARD_EXCLUDE_KERNEL_FROM_RECOVERY_IMAGE := true",
        ]
        if cmdline:
            lines.append(f"BOARD_KERNEL_CMDLINE := {cmdline}")
        if bootconfig:
            lines += ["", "# Exact vendor_boot bootconfig"]
            for key, value in sorted(bootconfig.items()):
                lines.append(f"BOARD_BOOTCONFIG += {key}={value}")
        if (self.out / "prebuilt/dtbo.img").is_file():
            lines += [
                "BOARD_KERNEL_SEPARATED_DTBO := true",
                "BOARD_PREBUILT_DTBOIMAGE := $(PREBUILT_PATH)/dtbo.img",
            ]

        lines += [
            "",
            "# Stock vendor_boot v4 has an explicit type=2/name=recovery fragment",
            "PRODUCT_BUILD_VENDOR_BOOT_IMAGE := true",
            "BOARD_MOVE_RECOVERY_RESOURCES_TO_VENDOR_BOOT := true",
            "BOARD_INCLUDE_RECOVERY_RAMDISK_IN_VENDOR_BOOT := true",
            "BOARD_USES_RECOVERY_AS_BOOT := false",
            "TARGET_NO_RECOVERY := true",
            "TW_HAS_NO_RECOVERY_PARTITION := true",
            "TW_NO_FLASH_CURRENT_TWRP := true",
            "TARGET_RECOVERY_FSTAB := $(DEVICE_PATH)/recovery/root/system/etc/recovery.fstab",
            "",
            "# A/B and dynamic partitions",
            "AB_OTA_UPDATER := true",
            mk_list("AB_OTA_PARTITIONS", ab_partitions, append=True),
            "PRODUCT_USE_DYNAMIC_PARTITIONS := true",
            "BOARD_USES_METADATA_PARTITION := true",
            "# BOARD_SUPER_PARTITION_SIZE is intentionally not guessed; add exact lpdump value later.",
        ]

        fsmap = self.facts["partitions"].get("filesystems", {})
        lines += ["", "# Filesystems proved by the stock recovery fstab"]
        for mount, fstype in sorted(fsmap.items()):
            clean = re.sub(r"[^A-Za-z0-9_]", "_", mount).upper()
            if fstype != "auto" and clean in {"SYSTEM", "SYSTEM_EXT", "PRODUCT", "VENDOR", "ODM", "VENDOR_DLKM", "ODM_DLKM", "SYSTEM_DLKM", "USERDATA"}:
                lines.append(f"BOARD_{clean}IMAGE_FILE_SYSTEM_TYPE := {fstype}")
        lines += [
            "TARGET_USERIMAGES_USE_EXT4 := true",
            "TARGET_USERIMAGES_USE_F2FS := true",
            "TARGET_USES_MKE2FS := true",
        ]

        for image_name, variable in [
            ("boot", "BOARD_BOOTIMAGE_PARTITION_SIZE"),
            ("vendor_boot", "BOARD_VENDOR_BOOTIMAGE_PARTITION_SIZE"),
            ("dtbo", "BOARD_DTBOIMG_PARTITION_SIZE"),
            ("init_boot", "BOARD_INIT_BOOT_IMAGE_PARTITION_SIZE"),
        ]:
            size = self.image_size(image_name)
            if size:
                lines.append(f"{variable} := {size}")

        lines += [
            "",
            "# Encryption proved by fstab flags",
        ]
        if self.facts["encryption"].get("file_based"):
            lines += [
                "TW_INCLUDE_CRYPTO := true",
                "TW_INCLUDE_CRYPTO_FBE := true",
                "TW_USE_FSCRYPT_POLICY := 2",
                "TW_PREPARE_DATA_MEDIA_EARLY := true",
            ]
        if self.facts["encryption"].get("metadata_encryption"):
            lines += [
                "TW_INCLUDE_FBE_METADATA_DECRYPT := true",
                "BOARD_USES_METADATA_PARTITION := true",
            ]

        version = shell_safe_version(f"BERU-{codename}")
        lines += [
            "",
            "# TWRP — official-first, no OrangeFox flags or custom logo replacement",
            "TW_MAINTAINER := B E R U",
            f"TW_DEVICE_VERSION := {version}",
            "RECOVERY_VARIANT := twrp",
            "TW_EXTRA_LANGUAGES := true",
            "TW_INCLUDE_REPACKTOOLS := true",
            "TW_INCLUDE_RESETPROP := true",
            "TW_INCLUDE_LIBRESETPROP := true",
            "TW_INCLUDE_NTFS_3G := true",
            "TW_INCLUDE_LPTOOLS := true",
            "TW_INCLUDE_LPDUMP := true",
            "TW_INCLUDE_FASTBOOTD := true",
            "TW_INCLUDE_TZDATA := true",
            "TW_INCLUDE_FUSE_EXFAT := true",
            "TWRP_INCLUDE_LOGCAT := true",
            "TARGET_USES_LOGD := true",
            "TW_SCREEN_BLANK_ON_BOOT := true",
            "RECOVERY_SDCARD_ON_DATA := true",
            "BOARD_SUPPRESS_SECURE_ERASE := true",
            "TW_LOAD_VENDOR_BOOT_MODULES := true",
            "",
            "# KeyMint/Gatekeeper services and DT_NEEDED closure are copied from stock A16.",
            "# No software KeyMint substitute and no guessed service package is injected.",
            "",
            "# Runtime-only values are deliberately not fabricated:",
            "# TW_BRIGHTNESS_PATH / TW_MAX_BRIGHTNESS / haptics need first-boot evidence.",
        ]
        self.runtime_checks += [
            "Confirm RGBX_8888 pixel format from the first recovery boot screenshot",
            "Discover TW_BRIGHTNESS_PATH and brightness range from /sys/class/backlight",
            "Verify touch scaling against 1080x2400 with input max 2401x1081",
            "Verify FBE metadata decryption against the Android 16 lockscreen credential",
        ]
        return "\n".join(x for x in lines if x is not None)

    def make_twrp_flags(self) -> str:
        lines = [
            "# Generated audit view. The untouched stock source is _provenance/stock-recovery.fstab.",
            "# mount_point  fs_type  block_device  twrp_flags",
        ]
        for entry in self.facts["partitions"].get("selected_entries", []):
            mount = entry["mount_point"]
            flags_text = (entry.get("mount_flags", "") + "," + entry.get("fs_mgr_flags", "")).lower()
            flags = []
            if "slotselect" in flags_text:
                flags.append("slotselect")
            if "logical" in flags_text:
                flags.append("logical")
            if mount == "/data":
                flags += ["backup=Data", "wipeingui"]
            if mount in {"/boot", "/vendor_boot", "/dtbo", "/init_boot", "/misc"}:
                flags.append("backup=" + mount.strip("/").upper())
            lines.append(f"{mount:<18} {entry['fs_type']:<8} {entry['device']:<48} flags={';'.join(flags)}")
        return "\n".join(lines)

    def make_device_mk(self) -> str:
        module_files = sorted(p.relative_to(self.out / "prebuilt/modules")
                              for p in (self.out / "prebuilt/modules").rglob("*")
                              if p.is_file()) if (self.out / "prebuilt/modules").is_dir() else []
        copies = [
            "$(DEVICE_PATH)/recovery/root/system/etc/recovery.fstab:$(TARGET_COPY_OUT_RECOVERY)/root/system/etc/recovery.fstab",
        ]
        for rel in module_files:
            copies.append(f"$(DEVICE_PATH)/prebuilt/modules/{rel}:$(TARGET_COPY_OUT_RECOVERY)/root/vendor/lib/modules/{rel.name}")
        for item in self.crypto_targets:
            relative = item["to"]
            destination = relative[len("recovery/root/"):] if relative.startswith("recovery/root/") else relative
            copies.append(
                f"$(DEVICE_PATH)/{relative}:$(TARGET_COPY_OUT_RECOVERY)/root/{destination}"
            )
        lines = [
            "# Copyright (C) 2026 B E R U",
            "# SPDX-License-Identifier: Apache-2.0",
            "",
            "LOCAL_PATH := device/infinix/x6886",
            "",
            "PRODUCT_USE_DYNAMIC_PARTITIONS := true",
            "PRODUCT_BUILD_VENDOR_BOOT_IMAGE := true",
            "",
            "# Recovery packages; this stage generates only and does not build.",
            mk_list("PRODUCT_PACKAGES", [
                "bootctl",
                "fastbootd",
                "lpdump",
                "lptools",
                "resetprop",
                "update_engine_sideload",
            ], append=True),
            "",
            mk_list("PRODUCT_COPY_FILES", copies, append=True),
            "",
            "PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \\",
            "    ro.adb.secure=0 \\",
            "    ro.secure=0 \\",
            "    ro.debuggable=1",
        ]
        return "\n".join(x for x in lines if x)

    def make_readme(self) -> str:
        ident = self.facts["identity"]
        display = self.config["display"]
        boot = self.facts["boot"]["vendor_boot_header"]
        selected = self.facts["partitions"].get("selected_fstab") or "missing"
        recovery = self.config["recovery"]
        return f"""# TWRP 14.1 device tree for Infinix X6886

Generated by **B E R U's X6886 TWRP Tree Forge** from the Android 16 dump for the `{recovery['manifest_branch']}` recovery source base. This is an official-first TWRP tree: it contains no OrangeFox flags, assets, or inherited Android 15 files.

## Proven device facts

| Item | Value |
|---|---|
| Device | {self.identity('model')} (`{self.identity('codename')}`) |
| Platform | `{self.identity('platform')}` |
| Android / API | {self.identity('android_release')} / {self.identity('api_level')} |
| Display | {display['width']}×{display['height']} at {display['density']} dpi |
| Touch range | {display['touch_max_x']}×{display['touch_max_y']} (`{self.config['hardware']['touch_input']}`) |
| Panel | `{display['panel']}` |
| Kernel | {self.facts['kernel']['version_text']} |
| Boot format | vendor_boot v{boot.get('header_version')} with separate recovery fragment |
| Recovery fstab | `{selected}` |
| Recovery source base | `{recovery['manifest_branch']}` |
| Stock KeyMint closure | {len(self.facts.get('crypto', {}).get('copy_files', []))} files |
| Maintainer | **B E R U** |

## Readiness meaning

`STATIC_COMPLETE` means every fact required to generate the source tree is present and cross-checked. It does **not** mean a recovery image was built or boot-tested. This repository intentionally performs no build.

The remaining runtime checks are listed in `_reports/validation.md`. They include framebuffer format, brightness sysfs, touch scaling, starting the stock KeyMint/Gatekeeper services, and Android 16 `/data` decryption. A tree cannot honestly be called official-ready until those are verified on-device later.

## Future build target (not run by this generator)

```bash
. build/envsetup.sh
lunch twrp_x6886-eng
mka vendorbootimage
```

## Provenance

See `_provenance/facts.json` and `_provenance/copied-files.json`. The raw Device Info HW PDF is not committed because it contains local IP/session data; its SHA-256 is retained in the facts.
"""

    def generate(self) -> None:
        if self.facts.get("collection", {}).get("errors"):
            raise RuntimeError("fact collection has critical errors; refusing to generate a fake-complete tree")
        mkdir_clean(self.out)
        self.copy_prebuilts()
        self.copy_recovery_sources()
        self.copy_modules()
        self.copy_crypto_stack()

        device_config = self.config["device"]
        brand = str(device_config["brand"]).lower()
        codename = self.identity("codename", "x6886").lower()
        model = str(device_config["model"])
        manufacturer = str(device_config["manufacturer"])
        device_path = f"device/{brand}/{codename}"

        write_text(self.out / "BoardConfig.mk", self.make_board_config())
        write_text(self.out / "device.mk", self.make_device_mk())
        write_text(self.out / "Android.bp", f'soong_namespace {{\n    imports: [],\n}}')
        write_text(self.out / "Android.mk", f"LOCAL_PATH := $(call my-dir)\n\nifeq ($(TARGET_DEVICE),{codename})\ninclude $(call all-makefiles-under,$(LOCAL_PATH))\nendif")
        write_text(self.out / "AndroidProducts.mk", f"PRODUCT_MAKEFILES := \\\n    $(LOCAL_DIR)/twrp_{codename}.mk\n\nCOMMON_LUNCH_CHOICES := \\\n    twrp_{codename}-eng \\\n    twrp_{codename}-userdebug")
        write_text(self.out / f"twrp_{codename}.mk", f"""# Copyright (C) 2026 B E R U
# SPDX-License-Identifier: Apache-2.0

$(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)
$(call inherit-product, $(SRC_TARGET_DIR)/product/base.mk)
$(call inherit-product, {device_path}/device.mk)
$(call inherit-product, vendor/twrp/config/common.mk)

PRODUCT_DEVICE := {codename}
PRODUCT_NAME := twrp_{codename}
PRODUCT_BRAND := {device_config['brand']}
PRODUCT_MODEL := {model}
PRODUCT_MANUFACTURER := {manufacturer}
PRODUCT_RELEASE_NAME := {codename}

PRODUCT_BUILD_PROP_OVERRIDES += \\
    TARGET_DEVICE={codename} \\
    PRODUCT_NAME={device_config['stock_product']}
""")
        write_text(self.out / "system.prop", f"""# B E R U / X6886 TWRP identity
ro.product.device={codename}
ro.build.product={codename}
ro.twrp.vendor=B E R U
ro.twrp.target.devices={codename},{self.identity('device')}
ro.sf.lcd_density={self.config['display']['density']}
""")
        write_text(self.out / "board-info.txt", f"require board={self.identity('platform', 'mt6789')}")
        write_text(self.out / "recovery/root/system/etc/twrp.flags", self.make_twrp_flags())
        write_text(
            self.out / "crypto-files.txt",
            "# Exact Android 16 stock files copied for KeyMint/FBE\n" +
            "\n".join(f"{item['role']}: {item['from']} -> {item['to']}" for item in self.crypto_targets),
        )
        write_text(self.out / "README.md", self.make_readme())
        write_text(self.out / "LICENSE", "Copyright 2026 B E R U\n\nLicensed under the Apache License, Version 2.0.\n")

        provenance = self.out / "_provenance"
        provenance.mkdir(parents=True, exist_ok=True)
        save_json(provenance / "facts.json", self.facts)
        save_json(provenance / "copied-files.json", {
            "old_tree_used": False,
            "copied_from_android16_dump": self.copied,
            "notes": self.notes,
            "runtime_checks": unique_preserve(self.runtime_checks),
        })
        save_json(provenance / "crypto-stack.json", self.facts.get("crypto", {}))
        save_json(provenance / "build-target.json", {
            "recovery": "TWRP",
            "manifest_repo": self.config["recovery"]["manifest_repo"],
            "manifest_branch": self.config["recovery"]["manifest_branch"],
            "stock_android": self.config["device"]["android_release"],
            "generated_tree_branch": self.config["recovery"]["output_branch"],
            "build_performed": False,
            "orangefox_included": False,
        })
        print(f">> generated tree: {self.out}")
        print(f">> files: {sum(1 for p in self.out.rglob('*') if p.is_file())}")


def unique_preserve(values: list[str]) -> list[str]:
    out = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a TWRP-only device tree from collected facts")
    parser.add_argument("--dump", required=True)
    parser.add_argument("--facts", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    Generator(Path(args.dump).resolve(), load_json(args.facts), load_json(args.config), Path(args.out).resolve()).generate()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
