from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Callable

from .common import load_json, read_text, save_json, sha256_file, write_text


class Validator:
    def __init__(self, tree: Path, facts: dict[str, Any], config: dict[str, Any]):
        self.tree = tree
        self.facts = facts
        self.config = config
        self.checks: list[dict[str, Any]] = []

    def add(self, check_id: str, category: str, status: str, message: str,
            evidence: str = "", weight: int = 1) -> None:
        self.checks.append({
            "id": check_id,
            "category": category,
            "status": status,
            "message": message,
            "evidence": evidence,
            "weight": weight,
        })

    def require(self, condition: bool, check_id: str, category: str, message: str,
                evidence: str = "", weight: int = 1) -> None:
        self.add(check_id, category, "PASS" if condition else "FAIL", message, evidence, weight)

    def warn(self, condition: bool, check_id: str, category: str, pass_message: str,
             warn_message: str, evidence: str = "") -> None:
        self.add(check_id, category, "PASS" if condition else "WARN",
                 pass_message if condition else warn_message, evidence, 0)

    def runtime(self, check_id: str, message: str, evidence: str = "") -> None:
        self.add(check_id, "runtime", "RUNTIME", message, evidence, 0)

    def file(self, rel: str) -> Path:
        return self.tree / rel

    def text(self, rel: str) -> str:
        return read_text(self.file(rel))

    @staticmethod
    def has_assignment(text: str, name: str, expected: str | int | None = None) -> bool:
        match = re.search(rf"(?m)^\s*{re.escape(name)}\s*(?::|\+)?=\s*([^#\n]+)", text)
        if not match:
            return False
        if expected is None:
            return True
        return match.group(1).strip() == str(expected)

    def check_layout(self) -> None:
        required = [
            "Android.bp", "Android.mk", "AndroidProducts.mk", "BoardConfig.mk",
            "device.mk", "twrp_x6886.mk", "system.prop", "board-info.txt",
            "crypto-files.txt",
            "recovery/root/system/etc/recovery.fstab", "prebuilt/kernel",
            "prebuilt/dtb.img", "_provenance/facts.json", "_provenance/copied-files.json",
            "_provenance/crypto-stack.json", "_provenance/build-target.json",
        ]
        for rel in required:
            self.require(self.file(rel).is_file(), "file-" + rel.replace("/", "-"), "layout",
                         f"Required file exists: {rel}", rel, 3)
        self.require(not self.file("INFINIX_X6886_DeviceInfo.pdf").exists(), "privacy-no-raw-pdf",
                     "security", "Raw Device Info PDF is not published", weight=4)

    def check_source_integrity(self) -> None:
        source = self.facts.get("source", {})
        self.require(source.get("old_tree_used") is False, "source-no-old-tree", "provenance",
                     "No Android 15/old recovery tree was used", "facts.json", 5)
        copied_path = self.file("_provenance/copied-files.json")
        copied = load_json(copied_path) if copied_path.is_file() else {}
        self.require(copied.get("old_tree_used") is False, "copied-no-old-tree", "provenance",
                     "Generated-file manifest declares zero old-tree inputs", str(copied_path), 5)

        dump_root_raw = os.environ.get("TREEFORGE_DUMP", "")
        dump_root = Path(dump_root_raw).resolve() if dump_root_raw else None
        mismatches = []
        checked = 0
        if dump_root and dump_root.is_dir():
            for item in copied.get("copied_from_android16_dump", []):
                src = dump_root / item["from"]
                dst = self.tree / item["to"]
                if src.is_file() and dst.is_file():
                    checked += 1
                    if sha256_file(src) != sha256_file(dst):
                        mismatches.append(item["to"])
                else:
                    mismatches.append(item["to"])
            self.require(checked > 0 and not mismatches, "source-copied-hashes", "provenance",
                         f"All {checked} copied files match the Android 16 dump byte-for-byte",
                         ", ".join(mismatches), 5)
        else:
            self.add("source-copied-hashes", "provenance", "WARN",
                     "Dump root was not supplied to the validator; copied-file hashes were not rechecked",
                     "set TREEFORGE_DUMP", 0)

        build_files = ["BoardConfig.mk", "device.mk", "AndroidProducts.mk", "twrp_x6886.mk", "system.prop"]
        executable_lines = []
        for rel in build_files:
            executable_lines.extend(
                line for line in self.text(rel).splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            )
        combined = "\n".join(executable_lines).lower()
        banned = [x for x in ["orangefox", "of_maintainer", "fox_version", "fox_", "ofrp"] if x in combined]
        self.require(not banned, "source-no-orangefox", "policy",
                     "No OrangeFox build flag or identity is present", ", ".join(banned), 5)

    def check_recovery_base(self) -> None:
        target_path = self.file("_provenance/build-target.json")
        target = load_json(target_path) if target_path.is_file() else {}
        expected = self.config["recovery"]
        self.require(target.get("recovery") == "TWRP", "base-twrp", "recovery-base",
                     "Generated tree targets TWRP", "build-target.json", 4)
        self.require(target.get("manifest_branch") == "twrp-14.1" and
                     expected.get("manifest_branch") == "twrp-14.1",
                     "base-twrp-14-1", "recovery-base",
                     "Recovery source base is exactly twrp-14.1", "build-target.json + config", 5)
        self.require(str(target.get("stock_android")) == "16",
                     "base-stock-a16", "recovery-base",
                     "Stock firmware target remains Android 16", "build-target.json", 5)
        self.require(target.get("generated_tree_branch") == "twrp-14.1-a16",
                     "base-output-branch", "recovery-base",
                     "Generated output branch is twrp-14.1-a16", "build-target.json", 4)
        self.require(target.get("build_performed") is False,
                     "base-no-build", "policy", "Generator did not build a recovery image",
                     "build-target.json", 3)
        self.require(target.get("orangefox_included") is False,
                     "base-no-orangefox", "policy", "OrangeFox remains a later separate stage",
                     "build-target.json", 3)

    def check_identity_and_brand(self) -> None:
        board = self.text("BoardConfig.mk")
        product = self.text("twrp_x6886.mk")
        prop = self.text("system.prop")
        expected = self.config["device"]
        self.require(self.has_assignment(board, "TARGET_BOARD_PLATFORM", expected["platform"]),
                     "identity-platform", "identity", f"Platform is {expected['platform']}", "BoardConfig.mk", 5)
        self.require(self.has_assignment(product, "PRODUCT_DEVICE", expected["codename"]),
                     "identity-codename", "identity", f"Product device is {expected['codename']}", "twrp_x6886.mk", 5)
        self.require(self.has_assignment(product, "PRODUCT_NAME", "twrp_x6886"),
                     "identity-product-name", "identity", "Product name is twrp_x6886", "twrp_x6886.mk", 3)
        self.require(self.has_assignment(board, "TW_MAINTAINER", "B E R U"),
                     "brand-maintainer", "branding", "TWRP maintainer brand is B E R U", "BoardConfig.mk", 4)
        self.require("ro.twrp.vendor=B E R U" in prop,
                     "brand-property", "branding", "Generated recovery identifies B E R U", "system.prop", 2)
        self.require("TW_DEVICE_VERSION := BERU-x6886" in board,
                     "brand-version", "branding", "Device version is BERU-x6886", "BoardConfig.mk", 2)

    def check_display(self) -> None:
        board = self.text("BoardConfig.mk")
        display = self.config["display"]
        for variable, key in [
            ("TARGET_SCREEN_WIDTH", "width"),
            ("TARGET_SCREEN_HEIGHT", "height"),
            ("TARGET_SCREEN_DENSITY", "density"),
            ("TW_THEME", "twrp_theme"),
        ]:
            self.require(self.has_assignment(board, variable, display[key]),
                         "display-" + key.replace("_", "-"), "display",
                         f"{variable} matches verified value {display[key]}", "BoardConfig.mk", 5)
        self.require(display["width"] == 1080 and display["height"] == 2400 and display["density"] == 420,
                     "display-report-exact", "display",
                     "Device report proves 1080x2400 at 420 dpi", "config/x6886.json", 5)
        self.require(display["touch_max_x"] == 2401 and display["touch_max_y"] == 1081,
                     "touch-report-range", "display",
                     "Touch controller range 2401x1081 is recorded for scaling validation",
                     "config/x6886.json", 3)
        self.runtime("touch-runtime", "Confirm that all four screen corners map correctly; apply swap/invert flags only if evidence requires it")
        self.runtime("framebuffer-runtime", "Confirm RGBX_8888 on the first boot; switch to BGRA/ABGR only from screenshot evidence")

    @staticmethod
    def crypto_target(relative: str) -> str:
        if relative.startswith("system/system/"):
            relative = relative[len("system/"):]
        return "recovery/root/" + relative

    def check_crypto_stack(self) -> None:
        crypto = self.facts.get("crypto", {})
        board = self.text("BoardConfig.mk")
        device_mk = self.text("device.mk")
        self.require(crypto.get("target_recovery_base") == "twrp-14.1",
                     "crypto-target-base", "encryption",
                     "Stock security stack was resolved for the twrp-14.1 target", "facts.json", 4)
        self.require(bool(crypto.get("keymint_services")), "crypto-keymint-service", "encryption",
                     "Android 16 stock KeyMint service binary is included",
                     ", ".join(crypto.get("keymint_services", [])), 5)
        self.require(bool(crypto.get("gatekeeper_services")), "crypto-gatekeeper-service", "encryption",
                     "Android 16 stock Gatekeeper service binary is included",
                     ", ".join(crypto.get("gatekeeper_services", [])), 5)
        self.require(bool(crypto.get("init_rc")), "crypto-init-rc", "encryption",
                     "Stock KeyMint/Gatekeeper init rc is included",
                     ", ".join(crypto.get("init_rc", [])), 4)
        self.require(bool(crypto.get("vintf_manifests")), "crypto-vintf", "encryption",
                     "Stock KeyMint/Gatekeeper VINTF manifest is included",
                     ", ".join(crypto.get("vintf_manifests", [])), 4)
        self.require(crypto.get("dependency_closure_complete") is True,
                     "crypto-dependency-closure", "encryption",
                     "readelf resolved the stock security DT_NEEDED closure",
                     ", ".join(crypto.get("unresolved_vendor_libraries", [])), 5)
        self.require(not crypto.get("lfs_pointers"), "crypto-no-lfs-pointers", "encryption",
                     "Every selected stock security file is a hydrated object",
                     ", ".join(crypto.get("lfs_pointers", [])), 4)

        missing = []
        unlisted = []
        for item in crypto.get("copy_files", []):
            target = self.crypto_target(str(item["path"]))
            if not self.file(target).is_file():
                missing.append(target)
            destination = target[len("recovery/root/"):]
            if f"$(TARGET_COPY_OUT_RECOVERY)/root/{destination}" not in device_mk:
                unlisted.append(target)
        self.require(bool(crypto.get("copy_files")) and not missing,
                     "crypto-files-copied", "encryption",
                     f"All {len(crypto.get('copy_files', []))} stock security files are in the tree",
                     ", ".join(missing), 5)
        self.require(not unlisted, "crypto-product-copy", "encryption",
                     "Every stock security file is packaged into the recovery ramdisk",
                     ", ".join(unlisted), 5)
        self.require(self.has_assignment(board, "TW_PREPARE_DATA_MEDIA_EARLY", "true"),
                     "crypto-data-early", "encryption",
                     "TWRP prepares data media early for FBE", "BoardConfig.mk", 3)
        self.require(self.has_assignment(board, "TW_USE_FSCRYPT_POLICY", "2"),
                     "crypto-fscrypt-v2", "encryption",
                     "TWRP uses the stock fscrypt v2 policy", "BoardConfig.mk", 3)
        self.runtime("keymint-runtime", "Boot TWRP and prove stock KeyMint/Gatekeeper services register without linker or SELinux failures")
        self.runtime("keymint-unlock-runtime", "Unlock Android 16 /data with PIN/password and verify decrypted file names and contents")

    def check_boot(self) -> None:
        board = self.text("BoardConfig.mk")
        boot = self.facts.get("boot", {})
        bh = boot.get("boot_header", {})
        vh = boot.get("vendor_boot_header", {})
        fragments = boot.get("recovery_fragments", [])
        self.require(int(bh.get("header_version", -1)) == 4, "boot-header-v4", "boot",
                     "boot.img uses header v4", "boot/header_info.json", 5)
        self.require(int(vh.get("header_version", -1)) == 4, "vendor-boot-header-v4", "boot",
                     "vendor_boot.img uses header v4", "vendor_boot/header_info.json", 5)
        self.require(bool(fragments), "vendor-recovery-fragment", "boot",
                     "vendor_boot has a separate type=recovery ramdisk fragment", json.dumps(fragments), 5)
        self.require(boot.get("recovery_file_count", 0) >= 50, "recovery-root-populated", "boot",
                     f"Extracted recovery ramdisk contains {boot.get('recovery_file_count', 0)} files",
                     "vendor_boot/recovery_ramdisk", 5)
        self.require(self.has_assignment(board, "BOARD_INCLUDE_RECOVERY_RAMDISK_IN_VENDOR_BOOT", "true"),
                     "build-recovery-fragment", "boot",
                     "Build configuration emits a standalone recovery vendor-ramdisk fragment",
                     "BoardConfig.mk", 5)
        self.require(self.has_assignment(board, "BOARD_MOVE_RECOVERY_RESOURCES_TO_VENDOR_BOOT", "true"),
                     "build-move-recovery", "boot", "Recovery resources are placed in vendor_boot",
                     "BoardConfig.mk", 4)
        self.require(self.file("prebuilt/kernel").stat().st_size > 1024 * 1024 if self.file("prebuilt/kernel").is_file() else False,
                     "prebuilt-kernel-size", "boot", "Prebuilt kernel is non-trivial", "prebuilt/kernel", 5)
        self.require(self.file("prebuilt/dtb.img").stat().st_size > 4096 if self.file("prebuilt/dtb.img").is_file() else False,
                     "prebuilt-dtb-size", "boot", "Prebuilt DTB is non-trivial", "prebuilt/dtb.img", 5)
        self.require(self.has_assignment(board, "BOARD_RAMDISK_USE_LZ4", "true"),
                     "ramdisk-lz4", "boot", "Recovery ramdisk uses stock-compatible LZ4", "BoardConfig.mk", 3)

    def check_partitions_and_crypto(self) -> None:
        board = self.text("BoardConfig.mk")
        facts = self.facts["partitions"]
        fstab = self.text("recovery/root/system/etc/recovery.fstab").lower()
        self.require(facts.get("ab") is True and "slotselect" in fstab,
                     "fstab-ab", "partitions", "Stock fstab proves A/B slot selection", "recovery.fstab", 5)
        self.require(facts.get("dynamic") is True and "logical" in fstab,
                     "fstab-logical", "partitions", "Stock fstab proves dynamic/logical partitions", "recovery.fstab", 5)
        self.require("/data" in fstab, "fstab-data", "partitions", "Fstab contains /data", "recovery.fstab", 4)
        self.require("/metadata" in fstab or "metadata" in fstab,
                     "fstab-metadata", "partitions", "Fstab contains metadata storage", "recovery.fstab", 4)
        self.require(self.has_assignment(board, "AB_OTA_UPDATER", "true"),
                     "board-ab", "partitions", "BoardConfig enables A/B", "BoardConfig.mk", 4)
        self.require(self.has_assignment(board, "PRODUCT_USE_DYNAMIC_PARTITIONS", "true"),
                     "board-dynamic", "partitions", "BoardConfig enables dynamic partitions", "BoardConfig.mk", 4)
        self.require(self.facts["encryption"].get("file_based") is True and
                     self.has_assignment(board, "TW_INCLUDE_CRYPTO_FBE", "true"),
                     "crypto-fbe", "encryption", "FBE is proved and enabled", "fstab + BoardConfig.mk", 5)
        self.require(self.facts["encryption"].get("metadata_encryption") is True and
                     self.has_assignment(board, "TW_INCLUDE_FBE_METADATA_DECRYPT", "true"),
                     "crypto-metadata", "encryption", "Metadata encryption is proved and enabled",
                     "fstab + BoardConfig.mk", 5)
        self.warn(self.has_assignment(board, "BOARD_SUPER_PARTITION_SIZE"), "super-size",
                  "partitions", "Exact super partition size is configured",
                  "Exact BOARD_SUPER_PARTITION_SIZE still requires lpdump/blockdev evidence; it was not guessed")
        self.runtime("crypto-runtime", "Unlock /data with the Android 16 user credential and verify file names/content")

    def check_modules_and_init(self) -> None:
        module_dir = self.file("prebuilt/modules")
        modules = list(module_dir.rglob("*.ko")) if module_dir.is_dir() else []
        stock_count = self.facts.get("kernel", {}).get("modules", {}).get("count", 0)
        if stock_count:
            self.require(bool(modules), "modules-present", "kernel-modules",
                         f"Recovery tree contains {len(modules)} stock early-boot modules",
                         "prebuilt/modules", 4)
            self.require(self.file("prebuilt/modules/modules.load.recovery").is_file(),
                         "modules-load-order", "kernel-modules",
                         "Recovery module load order exists", "prebuilt/modules/modules.load.recovery", 4)
        else:
            self.add("modules-present", "kernel-modules", "WARN",
                     "The dump exposed no modules; kernel may be monolithic or sparse checkout may need expansion", weight=0)
        init_files = list(self.file("recovery/root").rglob("init*.rc")) if self.file("recovery/root").is_dir() else []
        self.require(bool(init_files), "init-rc", "init", f"Copied {len(init_files)} stock recovery init rc files",
                     "recovery/root", 4)
        self.runtime("modules-runtime", "Verify touch, UFS, USB and display modules load before TWRP starts")

    def check_security_and_no_build(self) -> None:
        secret_patterns = {
            "classic GitHub token": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
            "fine-grained GitHub token": re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
            "private IPv4": re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
        }
        findings = []
        for path in self.tree.rglob("*"):
            if not path.is_file() or path.suffix.lower() in {".img", ".ko", ".pdf"}:
                continue
            text = read_text(path)
            for label, pattern in secret_patterns.items():
                if pattern.search(text):
                    findings.append(f"{label}:{path.relative_to(self.tree)}")
        self.require(not findings, "security-no-secrets", "security",
                     "No token or private network address is present in generated text files",
                     ", ".join(findings), 5)

        workflow = Path(__file__).resolve().parents[1] / "workflow/generate-tree.yml"
        if workflow.is_file():
            wf = read_text(workflow)
            forbidden = []
            for raw_line in wf.splitlines():
                command = raw_line.strip()
                if command.startswith("run:"):
                    command = command[4:].strip()
                if re.match(r"^(?:mka|ninja|soong_ui|brunch)(?:\s|$)", command):
                    forbidden.append(command)
            self.require(not forbidden, "policy-no-build", "policy",
                         "Generator workflow contains no recovery build command", ", ".join(forbidden), 5)
        else:
            self.add("policy-no-build", "policy", "WARN", "Workflow template not found during validation", weight=0)

    def run(self) -> dict[str, Any]:
        self.check_layout()
        self.check_source_integrity()
        self.check_recovery_base()
        self.check_identity_and_brand()
        self.check_display()
        self.check_boot()
        self.check_partitions_and_crypto()
        self.check_crypto_stack()
        self.check_modules_and_init()
        self.check_security_and_no_build()

        failures = [x for x in self.checks if x["status"] == "FAIL"]
        warnings = [x for x in self.checks if x["status"] == "WARN"]
        runtimes = [x for x in self.checks if x["status"] == "RUNTIME"]
        passes = [x for x in self.checks if x["status"] == "PASS"]
        total_weight = sum(x["weight"] for x in self.checks if x["status"] in {"PASS", "FAIL"})
        pass_weight = sum(x["weight"] for x in passes)
        score = round(100 * pass_weight / total_weight) if total_weight else 0
        readiness = "NEEDS_DATA" if failures else "STATIC_COMPLETE"
        result = {
            "schema_version": 1,
            "readiness": readiness,
            "official_readiness": "NOT_CLAIMED_UNTIL_BUILD_AND_DEVICE_TEST",
            "static_score": score,
            "summary": {
                "pass": len(passes), "warn": len(warnings),
                "fail": len(failures), "runtime": len(runtimes),
            },
            "checks": self.checks,
        }
        return result


def markdown_report(result: dict[str, Any]) -> str:
    icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "RUNTIME": "🧪"}
    lines = [
        "# TWRP tree completeness report",
        "",
        f"**Static readiness:** `{result['readiness']}`  ",
        f"**Static score:** `{result['static_score']}/100`  ",
        f"**Official status:** `{result['official_readiness']}`",
        "",
        "> STATIC_COMPLETE means the source tree is internally complete. It does not claim that an image was built, booted, decrypted data, or accepted by TeamWin.",
        "",
        "| State | Check | Category | Result | Evidence |",
        "|---|---|---|---|---|",
    ]
    for item in result["checks"]:
        evidence = str(item.get("evidence", "")).replace("|", "\\|").replace("\n", "<br>")
        message = item["message"].replace("|", "\\|")
        lines.append(f"| {icon[item['status']]} {item['status']} | `{item['id']}` | {item['category']} | {message} | {evidence} |")
    lines += [
        "",
        "## Rule",
        "",
        "Any ❌ makes the tree `NEEDS_DATA`. 🧪 items are deliberately postponed until a future build/device-test stage; this generator never builds recovery.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Strict static validator for a generated TWRP tree")
    parser.add_argument("--tree", required=True)
    parser.add_argument("--facts", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--json", required=True)
    parser.add_argument("--markdown", required=True)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    result = Validator(Path(args.tree).resolve(), load_json(args.facts), load_json(args.config)).run()
    save_json(args.json, result)
    write_text(Path(args.markdown), markdown_report(result))
    print(f">> readiness: {result['readiness']}")
    print(f">> score: {result['static_score']}/100")
    print(">> checks: " + " ".join(f"{k}={v}" for k, v in result["summary"].items()))
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(markdown_report(result) + "\n")
    if args.strict and result["readiness"] != "STATIC_COMPLETE":
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
