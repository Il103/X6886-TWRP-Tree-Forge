from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from treeforge.collect import Collector
from treeforge.common import load_json, save_json
from treeforge.generate import Generator
from treeforge.validate import Validator


class EndToEndTest(unittest.TestCase):
    def make_dump(self, root: Path) -> Path:
        dump = root / "dump"
        (dump / "system/system").mkdir(parents=True)
        (dump / "boot").mkdir()
        (dump / "vendor_boot/recovery_ramdisk/system/etc").mkdir(parents=True)
        (dump / "vendor_boot/recovery_ramdisk/first_stage_ramdisk").mkdir(parents=True)
        (dump / "vendor_boot/ramdisk/first_stage_ramdisk").mkdir(parents=True)
        (dump / "vendor_boot/ramdisk/lib/modules").mkdir(parents=True)
        (dump / "vendor/bin/hw").mkdir(parents=True)
        (dump / "vendor/lib64").mkdir(parents=True)
        (dump / "vendor/etc/init").mkdir(parents=True)
        (dump / "vendor/etc/vintf/manifest").mkdir(parents=True)
        (dump / "images").mkdir()

        (dump / "system/system/build.prop").write_text("""
ro.product.brand=Infinix
ro.product.manufacturer=INFINIX
ro.product.model=Infinix X6886
ro.product.device=tssi
ro.product.name=tssi
ro.product.board=common
ro.board.platform=common
ro.build.version.release=16
ro.build.version.sdk=36
ro.build.version.security_patch=2026-08-01
ro.build.version.incremental=301400084
ro.build.id=BP2A.250605.031.A3
ro.build.fingerprint=Transsion/tssi/mssi_64_64only_cn_armv82:16/BP2A.250605.031.A3/301400084:user/release-keys
ro.product.cpu.abilist=arm64-v8a,armeabi-v7a,armeabi
ro.sf.lcd_density=420
""".strip() + "\n")
        (dump / "README.md").write_text("- Codename: x6886\n- Platform: mt6789\n")
        (dump / "kernel_version.txt").write_text("Linux version 6.12.38-android16-5-test\n")
        (dump / "kernel_config.txt").write_text("CONFIG_EROFS_FS=y\nCONFIG_F2FS_FS=y\nCONFIG_DM_CRYPT=y\n")
        (dump / "boot/kernel").write_bytes(b"K" * (2 * 1024 * 1024))
        (dump / "vendor_boot/dtb").write_bytes(b"D" * 8192)
        (dump / "vendor_boot/dtb.dts").write_text('/dts-v1/; / { model = "Infinix X6886"; compatible = "infinix,x6886"; };\n')
        (dump / "vendor_boot/bootconfig").write_text("androidboot.hardware=mt6789\nandroidboot.force_normal_boot=1\n")
        (dump / "boot/header_info.json").write_text(json.dumps({
            "image": "boot.img", "bytes": 67108864, "format": "boot",
            "header_version": 4, "page_size": 4096, "cmdline": "",
            "kernel": {"size": 18885902, "file": "kernel", "format": "lz4_legacy"},
            "ramdisk": {"size": 0, "note": "empty (normal for GKI boot)"},
        }))
        (dump / "vendor_boot/header_info.json").write_text(json.dumps({
            "image": "vendor_boot.img", "bytes": 67108864, "format": "vendor_boot",
            "header_version": 4, "page_size": 4096,
            "cmdline": "bootopt=64S3,32N2,64N2 bootconfig",
            "dtb": {"size": 183850, "file": "dtb"},
            "bootconfig": {"size": 94, "file": "bootconfig"},
            "ramdisk_fragments": [
                {"file": "ramdisk", "name": "", "type": "platform", "size": 29692572, "format": "lz4_legacy"},
                {"file": "recovery_ramdisk", "name": "recovery", "type": "recovery", "size": 3209026, "format": "lz4_legacy"},
            ],
        }))
        recovery_fstab = """# stock recovery fstab intentionally omits super logical mounts
/metadata ext4 /dev/block/by-name/metadata flags=first_stage_mount
/data f2fs /dev/block/by-name/userdata flags=fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized;keydirectory=/metadata/vold/metadata_encryption;metadata_encryption=aes-256-xts;quota
/boot emmc /dev/block/by-name/boot flags=slotselect
/vendor_boot emmc /dev/block/by-name/vendor_boot flags=slotselect
/dtbo emmc /dev/block/by-name/dtbo flags=slotselect
/misc emmc /dev/block/by-name/misc
"""
        (dump / "vendor_boot/recovery_ramdisk/system/etc/recovery.fstab").write_text(recovery_fstab)
        (dump / "vendor_boot/recovery_ramdisk/first_stage_ramdisk/fstab.emmc").write_text(
            "/dev/block/mapper/system /system erofs ro wait,slotselect,logical,first_stage_mount\n")
        (dump / "vendor_boot/ramdisk/first_stage_ramdisk/fstab.mt6789").write_text(
            "/dev/block/mapper/system /system erofs ro wait,slotselect,logical,first_stage_mount\n")
        for index in range(60):
            (dump / f"vendor_boot/recovery_ramdisk/init.recovery.test{index}.rc").write_text(
                f"on init\n    setprop beru.test.{index} 1\n")
        (dump / "vendor_boot/ramdisk/lib/modules/touch.ko").write_bytes(b"module" * 1024)
        (dump / "vendor_boot/ramdisk/lib/modules/ufs.ko").write_bytes(b"module" * 1024)
        (dump / "vendor_boot/ramdisk/lib/modules/clk-mt6789.ko").write_bytes(b"module" * 1024)
        (dump / "vendor_boot/ramdisk/lib/modules/panel-x6886.ko").write_bytes(b"module" * 1024)
        (dump / "vendor_boot/ramdisk/lib/modules/modules.load").write_text("ufs.ko\ntouch.ko\n")
        for partition in ("product", "system_ext", "odm"):
            (dump / partition).mkdir(exist_ok=True)
            (dump / partition / ".treeforge-test-evidence").write_text("present\n")
        (dump / "images/dtbo.img").write_bytes(b"T" * 16384)
        (dump / "images/boot.img").write_bytes(b"B" * 65536)
        (dump / "images/vendor_boot.img").write_bytes(b"V" * 65536)
        (dump / "images/vbmeta_system.img").write_bytes(b"S" * 4096)
        (dump / "images/vbmeta_vendor.img").write_bytes(b"W" * 4096)

        crypto_files = {
            "vendor/bin/hw/android.hardware.security.keymint-service.mtee": b"ELF-keymint-test",
            "vendor/bin/hw/android.hardware.gatekeeper-service.mtee": b"ELF-gatekeeper-test",
            "vendor/lib64/libkeymint_support.so": b"ELF-keymint-support-test",
            "vendor/lib64/libteecli.so": b"ELF-tee-client-test",
            "vendor/etc/init/android.hardware.security.keymint-service.mtee.rc": b"service keymint /vendor/bin/hw/android.hardware.security.keymint-service.mtee\n",
            "vendor/etc/init/android.hardware.gatekeeper-service.mtee.rc": b"service gatekeeper /vendor/bin/hw/android.hardware.gatekeeper-service.mtee\n",
            "vendor/etc/vintf/manifest/android.hardware.security.keymint-service.mtee.xml": b"<manifest><hal><name>android.hardware.security.keymint</name></hal></manifest>\n",
            "vendor/etc/vintf/manifest/android.hardware.gatekeeper-service.mtee.xml": b"<manifest><hal><name>android.hardware.gatekeeper</name></hal></manifest>\n",
        }
        for relative, data in crypto_files.items():
            path = dump / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (dump / "crypto_hydration.json").write_text(json.dumps({
            "schema_version": 1,
            "strategy": "stock-keymint-readelf-dependency-closure",
            "source_android": 16,
            "target_recovery_base": "twrp-14.1",
            "copy_files": [{"path": path, "role": "test-stock-security"} for path in crypto_files],
            "dependencies": {},
            "unresolved_vendor_libraries": [],
            "lfs_pointers": [],
            "readelf_available": True,
        }))
        return dump

    def test_generate_and_validate_static_complete(self):
        repo = Path(__file__).resolve().parents[1]
        config = load_json(repo / "config/x6886.json")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dump = self.make_dump(root)
            facts = Collector(dump, config, "https://gitlab.com/Il103/test.git", "a16").collect()
            self.assertFalse(facts["collection"]["errors"], facts["collection"]["errors"])
            facts_path = root / "facts.json"
            save_json(facts_path, facts)
            tree = root / "output/android_device_infinix_x6886"
            Generator(dump, facts, config, tree).generate()
            old = os.environ.get("TREEFORGE_DUMP")
            os.environ["TREEFORGE_DUMP"] = str(dump)
            try:
                result = Validator(tree, facts, config).run()
            finally:
                if old is None:
                    os.environ.pop("TREEFORGE_DUMP", None)
                else:
                    os.environ["TREEFORGE_DUMP"] = old
            failures = [x for x in result["checks"] if x["status"] == "FAIL"]
            self.assertEqual([], failures)
            self.assertEqual("STATIC_COMPLETE", result["readiness"])
            self.assertEqual(100, result["static_score"])
            self.assertEqual("mt6789", facts["identity"]["platform"]["value"])
            self.assertEqual("derived-from-stock-module-filename", facts["identity"]["platform"]["method"])
            self.assertEqual("x6886", facts["identity"]["codename"]["value"])
            self.assertTrue(facts["partitions"]["dynamic"])
            self.assertTrue(facts["partitions"]["dynamic_evidence"])
            board = (tree / "BoardConfig.mk").read_text()
            self.assertIn("TARGET_SCREEN_WIDTH := 1080", board)
            self.assertIn("TARGET_SCREEN_HEIGHT := 2400", board)
            self.assertIn("TARGET_SCREEN_DENSITY := 420", board)
            self.assertIn("TW_MAINTAINER := B E R U", board)
            self.assertIn("TW_DEVICE_VERSION := BERU-x6886", board)
            self.assertNotIn("BERU-x6886-A16", board)
            self.assertIn("BOARD_INCLUDE_RECOVERY_RAMDISK_IN_VENDOR_BOOT := true", board)
            self.assertIn("TW_PREPARE_DATA_MEDIA_EARLY := true", board)
            self.assertIn("TW_USE_FSCRYPT_POLICY := 2", board)
            self.assertNotIn("OF_MAINTAINER", board)
            generated_fstab = (tree / "recovery/root/system/etc/recovery.fstab").read_text()
            self.assertIn("/dev/block/mapper/system", generated_fstab)
            self.assertIn("logical", generated_fstab)
            self.assertTrue((tree / "_provenance/stock-recovery.fstab").is_file())
            self.assertIn("twrp-14.1", (tree / "README.md").read_text())
            target = load_json(tree / "_provenance/build-target.json")
            self.assertEqual("twrp-14.1", target["manifest_branch"])
            self.assertEqual("twrp-14.1-a16", target["generated_tree_branch"])
            self.assertTrue((tree / "recovery/root/vendor/bin/hw/android.hardware.security.keymint-service.mtee").is_file())
            self.assertIn("android.hardware.security.keymint-service.mtee", (tree / "device.mk").read_text())


if __name__ == "__main__":
    unittest.main()
