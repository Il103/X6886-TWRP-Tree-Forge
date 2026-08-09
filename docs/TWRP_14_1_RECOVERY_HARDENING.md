# X6886 TWRP 14.1 boot and decryption hardening

This stage is based only on the fresh X6886 Android 16 dump. The linked X6840 `twrp-12.1` tree was studied **only as a structural reference**; none of its MT6768 binaries, partition values, fstab lines, Keymaster 4.1 files, boot-control source, properties, or UI settings are copied.

## Structural lessons

The reference separates the first-stage fstab, recovery fstab, device/USB/ueventd/TEE init, and kernel modules. X6886 follows that architecture using only its own MT6789 Android 16 evidence, AIDL KeyMint 3.0 Trustonic stack, and stock module lists.

## Official TWRP 14.1 module loader

`TeamWin/android_bootable_recovery` branch `android-14.1`, commit `426b747737e7ce9e9e17da5b4d2ba883f296aec7`, compiles `kernel_module_loader.cpp` only when `TW_LOAD_VENDOR_MODULES` is non-empty. `TW_LOAD_VENDOR_BOOT_MODULES := true` alone is insufficient.

The hardener preserves the exact stock `modules.load.recovery`, configures the same ordered names in `TW_LOAD_VENDOR_MODULES`, checks vendor_boot plus stock dlkm membership, and keeps vendor_boot loading enabled.

## Android 16 fstab

Android fs_mgr accepts a bare logical name such as `system` in its first column. The old generic parser dropped those rows and appended a second, incompatible syntax. The Android 16 collector recognizes them and preserves the direct stock fstab byte-for-byte while retaining a separate first-stage fstab. No block device, AVB flag, encryption mode, filesystem, or size is guessed.

## KeyMint/Trustonic runtime closure

`DT_NEEDED` alone misses init-time helpers and Trustonic registry blobs. The runtime hydration stage parses the stock security rc chain, hydrates its service executables and required `/vendor/app/mcRegistry/*.drbin` objects from the same dump, follows newly found ELF dependencies, records optional unavailable APEX media/DRM artifacts as warnings, and fails on missing required files. The collector now carries this `runtime_references` evidence into `facts.json` so the audit can verify packaging instead of re-deriving it.

`init.recovery.project.rc` imports the exact stock security rc files. The stock X6886 `init.recovery.mt6789.rc` already imports that project path, so service names, users, groups, classes, arguments, and property triggers remain stock.

## Trustonic persistent registry mount

The stock Trustonic service arguments reference a persistent registry directory (for example `/mnt/vendor/persist/mcRegistry`). If the stock recovery fstab already mounts that path, the tree uses it byte-for-byte. If it does not, the generated project rc creates and mounts the directory using the device node and filesystem evidenced by the dump's own fstab records (the sibling X6840 tree proved this mount is required for Trustonic to initialise). The audit accepts either coverage source and fails if neither exists.

## Static completion is not runtime proof

A 100% source audit does not prove build, image fit, boot, HAL registration, or decryption. Final proof still requires a `twrp-14.1` `vendorbootimage`, an X6886 boot test, recovery/logcat/dmesg capture, display/touch/UFS/USB/TEE module checks, Trustonic/KeyMint/Gatekeeper registration, and unlocking Android 16 `/data` with the real credential while verifying filenames and file contents.
