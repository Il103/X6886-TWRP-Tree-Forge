# What “complete” means

The forge separates facts that can be proven without a build from behavior that only a booted recovery can prove.

## Static gate (must pass now)

A generated tree is `STATIC_COMPLETE` only when all critical checks pass:

- Android 16 dump identity matches Infinix X6886 / mt6789.
- No file or value comes from an Android 15 recovery tree.
- No OrangeFox build flag, identity, or asset is present.
- boot and vendor_boot headers are v4.
- vendor_boot contains a real type-2 `recovery` fragment and its extracted root.
- Kernel, DTB, bootconfig and stock recovery fstab are present.
- A/B (`slotselect`) and dynamic partitions (`logical`) are proved by fstab.
- FBE and metadata encryption flags are present and configured.
- Stock Android 16 KeyMint and Gatekeeper service binaries are present.
- Their init rc and VINTF manifests are present.
- `readelf` resolves their vendor dependency closure with no unresolved library or LFS pointer.
- The generated recovery source base is exactly `twrp-14.1`; the output branch is `twrp-14.1-a16`.
- Display is exactly 1080×2400, density 420, portrait HDPI.
- TWRP maintainer/version identify B E R U.
- Copied binaries match source hashes.
- No token, private IP, raw hardware PDF, or other secret is published.
- The generator workflow contains no build command.

Any failed critical check produces `NEEDS_DATA` and stops publishing.

## Runtime gate (deliberately later)

No source-tree generator can honestly prove these without building and booting:

- framebuffer pixel order (RGBX/BGRA/ABGR),
- brightness sysfs path and numeric range,
- touch orientation/scaling at all corners,
- USB/MTP/ADB behavior,
- early module load order,
- vibration/haptics,
- KeyMint/Gatekeeper service registration and linker/SELinux health,
- Android 16 `/data` decryption with the real PIN/password,
- backup/restore and fastbootd,
- boot image size and bootloader acceptance.

Those remain `RUNTIME` checks and do not get mislabeled as official-ready. The build/test tool will be a separate future repository, as requested.

## Display choice

The report proves a native 1080×2400 panel at 420 dpi and a touch range of 2401×1081. The generated tree uses:

```make
TARGET_SCREEN_WIDTH := 1080
TARGET_SCREEN_HEIGHT := 2400
TARGET_SCREEN_DENSITY := 420
TW_THEME := portrait_hdpi
```

This avoids an undersized or oversized interface. No touch swap/invert flag is emitted without first-boot evidence.
