#!/usr/bin/env bash
# Fetch only recovery-tree evidence from the Android 16 dump. Never reads an old tree.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

REPO="${1:?dump repository URL}"
BRANCH="${2:?dump branch}"
DEST="${3:?destination directory}"

case "$REPO" in
  https://github.com/*|https://gitlab.com/*) ;;
  *) echo "::error::only HTTPS github.com/gitlab.com dump repositories are allowed"; exit 2 ;;
esac
[[ "$BRANCH" =~ ^[A-Za-z0-9._/-]+$ ]] || { echo "::error::invalid branch"; exit 2; }

rm -rf "$DEST"
export GIT_LFS_SKIP_SMUDGE=1

git clone --filter=blob:none --no-checkout --single-branch --branch "$BRANCH" "$REPO" "$DEST"
cd "$DEST"
git lfs install --local --skip-smudge >/dev/null 2>&1 || true
git sparse-checkout init --no-cone
cat > .git/info/sparse-checkout <<'PATTERNS'
/README.md
/board-info.txt
/ota_metadata.txt
/kernel_config.txt
/kernel_version.txt
/all_files.txt
/boot/**
/vendor_boot/**
/images/boot.img
/images/vendor_boot.img
/images/init_boot.img
/images/dtbo.img
/images/vbmeta*.img
/system/build.prop
/system/system/build.prop
/system/system/etc/build.prop
/product/build.prop
/vendor/build.prop
/odm/build.prop
/system_ext/build.prop
/my_*/build.prop
/my_*/etc/build.prop
/vendor_dlkm/build.prop
/odm_dlkm/build.prop
/system_dlkm/build.prop
/vendor/bin/**
/vendor/lib64/**
/vendor/lib/**
/vendor/etc/fstab*
/vendor/etc/init/**
/vendor/etc/vintf/**
/product/etc/build.prop
/product/bin/**
/product/lib64/**
/product/lib/**
/odm/etc/build.prop
/odm/etc/fstab*
/odm/bin/**
/odm/lib64/**
/odm/lib/**
/odm/etc/init/**
/odm/etc/vintf/**
/system_ext/etc/build.prop
/system_ext/bin/**
/system_ext/lib64/**
/system_ext/lib/**
/system/system/bin/**
/system/system/lib64/**
/system/system/lib/**
/vendor_dlkm/lib/modules/**
/odm_dlkm/lib/modules/**
/system_dlkm/lib/modules/**
PATTERNS

git checkout "$BRANCH"

# Record the immutable Git tree without hydrating every LFS object.  The
# collector uses this only as provenance for super/dynamic-partition metadata
# and partition-root presence.
git ls-tree -r --name-only HEAD > .treeforge-index.txt

# Critical tree inputs must be real blobs, not unresolved LFS pointers.
is_pointer() { head -n 1 "$1" 2>/dev/null | grep -q 'version https://git-lfs.github.com/spec/v1'; }
for p in images/boot.img images/vendor_boot.img images/init_boot.img images/dtbo.img; do
  if [ -f "$p" ] && is_pointer "$p"; then
    git lfs pull --include="$p" --exclude=""
  fi
done

# Hydrate only the stock KeyMint/Gatekeeper seeds and their recursive
# DT_NEEDED closure.  Listing the library trees above is cheap while LFS
# smudging is disabled; the helper fetches only files that decryption needs.
python3 "$ROOT/scripts/hydrate_crypto.py" \
  --dump "$DEST" \
  --report "$DEST/crypto_hydration.json"

printf '>> sparse dump ready: %s\n' "$DEST"
printf '>> checked out files: %s\n' "$(find . -type f -not -path './.git/*' | wc -l)"
