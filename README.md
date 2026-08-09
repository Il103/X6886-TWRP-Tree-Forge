# X6886 TWRP 14.1 Tree Forge

**B E R U's evidence-driven TWRP device-tree generator for Infinix Hot 60 Pro+ (X6886), Android 16.**

This repository creates a new **TWRP 14.1** tree for the Android 16 stock firmware and grades its static completeness. It does **not** compile TWRP, does not build an image, and contains no OrangeFox stage yet.

`twrp-14.1` is the recovery source base; `a16` is the stock firmware generation. The generated-tree branch is therefore exactly `twrp-14.1-a16`.

## Non-negotiable rules

- Fresh Android 16 dump only; no file from the old Android 15 tree.
- Every generated value includes provenance or is clearly marked for runtime verification.
- A failed critical check blocks publishing.
- The raw Device Info HW PDF is not published because it contains local network/session data.
- `TREE_PUSH_TOKEN` is read only from GitHub Actions secrets and is never stored in a remote URL or log.

## Verified X6886 UI profile

| Setting | Value |
|---|---:|
| Native panel | 1080 × 2400 |
| Density | 420 dpi |
| TWRP theme | `portrait_hdpi` |
| Touch range | 2401 × 1081 |
| Panel | `nt37706a_fhdp_dsi_vdo_dsc_boe_boe_144hz_x6886` |
| Supported modes | 60 / 90 / 120 / 144 Hz |
| Maintainer brand | **B E R U** |
| Device version | `BERU-x6886` |

The screen width, height and density are written directly into `BoardConfig.mk`; they are not README-only metadata.

## What the forge does

1. Sparse-clones only recovery-relevant files from the Android 16 dump.
2. Collects props, boot/vendor_boot v4 headers, recovery fragment, fstab, DTB, bootconfig, kernel, modules and hashes.
3. Finds the stock KeyMint, Gatekeeper, secure-clock/shared-secret/TEE files and follows their ELF `DT_NEEDED` dependencies with `readelf`.
4. Generates a clean TeamWin-style tree from those facts.
5. Copies stock kernel/DTB/DTBO, safe recovery init/fstab files, early boot modules, and the hydrated security dependency closure.
6. Runs the strict validator and writes JSON + Markdown reports.
7. Optionally creates a fresh output GitHub repository and publishes only after the static gate passes.

## Why KeyMint is handled this way

Android 16 FBE cannot be declared solved by adding one generic flag. The forge copies the **stock X6886 KeyMint/Gatekeeper services**, their init/VINTF definitions, and every resolvable vendor dependency. Missing services, unresolved libraries, or LFS pointers make the static gate fail. Actual PIN/password decryption remains a first-boot test; the tool never claims it succeeded before that test.

## One-time GitHub setup

The workflow template is kept at `workflow/generate-tree.yml`. Copy it to:

```text
.github/workflows/generate-tree.yml
```

Then add an Actions secret named `TREE_PUSH_TOKEN`:

1. GitHub → **Settings** → **Developer settings** → **Personal access tokens (classic)**.
2. Use `public_repo` for a public generated-tree repository, or `repo` if it will be private.
3. In this repository: **Settings** → **Secrets and variables** → **Actions** → **New repository secret**.
4. Name it exactly `TREE_PUSH_TOKEN`.

Never paste the token into chat, a file, workflow input, commit, or log.

## Run

Open **Actions → Generate and audit X6886 TWRP tree → Run workflow**. Defaults:

- dump: `https://gitlab.com/Il103/android_dump_infinix_x6886.git`
- dump branch: `a16`
- output repo: `android_device_infinix_X6886_TWRP-A16`
- recovery manifest: `minimal-manifest-twrp/platform_manifest_twrp_aosp`, branch `twrp-14.1`
- output branch: `twrp-14.1-a16`

The Actions artifact always contains the generated tree, facts, checksums and validation reports. Publishing occurs only when `publish=true` and the static gate passes.

## Honest readiness states

- `STATIC_COMPLETE`: source structure and evidence checks passed.
- `NEEDS_DATA`: at least one critical fact/file is missing or inconsistent.
- `NOT_CLAIMED_UNTIL_BUILD_AND_DEVICE_TEST`: official readiness is never claimed by this no-build tool.

See [docs/VALIDATION.md](docs/VALIDATION.md) for every static and future runtime gate.

## Local use

```bash
export DUMP_REPO=https://gitlab.com/Il103/android_dump_infinix_x6886.git
export DUMP_BRANCH=a16
export PUBLISH=false
bash scripts/run.sh
```

Apache-2.0 · Maintained by **B E R U**
