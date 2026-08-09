#!/usr/bin/env bash
# Full generate + dual audit + optional publish pipeline. It never builds recovery.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK:-$ROOT/work}"; DUMP="$WORK/dump"; TREE="$WORK/output/android_device_infinix_x6886"; REPORTS="$WORK/reports"; FACTS="$WORK/facts.json"; CONFIG="$ROOT/config/x6886.json"
DUMP_REPO="${DUMP_REPO:-https://gitlab.com/Il103/android_dump_infinix_x6886.git}"; DUMP_BRANCH="${DUMP_BRANCH:-a16}"
OUTPUT_OWNER="${OUTPUT_OWNER:-Il103}"; OUTPUT_REPO="${OUTPUT_REPO:-android_device_infinix_X6886_TWRP-A16}"; OUTPUT_BRANCH="${OUTPUT_BRANCH:-twrp-14.1-a16}"; OUTPUT_VISIBILITY="${OUTPUT_VISIBILITY:-public}"; PUBLISH="${PUBLISH:-false}"
if [[ "$OUTPUT_BRANCH" == "twrp-12.1-a16" ]]; then echo "::warning::migrating obsolete output branch to twrp-14.1-a16"; OUTPUT_BRANCH="twrp-14.1-a16"; fi
if [[ "$PUBLISH" == "true" && -z "${TREE_PUSH_TOKEN:-}" ]]; then echo "::warning::publish=true but TREE_PUSH_TOKEN is unset; generating complete artifact without publishing"; PUBLISH="false"; fi
rm -rf "$WORK"; mkdir -p "$WORK" "$REPORTS"; export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
echo "#################### 00 generator regression tests ####################"
python3 -m unittest discover -s "$ROOT/tests" -v
echo "#################### 01 fresh Android 16 evidence ####################"
bash "$ROOT/scripts/fetch_dump.sh" "$DUMP_REPO" "$DUMP_BRANCH" "$DUMP"
python3 "$ROOT/scripts/hydrate_runtime_refs.py" --dump "$DUMP" --report "$DUMP/crypto_hydration.json"
echo "#################### 02 collect Android 16 recovery facts ####################"
python3 "$ROOT/scripts/collect_a16.py" --dump "$DUMP" --config "$CONFIG" --out "$FACTS" --source-url "$DUMP_REPO" --source-branch "$DUMP_BRANCH"
echo "#################### 03 generate + harden TWRP 14.1 tree ####################"
python3 -m treeforge generate --dump "$DUMP" --facts "$FACTS" --config "$CONFIG" --out "$TREE"
python3 "$ROOT/scripts/harden_tree.py" apply --dump "$DUMP" --facts "$FACTS" --tree "$TREE"
echo "#################### 04 strict completeness audits ####################"
export TREEFORGE_DUMP="$DUMP"
python3 -m treeforge validate --tree "$TREE" --facts "$FACTS" --config "$CONFIG" --json "$REPORTS/validation.json" --markdown "$REPORTS/validation.md" --strict
python3 "$ROOT/scripts/harden_tree.py" audit --dump "$DUMP" --facts "$FACTS" --tree "$TREE" --json "$REPORTS/recovery14-audit.json" --markdown "$REPORTS/recovery14-audit.md" --strict
mkdir -p "$TREE/_reports"
cp "$REPORTS/validation.json" "$TREE/_reports/validation.json"; cp "$REPORTS/validation.md" "$TREE/_reports/validation.md"; cp "$REPORTS/recovery14-audit.json" "$TREE/_reports/recovery14-audit.json"; cp "$REPORTS/recovery14-audit.md" "$TREE/_reports/recovery14-audit.md"
find "$TREE" -type f -printf '%P\n' | sort > "$TREE/_reports/file-list.txt"
(cd "$TREE" && find . -type f -not -path './_reports/checksums.sha256' -print0 | sort -z | xargs -0 sha256sum > _reports/checksums.sha256)
echo ">> generated tree files: $(find "$TREE" -type f | wc -l)"; echo ">> tree size: $(du -sh "$TREE" | cut -f1)"; echo ">> no build was run; boot and decryption remain runtime tests"
if [[ "$PUBLISH" == "true" ]]; then
 : "${TREE_PUSH_TOKEN:?Add TREE_PUSH_TOKEN as a GitHub Actions secret; never paste it into a file or log}"
 echo "#################### 05 publish validated source tree ####################"
 python3 -m treeforge publish --tree "$TREE" --owner "$OUTPUT_OWNER" --repo "$OUTPUT_REPO" --branch "$OUTPUT_BRANCH" --visibility "$OUTPUT_VISIBILITY"
else echo ">> publish disabled; validated tree remains in the Actions artifact"; fi
