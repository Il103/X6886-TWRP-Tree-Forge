from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any, Iterable


PLACEHOLDER = re.compile(r"(?:^|[-_.])(mssi|generic|unknown)(?:$|[-_.])", re.I)


def load_json(path: os.PathLike[str] | str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"expected a JSON object in {path}")
    return data


def save_json(path: os.PathLike[str] | str, data: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                 encoding="utf-8")


def read_text(path: os.PathLike[str] | str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def sha256_file(path: os.PathLike[str] | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_record(root: Path, path: Path) -> dict[str, Any]:
    st = path.stat()
    return {
        "path": str(path.relative_to(root)),
        "bytes": st.st_size,
        "sha256": sha256_file(path),
    }


def is_real_value(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    return bool(text) and not PLACEHOLDER.search(text)


def normalize_codename(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"^(?:infinix|tecno|itel)[-_]", "", value)
    value = re.sub(r"[^a-z0-9_.-]", "", value)
    return value


def mkdir_clean(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def copy_file(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def copy_tree_filtered(source: Path, target: Path,
                       suffixes: Iterable[str] | None = None) -> list[str]:
    copied: list[str] = []
    allowed = {x.lower() for x in suffixes} if suffixes else None
    if not source.is_dir():
        return copied
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        if allowed is not None and path.suffix.lower() not in allowed:
            continue
        rel = path.relative_to(source)
        copy_file(path, target / rel)
        copied.append(str(rel))
    return copied


def first_existing(root: Path, relative_paths: Iterable[str]) -> Path | None:
    for rel in relative_paths:
        path = root / rel
        if path.is_file():
            return path
    return None


def parse_key_value(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in read_text(path).splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out.setdefault(key.strip(), value.strip())
    return out


def unique(items: Iterable[Any]) -> list[Any]:
    seen = set()
    out = []
    for item in items:
        marker = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else item
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    return out


def markdown_table(rows: list[tuple[str, str]]) -> str:
    lines = ["| Field | Value |", "|---|---|"]
    for key, value in rows:
        value = str(value).replace("|", "\\|").replace("\n", "<br>")
        lines.append(f"| {key} | {value} |")
    return "\n".join(lines)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.rstrip() + "\n", encoding="utf-8")


def parse_size(value: Any) -> int | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def check_id(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
