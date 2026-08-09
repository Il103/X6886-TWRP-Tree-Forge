from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


API = "https://api.github.com"


def api(token: str, method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, Any]:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "x6886-twrp-tree-forge")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"message": raw[:500]}
        return exc.code, body


def run(command: list[str], cwd: Path, env: dict[str, str], check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    safe_output = result.stdout.replace(env.get("TREE_PUSH_TOKEN", "__never__"), "***")
    if result.returncode and check:
        raise RuntimeError("command failed: " + " ".join(command[:3]) + "\n" + safe_output[-2000:])
    return subprocess.CompletedProcess(result.args, result.returncode, safe_output, None)


def validate_name(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        raise ValueError(f"invalid {label}: {value!r}")
    return value


def publish(tree: Path, owner: str, repo: str, branch: str, visibility: str,
            token: str, message: str) -> None:
    owner = validate_name(owner, "owner")
    repo = validate_name(repo, "repository")
    branch = validate_name(branch, "branch")
    if not tree.is_dir() or not (tree / "BoardConfig.mk").is_file():
        raise ValueError("--tree is not a generated TWRP device tree")
    if len(token) < 20:
        raise ValueError("TREE_PUSH_TOKEN is missing or implausibly short")

    code, body = api(token, "GET", f"/repos/{owner}/{repo}")
    if code == 404:
        code, body = api(token, "POST", "/user/repos", {
            "name": repo,
            "description": "B E R U's generated TWRP device tree for Infinix X6886 / Android 16",
            "private": visibility == "private",
            "has_issues": True,
            "has_projects": False,
            "has_wiki": False,
            "auto_init": False,
        })
        if code not in {200, 201}:
            raise RuntimeError(f"GitHub could not create {owner}/{repo}: HTTP {code} {body.get('message', '')}")
        print(f">> created GitHub repository {owner}/{repo}")
    elif code != 200:
        raise RuntimeError(f"GitHub repository lookup failed: HTTP {code} {body.get('message', '')}")
    else:
        print(f">> using existing GitHub repository {owner}/{repo}")

    with tempfile.TemporaryDirectory(prefix="treeforge_publish_") as td:
        base = Path(td)
        work = base / "repo"
        askpass = base / "askpass.sh"
        askpass.write_text("#!/usr/bin/env sh\ncase \"$1\" in *Username*) printf '%s\\n' x-access-token;; *Password*) printf '%s\\n' \"$TREE_PUSH_TOKEN\";; esac\n")
        askpass.chmod(0o700)
        env = os.environ.copy()
        env.update({
            "TREE_PUSH_TOKEN": token,
            "GIT_ASKPASS": str(askpass),
            "GIT_TERMINAL_PROMPT": "0",
        })
        scheme = "https"
        host = "github.com"
        url = f"{scheme}://{host}/{owner}/{repo}.git"
        clone = run(["git", "clone", "--depth=1", "--branch", branch, url, str(work)], base, env, check=False)
        if clone.returncode:
            work.mkdir()
            run(["git", "init"], work, env)
            run(["git", "checkout", "-b", branch], work, env)
            run(["git", "remote", "add", "origin", url], work, env)
        else:
            for child in work.iterdir():
                if child.name == ".git":
                    continue
                shutil.rmtree(child) if child.is_dir() else child.unlink()

        for source in tree.rglob("*"):
            if not source.is_file():
                continue
            rel = source.relative_to(tree)
            target = work / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        run(["git", "config", "user.name", "B E R U Tree Forge"], work, env)
        run(["git", "config", "user.email", "berucrypt02@gmail.com"], work, env)
        run(["git", "add", "-A"], work, env)
        diff = run(["git", "diff", "--cached", "--quiet"], work, env, check=False)
        if diff.returncode == 0:
            print(">> output repository already matches the generated tree")
            return
        run(["git", "commit", "-m", message], work, env)
        run(["git", "push", "origin", f"HEAD:refs/heads/{branch}"], work, env)
        print(f">> published {scheme}://{host}/{owner}/{repo}/tree/{branch}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Publish a validated tree without exposing the token")
    parser.add_argument("--tree", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--branch", default="twrp-14.1-a16")
    parser.add_argument("--visibility", choices=["public", "private"], default="public")
    parser.add_argument("--message", default="x6886: generate TWRP 14.1 tree from Android 16 stock")
    args = parser.parse_args(argv)
    token = os.environ.get("TREE_PUSH_TOKEN", "")
    publish(Path(args.tree).resolve(), args.owner, args.repo, args.branch,
            args.visibility, token, args.message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
