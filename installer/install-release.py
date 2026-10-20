#!/usr/bin/env python3
"""Install the bundled, pinned source using the existing guarded installer."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def restore_source(bundle, ref, repo):
    repo.mkdir()
    subprocess.run(["git", "init", "--quiet", "-b", "release"], cwd=repo, check=True, timeout=30)
    subprocess.run(
        ["git", "bundle", "unbundle", str(bundle)],
        cwd=repo,
        check=True,
        capture_output=True,
        timeout=60,
    )
    # The package deliberately contains one tree, not repository history. Restore
    # its shallow boundary before Git tries to traverse the original parent.
    (repo / ".git/shallow").write_text(ref + "\n")
    subprocess.run(
        ["git", "checkout", "--quiet", "--detach", ref], cwd=repo, check=True, timeout=60
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "install", "status", "rollback"])
    args, forwarded = parser.parse_known_args()
    allowed = {
        "--prefix",
        "--config",
        "--launcher",
        "--plist",
        "--service",
        "--cache-dir",
        "--full-access",
    }
    if any(arg.startswith("--") and arg.split("=", 1)[0] not in allowed for arg in forwarded):
        parser.error("Unsupported installer option; --repo and --ref are pinned by the release")
    root = Path(__file__).resolve().parent
    info = json.loads((root / "BUILD-INFO.json").read_text())
    ref = info["source_commit"]
    if info.get("schema_version") != 1 or not re.fullmatch("[0-9a-f]{40}", ref):
        raise RuntimeError("Invalid release manifest")
    for name in ("source.bundle", "install.py"):
        actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
        if actual != info["files"][name]:
            raise RuntimeError(f"Release checksum mismatch: {name}")
    with tempfile.TemporaryDirectory(prefix="kirabridge-package-") as temp:
        repo = Path(temp) / "source"
        restore_source(root / "source.bundle", ref, repo)
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo).decode().strip()
        if actual != ref:
            raise RuntimeError("Bundled source commit differs from manifest")
        command = [
            sys.executable,
            str(repo / "installer/install.py"),
            args.action,
            "--repo",
            str(repo),
            "--ref",
            ref,
            *forwarded,
        ]
        # Foreground only. The existing installer owns service switching, idle checks
        # and rollback. Preparing never activates a service or changes existing policy.
        result = subprocess.run(command, check=False)
        return result.returncode


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"Installation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
