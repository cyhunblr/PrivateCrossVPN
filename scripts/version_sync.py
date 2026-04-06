#!/usr/bin/env python3
"""Sync project version references from commit history.

This script computes the next semantic version using the same rules as release
workflow and keeps local version references consistent.

Rules:
- major: any commit body contains BREAKING CHANGE / BREAKING-CHANGE, or subject
  uses conventional-commit bang syntax (e.g. feat!: ... or feat(api)!: ...)
- minor: any commit subject starts with feat: or feat(scope):
- patch: otherwise
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BASE_VERSION = "1.2.0"


@dataclass
class SyncTarget:
    path: Path
    pattern: re.Pattern[str]
    replacement: str
    name: str


def run_git(args: list[str], cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _detect_bump_type(subjects: str, bodies: str) -> str:
    bump_type = "patch"
    if re.search(r"BREAKING CHANGE|BREAKING-CHANGE", bodies):
        bump_type = "major"
    elif re.search(r"^[a-zA-Z0-9_-]+\([^)]+\)!:", subjects, re.MULTILINE) or re.search(
        r"^[a-zA-Z0-9_-]+!:", subjects, re.MULTILINE
    ):
        bump_type = "major"
    elif re.search(r"^feat(\([^)]+\))?:", subjects, re.MULTILINE):
        bump_type = "minor"
    return bump_type


def _bump_rank(bump_type: str) -> int:
    ranks = {"patch": 0, "minor": 1, "major": 2}
    return ranks.get(bump_type, 0)


def compute_next_version(
    repo_root: Path, base_version: str, pending_message: str | None = None
) -> str:
    latest_tag = run_git(["tag", "--list", "v*", "--sort=-v:refname"], repo_root)
    latest_tag = latest_tag.splitlines()[0] if latest_tag else ""

    if latest_tag:
        base = latest_tag[1:] if latest_tag.startswith("v") else latest_tag
        log_range = f"{latest_tag}..HEAD"
    else:
        base = base_version
        log_range = "HEAD"

    commit_count = int(run_git(["rev-list", "--count", log_range], repo_root) or "0")
    if latest_tag and commit_count == 0 and not pending_message:
        # When HEAD is exactly at the latest release tag, keep that version.
        return base

    subjects = run_git(["log", "--format=%s", log_range], repo_root)
    bodies = run_git(["log", "--format=%B", log_range], repo_root)

    bump_type = _detect_bump_type(subjects, bodies)

    if pending_message:
        pending_subject = (
            pending_message.splitlines()[0] if pending_message.splitlines() else ""
        )
        pending_bump = _detect_bump_type(pending_subject, pending_message)
        if _bump_rank(pending_bump) > _bump_rank(bump_type):
            bump_type = pending_bump

    major, minor, patch = (int(p) for p in base.split("."))
    if bump_type == "major":
        return f"{major + 1}.0.0"
    if bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def build_targets(repo_root: Path, version: str) -> list[SyncTarget]:
    return [
        SyncTarget(
            path=repo_root / "privatecrossvpn.py",
            pattern=re.compile(
                r'(APP_VERSION\s*=\s*os\.environ\.get\("PVCVPN_VERSION",\s*")[0-9]+\.[0-9]+\.[0-9]+("\))'
            ),
            replacement=rf"\g<1>{version}\g<2>",
            name="app runtime version",
        ),
        SyncTarget(
            path=repo_root / ".github" / "workflows" / "release.yml",
            pattern=re.compile(r'(base_version=")[0-9]+\.[0-9]+\.[0-9]+(")'),
            replacement=rf"\g<1>{version}\g<2>",
            name="release fallback base version",
        ),
        SyncTarget(
            path=repo_root / "README.md",
            pattern=re.compile(
                r"(\|\s+PrivateCrossVPN v)[0-9]+\.[0-9]+\.[0-9]+(\s+\|)"
            ),
            replacement=rf"\g<1>{version}\g<2>",
            name="README screenshot version",
        ),
        SyncTarget(
            path=repo_root / "README.md",
            pattern=re.compile(
                r"(img\.shields\.io/badge/release-v)[0-9]+\.[0-9]+\.[0-9]+(-blue)"
            ),
            replacement=rf"\g<1>{version}\g<2>",
            name="README release badge version",
        ),
        SyncTarget(
            path=repo_root / "mobile" / "pubspec.yaml",
            pattern=re.compile(r"(version:\s*)[0-9]+\.[0-9]+\.[0-9]+(\+[0-9]+)?"),
            replacement=rf"\g<1>{version}\g<2>",
            name="mobile pubspec version",
        ),
    ]


def apply_target(target: SyncTarget, write: bool) -> tuple[bool, str]:
    content = target.path.read_text(encoding="utf-8")
    updated, count = target.pattern.subn(target.replacement, content, count=1)
    if count != 1:
        raise RuntimeError(
            f"Could not update {target.name} in {target.path}. Pattern match count={count}."
        )
    changed = updated != content
    if changed and write:
        target.path.write_text(updated, encoding="utf-8")
    return changed, target.name


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync project version references")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check whether version references are already in sync.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Apply version reference updates in-place.",
    )
    parser.add_argument(
        "--print-version",
        action="store_true",
        help="Print only the computed version.",
    )
    parser.add_argument(
        "--base-version",
        default=DEFAULT_BASE_VERSION,
        help=f"Fallback base version when no v* tag exists (default: {DEFAULT_BASE_VERSION}).",
    )
    parser.add_argument(
        "--pending-message-file",
        help="Optional path to pending commit message file to include its bump type in version calculation.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.check and args.write:
        print("Use either --check or --write, not both.", file=sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parent.parent

    pending_message = None
    if args.pending_message_file:
        try:
            pending_message = Path(args.pending_message_file).read_text(
                encoding="utf-8"
            )
        except Exception as exc:
            print(f"Could not read pending message file: {exc}", file=sys.stderr)
            return 1

    try:
        version = compute_next_version(repo_root, args.base_version, pending_message)
    except Exception as exc:
        print(f"Version calculation failed: {exc}", file=sys.stderr)
        return 1

    if args.print_version:
        print(version)
        return 0

    mode_write = args.write or not args.check
    targets = build_targets(repo_root, version)

    changed_any = False
    changed_names: list[str] = []

    try:
        for target in targets:
            changed, name = apply_target(target, write=mode_write)
            if changed:
                changed_any = True
                changed_names.append(f"{target.path.relative_to(repo_root)} ({name})")
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.check:
        if changed_any:
            print("Version references are out of sync.")
            for item in changed_names:
                print(f"- {item}")
            print("Run: python scripts/version_sync.py --write")
            return 1
        print("Version references are in sync.")
        return 0

    if changed_any:
        print(f"Computed version: {version}")
        print("Updated:")
        for item in changed_names:
            print(f"- {item}")
    else:
        print(f"No update needed. Computed version: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
