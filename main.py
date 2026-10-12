#!/usr/bin/env python3
"""
SentinelX — File Integrity Monitoring & Secret Scanner
Author: Snayza
Python: 3.10+
Defensive local security utility. Scans files you are authorized to inspect.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

APP_NAME = "SENTINELX"
VERSION = "1.0.0"
STATE_FILE = ".sentinelx_baseline.json"
DEFAULT_EXCLUDES = {".git", ".venv", "venv", "__pycache__", "node_modules", ".idea"}
MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MiB

# Optional color support. The app still works without colorama.
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C = {"red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
         "blue": Fore.CYAN, "purple": Fore.MAGENTA, "dim": Style.DIM,
         "bold": Style.BRIGHT, "reset": Style.RESET_ALL}
except ImportError:
    C = {k: "" for k in ("red", "green", "yellow", "blue", "purple", "dim", "bold", "reset")}

# Pattern-based detection is intentionally conservative; findings require review.
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key header", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("Generic API key assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\b"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{16,}")),
    ("Possible password assignment", re.compile(
        r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".cs", ".go", ".rs", ".php",
    ".rb", ".env", ".ini", ".cfg", ".conf", ".json", ".yaml", ".yml", ".toml",
    ".xml", ".html", ".css", ".scss", ".sql", ".sh", ".bat", ".ps1", ".md",
    ".txt", ".properties", ".pem", ".key", ".tf", ".gradle"
}
SENSITIVE_NAMES = {".env", ".env.local", ".env.production", "id_rsa", "id_ed25519",
                   "credentials", "secrets.json", "service-account.json"}


def paint(text: str, color: str) -> str:
    return f"{C.get(color, '')}{text}{C['reset']}"


def banner() -> None:
    print(paint(r"""
   _____ ______ _   _ _______ _____ _   _ ______ _      __  __
  / ____|  ____| \ | |__   __|_   _| \ | |  ____| |    \ \/ /
 | (___ | |__  |  \| |  | |    | | |  \| | |__  | |     \  /
  \___ \|  __| | . ` |  | |    | | | . ` |  __| | |      > <
  ____) | |____| |\  |  | |   _| |_| |\  | |____| |____ / . \
 |_____/|______|_| \_|  |_|  |_____|_| \_|______|______/_/ \_\
""", "blue"))
    print(paint("  FILE INTEGRITY MONITOR  •  SECRET SCANNER", "bold"))
    print(paint(f"  Version {VERSION} | Defensive local security toolkit | Author: Snayza", "dim"))
    print()


def timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def sha256_file(path: Path) -> str | None:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


def load_state(root: Path) -> dict[str, Any]:
    state_path = root / STATE_FILE
    if not state_path.exists():
        return {"version": 1, "created_at": None, "files": {}}
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        if not isinstance(data.get("files"), dict):
            raise ValueError("invalid baseline format")
        return data
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(f"Cannot read baseline: {exc}") from exc


def save_state(root: Path, state: dict[str, Any]) -> None:
    state_path = root / STATE_FILE
    temp_path = state_path.with_suffix(".tmp")
    temp_path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    temp_path.replace(state_path)


def iter_files(root: Path, include_hidden: bool = False):
    root = root.resolve()
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in DEFAULT_EXCLUDES and
                         (include_hidden or not d.startswith(".")))
        for name in sorted(files):
            path = Path(current) / name
            if path.name == STATE_FILE or path.name.endswith(".tmp"):
                continue
            if not include_hidden and any(part.startswith(".") for part in path.relative_to(root).parts):
                continue
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                if path.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            yield path


def relative_key(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def cmd_init(root: Path, include_hidden: bool = False) -> int:
    root.mkdir(parents=True, exist_ok=True)
    files: dict[str, dict[str, Any]] = {}
    skipped = 0
    for path in iter_files(root, include_hidden):
        digest = sha256_file(path)
        if digest is None:
            skipped += 1
            continue
        try:
            rel = relative_key(root, path)
            files[rel] = {"sha256": digest, "size": path.stat().st_size}
        except (OSError, ValueError):
            skipped += 1
    state = {"version": 1, "created_at": timestamp(), "root": str(root.resolve()), "files": files}
    save_state(root, state)
    print(paint("[+] Baseline created", "green"))
    print(f"    Root: {root.resolve()}")
    print(f"    Files fingerprinted: {len(files)}")
    if skipped:
        print(paint(f"    Files skipped due to access/path errors: {skipped}", "yellow"))
    print(paint(f"    Saved: {root / STATE_FILE}", "dim"))
    print(paint("    Keep this baseline file protected; an attacker with write access could alter it.", "yellow"))
    return 0


def cmd_integrity(root: Path, include_hidden: bool = False) -> int:
    try:
        state = load_state(root)
    except RuntimeError as exc:
        print(paint(f"[!] {exc}", "red"))
        print("    Run `python main.py init --path <folder>` to create a baseline.")
        return 2
    baseline = state["files"]
    current: dict[str, dict[str, Any]] = {}
    errors = 0
    for path in iter_files(root, include_hidden):
        digest = sha256_file(path)
        if digest is None:
            errors += 1
            continue
        try:
            current[relative_key(root, path)] = {"sha256": digest, "size": path.stat().st_size}
        except (OSError, ValueError):
            errors += 1

    added = sorted(set(current) - set(baseline))
    removed = sorted(set(baseline) - set(current))
    changed = sorted(k for k in set(current) & set(baseline)
                     if current[k]["sha256"] != baseline[k].get("sha256"))
    print(paint("INTEGRITY REPORT", "bold"))
    print(f"  Baseline created: {state.get('created_at') or 'unknown'}")
    print(f"  Files now: {len(current)} | Baseline: {len(baseline)}")
    print()
    if not (added or removed or changed):
        print(paint("  [OK] No file changes detected.", "green"))
    for label, entries, color in (("ADDED", added, "blue"), ("MODIFIED", changed, "yellow"),
                                  ("MISSING", removed, "red")):
        if entries:
            print(paint(f"  {label} ({len(entries)})", color))
            for item in entries[:100]:
                print(f"    {'+' if label == 'ADDED' else '~' if label == 'MODIFIED' else '-'} {item}")
            if len(entries) > 100:
                print(f"    ... and {len(entries) - 100} more")
    if errors:
        print(paint(f"  [!] Could not read {errors} file(s).", "yellow"))
    print()
    return 1 if added or removed or changed else 0


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * min(16, len(value) - 8) + value[-4:]


def cmd_secrets(root: Path, include_hidden: bool = False) -> int:
    findings = []
    scanned = 0
    for path in iter_files(root, include_hidden):
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in SENSITIVE_NAMES:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        for line_no, line in enumerate(content.splitlines(), 1):
            for label, pattern in SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Never print the full matched credential.
                    findings.append((relative_key(root, path), line_no, label, mask_secret(match.group(0))))
                    break
    print(paint("SECRET SCAN REPORT", "bold"))
    print(f"  Text files scanned: {scanned}")
    print()
    if not findings:
        print(paint("  [OK] No likely secrets detected by configured patterns.", "green"))
    else:
        print(paint(f"  [!] Potential findings: {len(findings)}", "red"))
        for filename, line_no, label, preview in findings[:100]:
            print(f"    {paint('FINDING', 'red')} {filename}:{line_no}")
            print(f"      Type: {label}")
            print(f"      Match: {preview}")
        if len(findings) > 100:
            print(f"    ... and {len(findings) - 100} more")
        print()
        print(paint("  Review findings manually. Pattern matches can be false positives.", "yellow"))
    return 1 if findings else 0


def cmd_status(root: Path) -> int:
    try:
        state = load_state(root)
    except RuntimeError as exc:
        print(paint(f"[!] {exc}", "red"))
        return 2
    print(paint("SENTINELX STATUS", "bold"))
    print(f"  Target directory : {root.resolve()}")
    print(f"  Baseline         : {'READY' if state.get('files') else 'NOT INITIALIZED'}")
    print(f"  Baseline files   : {len(state.get('files', {}))}")
    print(f"  Created          : {state.get('created_at') or '—'}")
    print(f"  State file       : {root / STATE_FILE}")
    return 0


def interactive() -> int:
    while True:
        banner()
        print("  [1] Initialize / refresh integrity baseline")
        print("  [2] Check file integrity")
        print("  [3] Scan for exposed secrets")
        print("  [4] Show project status")
        print("  [5] Change scan directory")
        print("  [0] Exit")
        print()
        raw_path = input("  Scan directory [current folder]: ").strip()
        root = Path(raw_path.strip('"')) if raw_path else Path.cwd()
        print()
        choice = input("  Select option > ").strip()
        print()
        try:
            if choice == "1":
                confirm = input("  Create/replace baseline? [y/N] > ").strip().lower()
                if confirm == "y":
                    cmd_init(root)
                else:
                    print("  Cancelled.")
            elif choice == "2":
                cmd_integrity(root)
            elif choice == "3":
                cmd_secrets(root)
            elif choice == "4":
                cmd_status(root)
            elif choice == "5":
                print("  Enter a path on the next screen.")
            elif choice == "0":
                print(paint("  SentinelX shutting down. Stay vigilant.", "blue"))
                return 0
            else:
                print(paint("  Invalid option.", "yellow"))
        except KeyboardInterrupt:
            print("\n  Cancelled.")
        input("\n  Press Enter to return to the dashboard...")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SentinelX: local file integrity monitoring and secret scanning.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python main.py
  python main.py init --path .
  python main.py integrity --path . --include-hidden
  python main.py secrets --path .""")
    sub = parser.add_subparsers(dest="command")
    for name, help_text in [
        ("init", "Create a SHA-256 integrity baseline"),
        ("integrity", "Compare current files with the saved baseline"),
        ("secrets", "Scan text files for likely exposed credentials"),
        ("status", "Show baseline status"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--path", default=".", help="Folder to scan (default: current directory)")
        p.add_argument("--include-hidden", action="store_true", help="Include hidden files/folders")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        return interactive()
    root = Path(args.path).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(paint(f"[!] Directory does not exist or is not a folder: {root}", "red"))
        return 2
    if args.command == "init":
        return cmd_init(root, args.include_hidden)
    if args.command == "integrity":
        return cmd_integrity(root, args.include_hidden)
    if args.command == "secrets":
        return cmd_secrets(root, args.include_hidden)
    if args.command == "status":
        return cmd_status(root)
    parser.print_help()
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        raise SystemExit(130)
