"""Shared IO and formatting helpers used by every phase.

Deliberately small and dependency-free (stdlib only) so it imports cleanly on a
laptop that has only installed its own phase's tools.

Every phase script starts with the same two lines so `shared` is importable no
matter which folder you run from:

    import sys; from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
"""

from __future__ import annotations

import csv
import ctypes
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, NoReturn, Sequence

# --------------------------------------------------------------------------
# Console output
#
# ASCII only on purpose: the default Windows console codepage chokes on box
# drawing characters and emoji, and a UnicodeEncodeError mid-demo is a bad look.
# --------------------------------------------------------------------------


def banner(title: str) -> None:
    line = "=" * max(len(title) + 4, 60)
    print(f"\n{line}\n  {title}\n{line}")


def step(message: str) -> None:
    print(f"\n--- {message}")


def info(message: str) -> None:
    print(f"[i] {message}")


def ok(message: str) -> None:
    print(f"[+] {message}")


def warn(message: str) -> None:
    print(f"[!] {message}")


def error(message: str) -> None:
    print(f"[x] {message}", file=sys.stderr)


def die(message: str, code: int = 1) -> NoReturn:
    error(message)
    sys.exit(code)


def print_table(rows: Sequence[Sequence[Any]], headers: Sequence[str]) -> None:
    """Plain fixed-width table. Good enough for a terminal and for screenshots."""
    if not rows:
        print("  (no rows)")
        return
    cells = [[("" if c is None else str(c)) for c in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in cells:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(cell))
    fmt = "  ".join("{:<%d}" % w for w in widths)
    print(fmt.format(*headers))
    print("  ".join("-" * w for w in widths))
    for row in cells:
        padded = list(row) + [""] * (len(headers) - len(row))
        print(fmt.format(*padded[: len(headers)]))


def confirm(question: str, default: bool = False) -> bool:
    """Yes/no prompt. Returns `default` if stdin is not a terminal."""
    if not sys.stdin or not sys.stdin.isatty():
        return default
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input(question + suffix).strip().lower()
    if not answer:
        return default
    return answer.startswith("y")


def pause(message: str = "Press Enter to continue...") -> None:
    if sys.stdin and sys.stdin.isatty():
        input(message)
    else:
        info(f"(non-interactive; skipping prompt: {message})")


# --------------------------------------------------------------------------
# Time
# --------------------------------------------------------------------------


def now_iso() -> str:
    """Local timestamp, ISO-8601, seconds resolution."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def timestamp_slug() -> str:
    """Filename-safe timestamp, e.g. 20260803-142530."""
    return datetime.now().strftime("%Y%m%d-%H%M%S")


# --------------------------------------------------------------------------
# Filesystem / IO
# --------------------------------------------------------------------------


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write_json(path: Path, data: Any) -> Path:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, default=str)
        handle.write("\n")
    ok(f"wrote {rel(path)}")
    return path


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_csv(path: Path, rows: Iterable[dict], fieldnames: Sequence[str]) -> Path:
    ensure_dir(path.parent)
    rows = list(rows)
    # newline="" is required or csv writes \r\r\n on Windows.
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    ok(f"wrote {rel(path)} ({len(rows)} rows)")
    return path


def read_csv(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def rel(path: Path) -> str:
    """Path relative to the repo root when possible - keeps output readable."""
    try:
        root = Path(__file__).resolve().parent.parent
        return str(Path(path).resolve().relative_to(root))
    except (ValueError, OSError):
        return str(path)


def require_file(path: Path, produced_by: str) -> Path:
    """Fail with a useful message instead of a traceback when input is missing."""
    if not Path(path).exists():
        die(
            f"missing input: {rel(Path(path))}\n"
            f"    This file is produced by {produced_by}. Run that first, or "
            f"copy the file over from the laptop that produced it."
        )
    return Path(path)


# --------------------------------------------------------------------------
# Process / tooling
# --------------------------------------------------------------------------


def find_tool(name: str, configured: str | None = None) -> str | None:
    """Resolve an external tool: configured path first, then PATH, then the
    usual Windows install locations."""
    if configured and Path(configured).exists():
        return str(configured)
    found = shutil.which(name)
    if found:
        return found
    candidates = {
        "nmap": [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"],
        "tshark": [r"C:\Program Files\Wireshark\tshark.exe",
                   r"C:\Program Files (x86)\Wireshark\tshark.exe"],
        "smac": [r"C:\Program Files\SMAC\smac.exe",
                 r"C:\Program Files (x86)\SMAC\smac.exe"],
    }
    for candidate in candidates.get(name.lower(), []):
        if Path(candidate).exists():
            return candidate
    return None


def require_tool(name: str, configured: str | None, install_hint: str) -> str:
    path = find_tool(name, configured)
    if not path:
        die(f"{name} not found on this laptop.\n    {install_hint}")
    return path


def run(cmd: Sequence[str], timeout: int = 120, check: bool = False,
        quiet: bool = True) -> subprocess.CompletedProcess:
    """Run a command and capture its output. Never raises on non-zero unless
    check=True - callers usually want to inspect stderr themselves."""
    if not quiet:
        info("$ " + " ".join(str(c) for c in cmd))
    try:
        result = subprocess.run(
            [str(c) for c in cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired:
        raise
    if check and result.returncode != 0:
        die(f"command failed ({result.returncode}): {' '.join(str(c) for c in cmd)}\n"
            f"    {result.stderr.strip()}")
    return result


def is_admin() -> bool:
    """True if the current process is elevated (Administrator)."""
    if os.name != "nt":
        return hasattr(os, "geteuid") and os.geteuid() == 0  # type: ignore[attr-defined]
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def require_admin(reason: str) -> None:
    if not is_admin():
        die(f"this needs an Administrator shell: {reason}\n"
            f"    Close this window, right-click PowerShell -> "
            f"'Run as administrator', and re-run.")


# --------------------------------------------------------------------------
# Small formatting helpers shared by the reporting layer
# --------------------------------------------------------------------------


def normalise_mac(mac: str | None) -> str | None:
    """Upper-case, dash-separated MAC so getmac/ipconfig/Nmap output compares."""
    if not mac:
        return None
    cleaned = "".join(ch for ch in str(mac) if ch.isalnum()).upper()
    if len(cleaned) != 12:
        return str(mac).strip().upper()
    return "-".join(cleaned[i:i + 2] for i in range(0, 12, 2))


def human_bytes(count: float | int | None) -> str:
    if not count:
        return "0 B"
    size = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def truncate(text: Any, length: int = 80) -> str:
    text = "" if text is None else str(text)
    return text if len(text) <= length else text[: length - 3] + "..."
