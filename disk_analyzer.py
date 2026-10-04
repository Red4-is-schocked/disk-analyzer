#!/usr/bin/env python3
"""
diskview - enhanced disk usage analyzer

Shows:
  * Disk / partition overview with usage bars
  * Directory breakdown with percentage bars, file counts, last-modified
  * Largest files
  * File-type (extension) breakdown

Usage:
  python3 diskview.py [path] [-n TOP] [-f FILES] [-e EXTS] [--no-disks]

Optional but recommended:  pip install rich psutil
"""

import argparse
import heapq
import os
import shutil
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

try:
    import psutil
except ImportError:  # psutil is optional
    psutil = None

console = Console()

IGNORED_FS = {
    "squashfs", "tmpfs", "devtmpfs", "overlay", "proc", "sysfs", "cgroup",
    "cgroup2", "devpts", "securityfs", "pstore", "bpf", "autofs", "tracefs",
    "debugfs", "configfs", "fusectl", "mqueue", "hugetlbfs", "efivarfs",
    "binfmt_misc", "ramfs", "nsfs",
}

def format_size(size):
    size = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def usage_color(percent):
    """Green -> yellow -> red depending on how full something is."""
    if percent < 60:
        return "green"
    if percent < 85:
        return "yellow"
    return "red"


def share_color(percent):
    """Color for 'share of directory' bars."""
    if percent >= 40:
        return "red"
    if percent >= 15:
        return "yellow"
    if percent >= 5:
        return "cyan"
    return "green"


def make_bar(percent, width=20, color=None):
    percent = max(0.0, min(100.0, percent))
    filled = int(round(width * percent / 100))
    color = color or usage_color(percent)
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * (width - filled), style="grey35")
    bar.append(f" {percent:5.1f}%", style=color)
    return bar


def fmt_time(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    except (OverflowError, OSError, ValueError):
        return "-"

def get_partitions():
    parts = []

    if psutil:
        for p in psutil.disk_partitions(all=False):
            if p.fstype.lower() in IGNORED_FS or p.device.startswith("/dev/loop"):
                continue
            try:
                u = psutil.disk_usage(p.mountpoint)
            except (PermissionError, OSError):
                continue
            parts.append((p.device, p.mountpoint, p.fstype, u.total, u.used, u.free))
    else:
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    dev, mnt, fs, *_ = line.split()
                    if fs in IGNORED_FS or not dev.startswith("/dev/") or dev.startswith("/dev/loop"):
                        continue
                    try:
                        u = shutil.disk_usage(mnt)
                    except OSError:
                        continue
                    parts.append((dev, mnt, fs, u.total, u.used, u.free))
        except OSError:
            u = shutil.disk_usage("/")
            parts.append(("-", "/", "-", u.total, u.used, u.free))

    # de-duplicate (same device mounted several times)
    seen, unique = set(), []
    for p in parts:
        if p[0] in seen:
            continue
        seen.add(p[0])
        unique.append(p)
    return unique


def show_disks(target):
    parts = get_partitions()
    if not parts:
        return

    table = Table(
        title="💽  Disks & Partitions",
        box=box.ROUNDED,
        header_style="bold magenta",
        title_style="bold",
    )
    table.add_column("Device", style="cyan")
    table.add_column("Mount", style="white")
    table.add_column("FS", style="blue")
    table.add_column("Total", justify="right")
    table.add_column("Used", justify="right", style="yellow")
    table.add_column("Free", justify="right", style="green")
    table.add_column("Usage")

    target_str = str(target)
    best = None  # mountpoint that contains the scanned path
    for p in parts:
        mnt = p[1]
        if target_str == mnt or target_str.startswith(mnt.rstrip("/") + "/"):
            if best is None or len(mnt) > len(best):
                best = mnt

    for dev, mnt, fs, total, used, free in parts:
        pct = (used / total * 100) if total else 0
        mnt_text = Text(mnt)
        if mnt == best:
            mnt_text.append("  ◀ scanned", style="bold green")
        table.add_row(
            dev, mnt_text, fs,
            format_size(total), format_size(used), format_size(free),
            make_bar(pct, width=24),
        )

    console.print(table)

    extras = []
    if psutil:
        try:
            ram = psutil.virtual_memory()
            swap = psutil.swap_memory()
            extras.append(f"[bold]RAM:[/bold] {format_size(ram.used)} / {format_size(ram.total)} ({ram.percent:.0f}%)")
            if swap.total:
                extras.append(f"[bold]Swap:[/bold] {format_size(swap.used)} / {format_size(swap.total)} ({swap.percent:.0f}%)")
        except Exception:
            pass
    if extras:
        console.print("  " + "    ".join(extras))
    console.print()

class Stats:
    def __init__(self, top_files):
        self.top_files = top_files
        self.heap = []  # (size, path)
        self.ext_size = defaultdict(int)
        self.ext_count = defaultdict(int)

    def record_file(self, path, size):
        ext = os.path.splitext(path)[1].lower() or "(none)"
        self.ext_size[ext] += size
        self.ext_count[ext] += 1
        if self.top_files:
            if len(self.heap) < self.top_files:
                heapq.heappush(self.heap, (size, path))
            elif size > self.heap[0][0]:
                heapq.heapreplace(self.heap, (size, path))


def scan(path, stats):
    """Return (size, files, dirs, newest_mtime) for a file or directory."""
    try:
        st = os.lstat(path)
    except OSError:
        return 0, 0, 0, 0

    if not os.path.isdir(path) or os.path.islink(path):
        stats.record_file(path, st.st_size)
        return st.st_size, 1, 0, st.st_mtime

    size = files = dirs = 0
    newest = st.st_mtime
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            dirs += 1
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            s = entry.stat(follow_symlinks=False)
                            size += s.st_size
                            files += 1
                            newest = max(newest, s.st_mtime)
                            stats.record_file(entry.path, s.st_size)
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError):
            continue
    return size, files, dirs, newest

def show_summary(path, entries, total_size, total_files, total_dirs):
    biggest = entries[0] if entries else None
    lines = [
        f"[bold cyan]Path:[/bold cyan]        {path}",
        f"[bold cyan]Total size:[/bold cyan]  [bold green]{format_size(total_size)}[/bold green]",
        f"[bold cyan]Items:[/bold cyan]       {len(entries)} top-level   |   "
        f"{total_files:,} files   |   {total_dirs:,} folders",
    ]
    if biggest and total_size:
        lines.append(
            f"[bold cyan]Largest:[/bold cyan]     {biggest['name']} "
            f"({biggest['size'] / total_size * 100:.1f}% of total)"
        )
    console.print(Panel("\n".join(lines), title="📊 Summary", border_style="cyan", box=box.ROUNDED))
    console.print()


def show_entries(path, entries, total_size, limit):
    table = Table(
        title=f"📁  Disk Usage — {path}",
        box=box.ROUNDED,
        header_style="bold magenta",
        title_style="bold",
    )
    table.add_column("#", justify="right", style="grey50")
    table.add_column("Type", style="cyan")
    table.add_column("Name", style="white", overflow="fold")
    table.add_column("Size", justify="right", style="green")
    table.add_column("Share of total")
    table.add_column("Files", justify="right", style="blue")
    table.add_column("Modified", style="grey70")

    shown = entries[:limit] if limit else entries
    for i, e in enumerate(shown, 1):
        pct = (e["size"] / total_size * 100) if total_size else 0
        table.add_row(
            str(i),
            "DIR" if e["is_dir"] else "FILE",
            e["name"],
            format_size(e["size"]),
            make_bar(pct, width=22, color=share_color(pct)),
            f"{e['files']:,}",
            fmt_time(e["mtime"]),
        )

    hidden = len(entries) - len(shown)
    if hidden > 0:
        rest = sum(e["size"] for e in entries[limit:])
        pct = (rest / total_size * 100) if total_size else 0
        table.add_section()
        table.add_row("", "", f"[italic]… {hidden} more items[/italic]",
                      format_size(rest), make_bar(pct, 22, "grey50"), "", "")

    console.print(table)
    console.print()


def show_top_files(stats):
    if not stats.heap:
        return
    table = Table(title="🏆  Largest Files", box=box.ROUNDED,
                  header_style="bold magenta", title_style="bold")
    table.add_column("#", justify="right", style="grey50")
    table.add_column("Size", justify="right", style="green")
    table.add_column("Path", style="white", overflow="fold")

    for i, (size, p) in enumerate(sorted(stats.heap, reverse=True), 1):
        table.add_row(str(i), format_size(size), p)
    console.print(table)
    console.print()


def show_extensions(stats, total_size, limit):
    if not stats.ext_size or not limit:
        return
    table = Table(title="🧩  File Types", box=box.ROUNDED,
                  header_style="bold magenta", title_style="bold")
    table.add_column("Extension", style="cyan")
    table.add_column("Files", justify="right", style="blue")
    table.add_column("Size", justify="right", style="green")
    table.add_column("Share of total")

    ranked = sorted(stats.ext_size.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    for ext, size in ranked:
        pct = (size / total_size * 100) if total_size else 0
        table.add_row(ext, f"{stats.ext_count[ext]:,}", format_size(size),
                      make_bar(pct, width=22, color=share_color(pct)))
    console.print(table)
    console.print()

DANCE_FRAMES = [
    "\\o/\n | \n/ \\",
    " o/\n/| \n/ \\",
    "\\o \n |\\\n/ \\",
    "_o_\n | \n/ \\",
    " o \n/|\\\n < ",
    " o \n/|\\\n > ",
]


def render_credit(i):
    frame = DANCE_FRAMES[i % len(DANCE_FRAMES)]
    colors = ["cyan", "magenta", "green", "yellow", "red", "blue"]
    return Group(
        Align.center(Text(frame, style=f"bold {colors[i % len(colors)]}")),
        Align.center(Text("CREATED BY RED4", style="bold magenta")),
    )


def show_credit():
    if not console.is_terminal:
        console.print(render_credit(0))
        return
    with Live(render_credit(0), console=console, refresh_per_second=10) as live:
        for i in range(30):
            live.update(render_credit(i))
            time.sleep(0.15)
    console.print()

def analyze_directory(directory, args):
    path = Path(directory).expanduser().resolve()

    if not path.exists():
        console.print("[red]Error:[/red] Path does not exist.")
        return 1
    if not path.is_dir():
        console.print("[red]Error:[/red] Not a directory.")
        return 1

    console.print()
    if not args.no_disks:
        show_disks(path)

    try:
        children = list(path.iterdir())
    except PermissionError:
        console.print("[red]Permission denied.[/red]")
        return 1

    stats = Stats(args.files)
    entries = []
    total_files = total_dirs = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Analyzing[/bold cyan] {task.fields[current]}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("scan", total=len(children), current="")
        for child in children:
            progress.update(task, current=child.name[:30].ljust(30))
            size, files, dirs, mtime = scan(str(child), stats)
            entries.append({
                "name": child.name,
                "is_dir": child.is_dir() and not child.is_symlink(),
                "size": size,
                "files": files,
                "mtime": mtime,
            })
            total_files += files
            total_dirs += dirs + (1 if entries[-1]["is_dir"] else 0)
            progress.advance(task)

    entries.sort(key=lambda e: e["size"], reverse=True)
    total_size = sum(e["size"] for e in entries)

    show_summary(path, entries, total_size, total_files, total_dirs)
    show_entries(path, entries, total_size, args.top)
    show_top_files(stats)
    show_extensions(stats, total_size, args.exts)
    show_credit()
    return 0


def main():
    parser = argparse.ArgumentParser(description="Enhanced disk usage analyzer")
    parser.add_argument("path", nargs="?", default=".", help="directory to analyze")
    parser.add_argument("-n", "--top", type=int, default=0,
                        help="only show the N largest entries (0 = all)")
    parser.add_argument("-f", "--files", type=int, default=10,
                        help="show N largest files (0 = hide)")
    parser.add_argument("-e", "--exts", type=int, default=10,
                        help="show N biggest file types (0 = hide)")
    parser.add_argument("--no-disks", action="store_true",
                        help="hide the disk/partition overview")
    args = parser.parse_args()

    try:
        sys.exit(analyze_directory(args.path, args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()