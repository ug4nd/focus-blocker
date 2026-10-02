"""Focus blocker: closes blacklisted processes during work blocks from plan.json."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, time as dtime
from pathlib import Path

import psutil

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

# Never terminated, even if someone puts them into the blacklist by mistake.
PROTECTED = frozenset(
    name.lower()
    for name in (
        "system", "system idle process", "registry", "smss.exe", "csrss.exe",
        "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
        "explorer.exe", "dwm.exe", "fontdrvhost.exe", "taskmgr.exe",
        "powershell.exe", "pwsh.exe", "cmd.exe", "conhost.exe",
        "windowsterminal.exe", "code.exe",
    )
)

TERMINATE_TIMEOUT = 3.0

log = logging.getLogger("blocker")


@dataclass(frozen=True)
class Block:
    days: frozenset[int]  # 0 = Monday
    start: dtime
    end: dtime


@dataclass(frozen=True)
class Plan:
    interval: float
    dry_run: bool
    blocks: tuple[Block, ...]
    blacklist: frozenset[str]
    whitelist: frozenset[str]


def _parse_time(value: object, where: str) -> dtime:
    try:
        return datetime.strptime(str(value), "%H:%M").time()
    except ValueError:
        raise ValueError(f"{where}: invalid time {value!r}, expected HH:MM") from None


def _parse_names(data: dict, key: str) -> frozenset[str]:
    items = data.get(key, [])
    if not isinstance(items, list) or not all(isinstance(x, str) and x.strip() for x in items):
        raise ValueError(f"'{key}' must be a list of non-empty strings")
    return frozenset(x.strip().lower() for x in items)


def load_plan(path: Path) -> Plan:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ValueError(f"config not found: {path}") from None
    except json.JSONDecodeError as e:
        raise ValueError(f"{path}: invalid JSON: {e}") from None
    if not isinstance(data, dict):
        raise ValueError("config root must be an object")

    interval = data.get("check_interval_seconds", 5)
    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or interval <= 0:
        raise ValueError("'check_interval_seconds' must be a positive number")

    dry_run = data.get("dry_run", True)
    if not isinstance(dry_run, bool):
        raise ValueError("'dry_run' must be true or false")

    raw_blocks = data.get("work_blocks", [])
    if not isinstance(raw_blocks, list):
        raise ValueError("'work_blocks' must be a list")
    blocks: list[Block] = []
    for i, b in enumerate(raw_blocks):
        where = f"work_blocks[{i}]"
        if not isinstance(b, dict):
            raise ValueError(f"{where}: must be an object")
        days_raw = b.get("days")
        if not isinstance(days_raw, list) or not days_raw:
            raise ValueError(f"{where}: 'days' must be a non-empty list")
        days = set()
        for d in days_raw:
            if not isinstance(d, str) or d.lower() not in DAYS:
                raise ValueError(f"{where}: unknown day {d!r}, expected one of {DAYS}")
            days.add(DAYS.index(d.lower()))
        start = _parse_time(b.get("start"), f"{where}.start")
        end = _parse_time(b.get("end"), f"{where}.end")
        if start == end:
            raise ValueError(f"{where}: start and end must differ")
        blocks.append(Block(frozenset(days), start, end))

    blacklist = _parse_names(data, "blacklist")
    whitelist = _parse_names(data, "whitelist")

    overlap = blacklist & whitelist
    if overlap:
        log.warning("in both blacklist and whitelist (whitelist wins): %s", ", ".join(sorted(overlap)))
    risky = blacklist & PROTECTED
    if risky:
        log.warning("protected system processes in blacklist (will be ignored): %s", ", ".join(sorted(risky)))

    return Plan(float(interval), dry_run, tuple(blocks), blacklist, whitelist)


def is_work_time(plan: Plan, now: datetime) -> bool:
    """True if `now` falls into any work block. A block with start > end crosses midnight
    and belongs to the day it starts on."""
    t = now.time()
    today = now.weekday()
    yesterday = (today - 1) % 7
    for b in plan.blocks:
        if b.start < b.end:
            if today in b.days and b.start <= t < b.end:
                return True
        else:
            if today in b.days and t >= b.start:
                return True
            if yesterday in b.days and t < b.end:
                return True
    return False


def should_kill(plan: Plan, name: str) -> bool:
    n = name.lower()
    if n in plan.whitelist or n in PROTECTED:
        return False
    return n in plan.blacklist


def close_process(proc: psutil.Process, name: str, dry_run: bool) -> None:
    if dry_run:
        log.info("[dry-run] would close %s (pid %d)", name, proc.pid)
        return
    try:
        proc.terminate()
        try:
            proc.wait(TERMINATE_TIMEOUT)
            log.info("closed %s (pid %d)", name, proc.pid)
        except psutil.TimeoutExpired:
            proc.kill()
            log.info("killed %s (pid %d) after timeout", name, proc.pid)
    except psutil.NoSuchProcess:
        pass  # already gone
    except psutil.AccessDenied:
        log.warning("access denied for %s (pid %d), try running as administrator", name, proc.pid)
    except psutil.Error as e:
        log.warning("failed to close %s (pid %d): %s", name, proc.pid, e)


def sweep(plan: Plan) -> int:
    own_pid = os.getpid()
    count = 0
    for proc in psutil.process_iter(["pid", "name"]):
        name = proc.info.get("name")
        if not name or proc.info["pid"] == own_pid:
            continue
        if should_kill(plan, name):
            close_process(proc, name, plan.dry_run)
            count += 1
    return count


def run(plan: Plan, once: bool) -> None:
    if plan.dry_run:
        log.info("DRY RUN: processes will only be reported, not closed")
    if not plan.blocks:
        log.warning("no work blocks defined, nothing will ever be blocked")
    was_working = False
    while True:
        working = is_work_time(plan, datetime.now())
        if working != was_working:
            log.info("work block started" if working else "work block ended")
            was_working = working
        if working:
            sweep(plan)
        elif once:
            log.info("not in a work block, nothing to do")
        if once:
            return
        time.sleep(plan.interval)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("plan.json"))
    parser.add_argument("--once", action="store_true", help="single check instead of a loop")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(Path(__file__).with_name("blocker.log"), encoding="utf-8"),
        ],
    )

    try:
        plan = load_plan(args.config)
    except ValueError as e:
        log.error("%s", e)
        return 1

    try:
        run(plan, args.once)
    except KeyboardInterrupt:
        log.info("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
