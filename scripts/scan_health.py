#!/usr/bin/env python3
"""Read-only Linux server health scanner for OpenClaw-hosted execution.

Produces bounded JSON suitable for a language model to summarize. The script
never uses sudo or modifies services, target files, firewall rules, or system
configuration. It writes only the report (via a private temporary file) and
terminates only its own timed-out collectors, never inspected processes.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import math
import os
import platform
import re
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = "1.3"
MAX_CMD_CHARS = 120_000


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def run_cmd(cmd: List[str], timeout: float = 4.0, max_chars: int = MAX_CMD_CHARS) -> Dict[str, Any]:
    if not cmd or shutil.which(cmd[0]) is None:
        return {"available": False, "ok": False, "returncode": None, "stdout": "", "stderr": "command not available"}
    # Drain both pipes while retaining bounded buffers, including on timeout.
    # Slicing subprocess.run's output afterwards would not bound memory use.
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": max_chars, "stderr": 20_000}
    truncated = {"stdout": False, "stderr": False}
    p = None
    timed_out = False
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True,
                             env={**os.environ, "LC_ALL": "C", "LANG": "C", "SYSTEMD_COLORS": "0"})
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout, selectors.EVENT_READ, "stdout")
            selector.register(p.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    name = key.data
                    room = limits[name] - len(buffers[name])
                    buffers[name].extend(chunk[:room])
                    truncated[name] |= len(chunk) > room
        if not timed_out:
            try:
                p.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
        if timed_out:
            # Only stop this scanner's own timed-out collector process group.
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
        out = buffers["stdout"].decode("utf-8", errors="replace")
        err = buffers["stderr"].decode("utf-8", errors="replace")
        return {
            "available": True,
            "ok": p.returncode == 0 and not timed_out,
            "returncode": None if timed_out else p.returncode,
            "stdout": out,
            "stderr": (err + "\ncommand timed out").strip() if timed_out else err,
            "truncated": truncated["stdout"],
            "stderr_truncated": truncated["stderr"],
            "timed_out": timed_out,
        }
    except OSError as e:
        return {"available": True, "ok": False, "returncode": None, "stdout": "", "stderr": str(e)}
    finally:
        if p is not None:
            if p.poll() is None:
                p.kill()
                p.wait()
            for pipe in (p.stdout, p.stderr):
                if pipe:
                    pipe.close()


def redact(text: str) -> str:
    """Best-effort redaction for common credential shapes in log excerpts."""
    text = re.sub(r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|$)", "<redacted private key>", text)
    text = re.sub(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+", r"\1 <redacted>", text)
    text = re.sub(
        r"(?i)(?<!\w)([\"']?(?:[a-z0-9]+[_-])*(?:password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie)[\"']?)"
        r"(\s*[:=]\s*)(\"(?:\\.|[^\"\\])*\"?|'(?:\\.|[^'\\])*'?|[^\s,;]+)",
        lambda m: m.group(1) + m.group(2) + (
            m.group(3)[0] + "<redacted>" + m.group(3)[0]
            if m.group(3)[0] in "\"'" else "<redacted>"
        ),
        text,
    )
    text = re.sub(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/@:\s]+):([^/@\s]+)@", r"\1<redacted>:<redacted>@", text)
    return text


def command_status(result: Dict[str, Any]) -> Dict[str, Any]:
    """Retain collection failures and bounds without copying raw stdout."""
    status = {key: result.get(key) for key in ("available", "ok", "returncode")}
    for key in ("timed_out", "truncated", "stderr_truncated"):
        if result.get(key):
            status[key] = True
    if result.get("stderr"):
        status["error"] = redact(result["stderr"])[:1000]
    return status


def parse_proc_stat_cpu() -> Optional[Tuple[int, int]]:
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            line = f.readline().strip()
        parts = line.split()
        if not parts or parts[0] != "cpu":
            return None
        vals = [int(x) for x in parts[1:]]
        # guest and guest_nice (fields 9/10) are already in user and nice.
        total = sum(vals[:8])
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        return total, idle
    except Exception:
        return None


def cpu_usage(sample_seconds: float) -> Optional[float]:
    first = parse_proc_stat_cpu()
    if first is None:
        return None
    time.sleep(max(0.1, min(sample_seconds, 2.0)))
    second = parse_proc_stat_cpu()
    if second is None:
        return None
    total_delta = second[0] - first[0]
    idle_delta = second[1] - first[1]
    if total_delta <= 0 or not 0 <= idle_delta <= total_delta:
        return None
    return round(100.0 * (1.0 - idle_delta / total_delta), 1)


def read_meminfo() -> Dict[str, int]:
    data: Dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                key, rest = line.split(":", 1)
                value = rest.strip().split()[0]
                data[key] = int(value) * 1024
    except Exception:
        pass
    return data


def memory_metrics(mem: Dict[str, int]) -> Dict[str, Any]:
    total = mem.get("MemTotal")
    available = mem.get("MemAvailable")
    used = total - available if total and available is not None and 0 <= available <= total else None
    swap_total, swap_free = mem.get("SwapTotal"), mem.get("SwapFree")
    swap_used = swap_total - swap_free if swap_total is not None and swap_free is not None and 0 <= swap_free <= swap_total else None
    out = {"total_bytes": total, "available_bytes": available, "used_bytes": used,
            "used_percent": pct(used, total) if used is not None else None,
            "swap_total_bytes": swap_total, "swap_used_bytes": swap_used,
            "swap_used_percent": pct(swap_used, swap_total) if swap_total and swap_used is not None else None}
    if swap_total is None or (swap_total > 0 and swap_used is None):
        out["coverage_note"] = "Swap accounting is unavailable; this does not establish that no swap is configured"
    return out


def pct(used: float, total: float) -> Optional[float]:
    if total <= 0:
        return None
    return round(used * 100.0 / total, 1)


def human_uptime(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def get_uptime() -> Dict[str, Any]:
    try:
        seconds = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
        boot = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=seconds)
        return {"seconds": int(seconds), "human": human_uptime(seconds), "boot_time_utc": boot.isoformat(timespec="seconds")}
    except Exception as e:
        return {"error": str(e)}


def parse_df(mode: str, command_results: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    cmd = ["df", "-Pk"] if mode == "space" else ["df", "-Pi"]
    for fs_type in ("tmpfs", "devtmpfs", "squashfs"):
        cmd.extend(["-x", fs_type])
    res = run_cmd(cmd, timeout=5.0)
    if command_results is not None:
        command_results[mode] = command_status(res)
    if not res["ok"]:
        return []
    rows: List[Dict[str, Any]] = []
    parse_errors = 0
    lines = res["stdout"].splitlines()
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split(None, 5)
        if len(parts) != 6:
            parse_errors += 1
            continue
        filesystem, total, used, avail, use_pct, mount = parts
        if mode == "inode" and total == "0" and use_pct == "-":
            rows.append({"filesystem": filesystem, "mount": mount, "used_percent": None,
                         "inode_applicable": False, "inodes_total": 0})
            continue
        try:
            percentage = float(use_pct.rstrip("%"))
            if not math.isfinite(percentage) or percentage < 0:
                raise ValueError("invalid utilization")
        except ValueError:
            parse_errors += 1
            continue
        row = {"filesystem": filesystem, "mount": mount, "used_percent": percentage}
        if mode == "space":
            try:
                row.update({"total_bytes": int(total) * 1024, "used_bytes": int(used) * 1024, "available_bytes": int(avail) * 1024})
            except ValueError:
                parse_errors += 1
        else:
            try:
                row.update({"inodes_total": int(total), "inodes_used": int(used), "inodes_free": int(avail)})
            except ValueError:
                parse_errors += 1
        rows.append(row)
    if command_results is not None and parse_errors:
        command_results[mode]["parse_errors"] = parse_errors
    return rows


def merge_disk_rows(command_results: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    space = parse_df("space", command_results)
    inode = parse_df("inode", command_results)
    inode_map = {(r.get("filesystem"), r.get("mount")): r for r in inode}
    result: List[Dict[str, Any]] = []
    for row in space:
        key = (row.get("filesystem"), row.get("mount"))
        i = inode_map.get(key, {})
        merged = dict(row)
        if i:
            merged["inode_used_percent"] = i.get("used_percent")
            merged["inode_applicable"] = i.get("inode_applicable", True)
            for k in ("inodes_total", "inodes_used", "inodes_free"):
                if k in i:
                    merged[k] = i[k]
        result.append(merged)
    return result


def process_state() -> Dict[str, Any]:
    total = 0
    zombies: List[Dict[str, Any]] = []
    proc = Path("/proc")
    unreadable = 0
    readable = 0
    try:
        children = list(proc.iterdir())
    except OSError:
        children = []
    if children:
        for child in children:
            if not child.name.isdigit():
                continue
            total += 1
            try:
                stat = (child / "stat").read_text(encoding="utf-8", errors="replace")
                right = stat.rsplit(") ", 1)[1]
                state = right.split()[0]
                readable += 1
                if state == "Z":
                    comm = (child / "comm").read_text(encoding="utf-8", errors="replace").strip()[:120]
                    zombies.append({"pid": int(child.name), "ppid": int(right.split()[1]), "comm": comm})
            except FileNotFoundError:
                # A process exiting during enumeration is normal.
                continue
            except (OSError, ValueError, IndexError):
                unreadable += 1
                continue
    commands: Dict[str, Any] = {}
    top_cpu = top_processes("-%cpu", command_results=commands)
    top_mem = top_processes("-%mem", command_results=commands)
    out = {"count": total if readable else None, "zombie_count": len(zombies) if readable else None, "zombies": zombies[:20], "top_cpu": top_cpu, "top_memory": top_mem, "commands": commands, "readable_processes": readable, "unreadable_processes": unreadable}
    if not readable or unreadable:
        out["coverage_note"] = "Process state coverage is incomplete; counts describe only readable processes"
    return out


def top_processes(sort_key: str, limit: int = 10, command_results: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    res = run_cmd(["ps", "-eo", "pid,user,stat,%cpu,%mem,comm", f"--sort={sort_key}"], timeout=4.0)
    if command_results is not None:
        command_results["top_cpu" if sort_key == "-%cpu" else "top_memory"] = command_status(res)
    if not res["ok"]:
        return []
    rows = []
    for line in res["stdout"].splitlines()[1 : limit + 1]:
        parts = line.split(None, 5)
        if len(parts) != 6:
            continue
        pid, user, stat, cpu, mem, comm = parts
        try:
            rows.append({"pid": int(pid), "user": user, "state": stat, "cpu_percent": float(cpu), "memory_percent": float(mem), "command": comm})
        except ValueError:
            continue
    return rows


def get_services(scope: str = "system") -> Dict[str, Any]:
    systemctl_available = shutil.which("systemctl") is not None
    runtime = Path(os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"))
    manager_available = os.path.isdir("/run/systemd/system") if scope == "system" else (runtime / "systemd/private").exists()
    prefix = ["systemctl"] + (["--user"] if scope == "user" else [])
    out: Dict[str, Any] = {"scope": scope, "systemctl_available": systemctl_available, "systemd_manager_available": manager_available, "failed_units": [], "failed_count": None, "openclaw_units": [], "commands": {}}
    if scope == "system":
        out["user"] = get_services("user")
    if not systemctl_available or not manager_available:
        out["system_state"] = None
        out["coverage_note"] = f"{scope} systemd manager or systemctl is not visible in this execution namespace"
        return out
    state = run_cmd(prefix + ["is-system-running", "--no-pager"], timeout=4.0)
    out["commands"]["system_state"] = command_status(state)
    out["system_state"] = state["stdout"].strip() or None
    out["system_state_ok"] = state["ok"]
    failed = run_cmd(prefix + ["--failed", "--no-pager", "--no-legend", "--plain"], timeout=5.0)
    out["commands"]["failed_units"] = command_status(failed)
    failed_units = []
    if failed["ok"]:
        for line in failed["stdout"].splitlines():
            if not line.strip():
                continue
            parts = line.split(None, 4)
            failed_units.append({"unit": parts[0] if len(parts) > 0 else line.strip(), "load": parts[1] if len(parts) > 1 else None, "active": parts[2] if len(parts) > 2 else None, "sub": parts[3] if len(parts) > 3 else None, "description": parts[4] if len(parts) > 4 else None})
    out["failed_units"] = failed_units[:50]
    out["failed_count"] = len(failed_units) if failed["ok"] else None
    all_services = run_cmd(prefix + ["list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain"], timeout=6.0)
    out["commands"]["service_list"] = command_status(all_services)
    openclaw = []
    if all_services["ok"]:
        for line in all_services["stdout"].splitlines():
            if "openclaw" in line.lower():
                openclaw.append(line.strip()[:500])
    out["openclaw_units"] = openclaw[:20]
    return out


def summarize_listeners(lines: List[str]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    non_loopback = set()
    for line in lines:
        parts = line.split()
        if len(parts) < 6 or ":" not in parts[4]:
            counts["unparsed"] = counts.get("unparsed", 0) + 1
            continue
        address, port = parts[4].rsplit(":", 1)
        address = address.strip("[]")
        try:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
            # IPv4-mapped IPv6 loopback must not be labelled externally bound.
            ip = getattr(ip, "ipv4_mapped", None) or ip
            scope = "wildcard" if ip.is_unspecified else "loopback" if ip.is_loopback else "interface"
        except ValueError:
            scope = "wildcard" if address == "*" else "unknown"
        counts[scope] = counts.get(scope, 0) + 1
        if scope != "loopback":
            non_loopback.add((parts[0], address, port))
    return {"counts_by_bind_scope": counts,
            "non_loopback_bindings": [{"protocol": p, "address": a, "port": port} for p, a, port in sorted(non_loopback)],
            "reachability": "not_tested; local bindings do not establish public reachability or firewall policy"}


def get_network(ping_gateway: bool, max_ports: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {"commands": {}}
    addr = run_cmd(["ip", "-brief", "address"], timeout=4.0)
    out["commands"]["interfaces"] = command_status(addr)
    out["interfaces"] = [redact(x)[:500] for x in addr["stdout"].splitlines()[:100]] if addr["available"] else []
    route = run_cmd(["ip", "route", "show", "default"], timeout=4.0)
    out["commands"]["default_routes"] = command_status(route)
    defaults = route["stdout"].splitlines()[:20] if route["available"] else []
    out["default_routes"] = [x[:500] for x in defaults]
    nameservers: List[str] = []
    try:
        for line in Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                nameservers.append(parts[1])
    except Exception as e:
        out["dns_coverage_note"] = redact(str(e))[:1000]
    out["dns_nameservers"] = nameservers[:10]
    ss = run_cmd(["ss", "-lntupH"], timeout=5.0, max_chars=80_000)
    out["commands"]["listening_ports"] = command_status(ss)
    listen = [redact(x)[:700] for x in ss["stdout"].splitlines() if x.strip()] if ss["available"] else []
    out["listening_ports"] = listen[:max_ports]
    out["listening_ports_total_observed"] = len(listen) if ss["ok"] else None
    out["listening_ports_truncated"] = len(listen) > max_ports or bool(ss.get("truncated"))
    out["listener_summary"] = summarize_listeners(listen[:max_ports]) if ss["ok"] else None
    gateway = None
    for line in defaults:
        m = re.search(r"\bvia\s+(\S+)", line)
        if m:
            gateway = m.group(1)
            break
    out["default_gateway"] = gateway
    if ping_gateway and gateway:
        ping = run_cmd(["ping", "-c", "1", "-W", "1", gateway], timeout=3.0, max_chars=10_000)
        out["gateway_ping"] = {"attempted": ping["available"], "ok": ping["ok"], "detail": redact(ping["stdout"] or ping["stderr"])[:1000]}
        out["commands"]["gateway_ping"] = command_status(ping)
    else:
        out["gateway_ping"] = {"attempted": False, "ok": None}
        if ping_gateway:
            out["gateway_ping"]["coverage_note"] = "No default gateway was identified; the requested ICMP check was not performed"
    return out


def get_journal(since: str, max_lines: int) -> Dict[str, Any]:
    # JSON counts journal records, not physical lines in multiline messages.
    # The extra record distinguishes an exactly full sample from truncation.
    res = run_cmd(["journalctl", "-p", "0..3", "--since", since, "--no-pager", "--quiet",
                   "--output=json", "--output-fields=__REALTIME_TIMESTAMP,PRIORITY,_SYSTEMD_UNIT,_SYSTEMD_USER_UNIT,SYSLOG_IDENTIFIER,MESSAGE",
                   "-n", str(max_lines + 1)], timeout=7.0, max_chars=100_000)
    records = []
    parse_errors = 0
    for line in res["stdout"].splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            if not isinstance(record, dict) or "MESSAGE" not in record:
                raise ValueError("not a journal entry")
            records.append(record)
        except (ValueError, TypeError):
            parse_errors += 1
    limited_access = any(s in res["stderr"].lower() for s in ("no journal files", "permission denied", "not seeing messages", "insufficient permissions"))
    complete = res["ok"] and not limited_access and not parse_errors and not res.get("truncated")
    observed = len(records)
    records = records[-max_lines:]
    groups: Dict[str, int] = {}
    priorities: Dict[str, int] = {}
    entries = []
    for record in records:
        unit = str(record.get("_SYSTEMD_USER_UNIT") or record.get("_SYSTEMD_UNIT") or record.get("SYSLOG_IDENTIFIER") or "unknown")
        priority = str(record.get("PRIORITY", "unknown"))
        groups[unit] = groups.get(unit, 0) + 1
        priorities[priority] = priorities.get(priority, 0) + 1
        message = record["MESSAGE"]
        if not isinstance(message, str):
            message = "<non-text journal message omitted>"
        entries.append(redact(f"{record.get('__REALTIME_TIMESTAMP', '?')} {unit} priority={priority}: {message}")[:1000])
    truncated = observed > max_lines or bool(res.get("truncated"))
    out = {"available": res["available"], "ok": res["ok"], "since": since, "priority_range": "0..3 (emerg..err)",
           "entries": entries, "observed_count": observed if complete or observed else None,
           "sample_count": len(records), "sample_by_unit": groups, "sample_by_priority": priorities,
           "count_is_lower_bound": truncated or not complete,
           "truncated_at": max_lines if truncated else None, "parse_errors": parse_errors,
           "command": command_status(res), "coverage_complete": complete,
           "error": redact(res["stderr"])[:1000] if res["stderr"] else None}
    if not complete:
        out["coverage_note"] = "Journal collection is unavailable, restricted, or incomplete; absence of errors is not established"
    return out


def add_finding(findings: List[Dict[str, Any]], severity: str, category: str, title: str, detail: str, evidence: Dict[str, Any]) -> None:
    findings.append({"severity": severity, "category": category, "title": title, "detail": detail, "evidence": evidence})


def classify(data: Dict[str, Any], args: argparse.Namespace) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    cpu = data["metrics"]["cpu"]
    usage = cpu.get("usage_percent")
    if usage is None:
        add_finding(findings, "warning", "coverage", "CPU utilization is unavailable", "The scanner could not obtain a CPU utilization sample.", {"metric": "cpu.usage_percent"})
    else:
        if usage >= args.cpu_critical:
            add_finding(findings, "critical", "cpu", "CPU utilization is critical", f"CPU usage is {usage:.1f}%.", {"usage_percent": usage, "threshold": args.cpu_critical})
        elif usage >= args.cpu_warning:
            add_finding(findings, "warning", "cpu", "CPU utilization is high", f"CPU usage is {usage:.1f}%.", {"usage_percent": usage, "threshold": args.cpu_warning})
    load1 = cpu.get("load_1m")
    cpu_count = cpu.get("logical_cpus") or 1
    if load1 is None:
        add_finding(findings, "warning", "coverage", "Load averages are unavailable", "The scanner could not obtain the system load averages.", {"metric": "cpu.load_1m"})
    elif cpu_count:
        ratio = load1 / cpu_count
        if ratio >= args.load_critical_per_cpu:
            add_finding(findings, "critical", "cpu", "Load average is critical", f"1-minute load per logical CPU is {ratio:.2f}.", {"load_1m": load1, "logical_cpus": cpu_count, "ratio": round(ratio, 2)})
        elif ratio >= args.load_warning_per_cpu:
            add_finding(findings, "warning", "cpu", "Load average is elevated", f"1-minute load per logical CPU is {ratio:.2f}.", {"load_1m": load1, "logical_cpus": cpu_count, "ratio": round(ratio, 2)})
    mem = data["metrics"]["memory"]
    mem_pct = mem.get("used_percent")
    if mem_pct is None:
        add_finding(findings, "warning", "coverage", "Memory utilization is unavailable", "The scanner could not determine total and available memory.", {"metric": "memory.used_percent"})
    else:
        if mem_pct >= args.mem_critical:
            add_finding(findings, "critical", "memory", "Memory pressure is critical", f"Memory used is {mem_pct:.1f}%.", {"used_percent": mem_pct, "threshold": args.mem_critical})
        elif mem_pct >= args.mem_warning:
            add_finding(findings, "warning", "memory", "Memory usage is high", f"Memory used is {mem_pct:.1f}%.", {"used_percent": mem_pct, "threshold": args.mem_warning})
    swap_pct = mem.get("swap_used_percent")
    if swap_pct is not None and mem.get("swap_total_bytes", 0) > 0:
        if swap_pct >= args.swap_critical:
            add_finding(findings, "critical", "memory", "Swap usage is critical", f"Swap used is {swap_pct:.1f}%.", {"swap_used_percent": swap_pct, "threshold": args.swap_critical})
        elif swap_pct >= args.swap_warning:
            add_finding(findings, "warning", "memory", "Swap usage is high", f"Swap used is {swap_pct:.1f}%.", {"swap_used_percent": swap_pct, "threshold": args.swap_warning})
    disks = data["metrics"]["disks"]
    if not disks:
        add_finding(findings, "warning", "coverage", "Filesystem utilization is unavailable", "The scanner could not obtain filesystem space or inode metrics.", {"metric": "disks"})
    else:
        missing_inode_mounts = [disk.get("mount") for disk in disks if disk.get("inode_used_percent") is None and disk.get("inode_applicable") is not False]
        if missing_inode_mounts:
            add_finding(findings, "warning", "coverage", "Inode utilization is incomplete", "Filesystem space was collected, but inode utilization is missing for one or more observed mounts.", {"metric": "disks.inode_used_percent", "mounts": missing_inode_mounts})
        incomplete_commands = [name for name, status in data["metrics"].get("disk_commands", {}).items() if not status.get("ok") or status.get("truncated") or status.get("parse_errors")]
        if incomplete_commands:
            add_finding(findings, "warning", "coverage", "Filesystem command coverage is incomplete", "A filesystem collection command failed or its output was truncated.", {"commands": incomplete_commands})
    for disk in disks:
        used = disk.get("used_percent")
        mount = disk.get("mount")
        if used is not None:
            if used >= args.disk_critical:
                add_finding(findings, "critical", "disk", f"Disk space critical on {mount}", f"Filesystem usage is {used:.1f}%.", {"mount": mount, "used_percent": used, "threshold": args.disk_critical})
            elif used >= args.disk_warning:
                add_finding(findings, "warning", "disk", f"Disk space high on {mount}", f"Filesystem usage is {used:.1f}%.", {"mount": mount, "used_percent": used, "threshold": args.disk_warning})
        inode = disk.get("inode_used_percent")
        if inode is not None:
            if inode >= args.inode_critical:
                add_finding(findings, "critical", "disk", f"Inode usage critical on {mount}", f"Inode usage is {inode:.1f}%.", {"mount": mount, "inode_used_percent": inode, "threshold": args.inode_critical})
            elif inode >= args.inode_warning:
                add_finding(findings, "warning", "disk", f"Inode usage high on {mount}", f"Inode usage is {inode:.1f}%.", {"mount": mount, "inode_used_percent": inode, "threshold": args.inode_warning})
    procs = data["metrics"]["processes"]
    z = procs.get("zombie_count")
    if z is None:
        add_finding(findings, "warning", "coverage", "Process state is unavailable", "The scanner could not read process states.", {"metric": "processes.zombie_count"})
    elif z >= args.zombie_critical_count:
        add_finding(findings, "critical", "process", "Many zombie processes detected", f"Detected {z} zombie processes.", {"zombie_count": z})
    elif z >= args.zombie_warning_count:
        add_finding(findings, "warning", "process", "Zombie processes detected", f"Detected {z} zombie process(es).", {"zombie_count": z})
    services = data["metrics"]["services"]
    if services.get("systemd_manager_available"):
        failed_count = services.get("failed_count") or 0
        if failed_count > 0:
            add_finding(findings, "warning", "service", "Failed systemd units detected", f"systemd reports {failed_count} failed unit(s).", {"failed_count": failed_count})
        system_state = (services.get("system_state") or "").strip().lower()
        if system_state in {"maintenance", "stopping"}:
            add_finding(findings, "critical", "service", f"Systemd state is {system_state}", "The overall systemd state is unhealthy.", {"system_state": system_state})
        elif system_state == "degraded":
            add_finding(findings, "warning", "service", "Systemd reports degraded state", "One or more units may be unhealthy.", {"system_state": system_state})
    user_services = services.get("user", {})
    if (user_services.get("failed_count") or 0) > 0:
        add_finding(findings, "warning", "service", "Failed user systemd units detected", "The current user's systemd manager reports failed units.", {"scope": "user", "failed_count": user_services["failed_count"]})
    for scope, state in (("system", services), ("user", user_services)):
        for unit in state.get("openclaw_units", []):
            parts = unit.split()
            if len(parts) >= 4 and parts[2] in {"failed", "inactive"}:
                add_finding(findings, "warning", "service", "OpenClaw unit is not active", "A loaded OpenClaw unit is inactive or failed; inspect its role before diagnosing an outage.", {"scope": scope, "unit": parts[0], "active": parts[2], "sub": parts[3]})
    journal = data["metrics"]["journal"]
    jcount = (journal.get("observed_count") or 0) if journal.get("available") else 0
    if jcount >= args.journal_warning_count:
        add_finding(findings, "warning", "log", "Recent error-level journal entries detected", f"Observed at least {jcount} error-or-higher journal entries in the requested window.", {"observed_count": jcount, "since": journal.get("since")})
    urgent = sum(journal.get("sample_by_priority", {}).get(str(p), 0) for p in range(3))
    if urgent:
        add_finding(findings, "warning", "log", "High-priority journal entries detected", "Emergency, alert, or critical log records need review even below the volume threshold; historical records alone do not prove an active outage.", {"sample_count": urgent, "since": journal.get("since")})
    if journal.get("coverage_note") and not journal.get("skipped"):
        add_finding(findings, "warning", "coverage", "Journal coverage is incomplete", journal["coverage_note"], {"since": journal.get("since"), "command": journal.get("command")})
    network = data["metrics"]["network"]
    gw_ping = network.get("gateway_ping", {})
    if gw_ping.get("attempted") and gw_ping.get("ok") is False:
        add_finding(findings, "warning", "network", "Default gateway ping failed", "A one-packet ICMP check to the default gateway did not succeed. ICMP may be blocked, so treat this as supporting evidence rather than proof of an outage.", {"gateway": network.get("default_gateway")})
    return findings


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Read-only local Linux server health scan")
    p.add_argument("--output", help="Write JSON to this file instead of stdout")
    p.add_argument("--cpu-sample-seconds", type=float, default=0.5)
    p.add_argument("--cpu-warning", type=float, default=85.0)
    p.add_argument("--cpu-critical", type=float, default=95.0)
    p.add_argument("--mem-warning", type=float, default=85.0)
    p.add_argument("--mem-critical", type=float, default=95.0)
    p.add_argument("--swap-warning", type=float, default=80.0)
    p.add_argument("--swap-critical", type=float, default=95.0)
    p.add_argument("--disk-warning", type=float, default=80.0)
    p.add_argument("--disk-critical", type=float, default=90.0)
    p.add_argument("--inode-warning", type=float, default=85.0)
    p.add_argument("--inode-critical", type=float, default=95.0)
    p.add_argument("--load-warning-per-cpu", type=float, default=1.0)
    p.add_argument("--load-critical-per-cpu", type=float, default=2.0)
    p.add_argument("--zombie-warning-count", type=int, default=1)
    p.add_argument("--zombie-critical-count", type=int, default=10)
    p.add_argument("--journal-since", default="24 hours ago", help="Journal lookback window (default: 24 hours ago)")
    p.add_argument("--journal-lines", type=int, default=100, help="Maximum retained journal records, 1..500")
    p.add_argument("--journal-warning-count", type=int, default=20)
    p.add_argument("--max-ports", type=int, default=80)
    p.add_argument("--no-journal", action="store_true")
    p.add_argument("--ping-gateway", action="store_true", help="Attempt one ICMP ping to the default gateway")
    args = p.parse_args(argv)
    for name in ("cpu", "mem", "swap", "disk", "inode"):
        warning, critical = getattr(args, f"{name}_warning"), getattr(args, f"{name}_critical")
        if not (math.isfinite(warning) and math.isfinite(critical) and 0 <= warning < critical <= 100):
            p.error(f"--{name}-warning and --{name}-critical must satisfy 0 <= warning < critical <= 100")
    if not (math.isfinite(args.load_warning_per_cpu) and math.isfinite(args.load_critical_per_cpu)
            and 0 < args.load_warning_per_cpu < args.load_critical_per_cpu):
        p.error("load thresholds must be finite and satisfy 0 < warning < critical")
    if not 1 <= args.zombie_warning_count < args.zombie_critical_count:
        p.error("zombie thresholds must satisfy 1 <= warning < critical")
    if not math.isfinite(args.cpu_sample_seconds) or not 0.1 <= args.cpu_sample_seconds <= 2:
        p.error("--cpu-sample-seconds must be between 0.1 and 2")
    if not 1 <= args.max_ports <= 500 or not 1 <= args.journal_lines <= 500:
        p.error("--max-ports and --journal-lines must be between 1 and 500")
    if args.journal_warning_count < 1 or (not args.no_journal and args.journal_warning_count > args.journal_lines):
        p.error("--journal-warning-count must be positive and no larger than --journal-lines")
    if not args.journal_since.strip():
        p.error("--journal-since must not be empty")
    return args


def collect_coverage(metrics: Dict[str, Any], findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Expose failed and bounded auxiliary collectors in one report field."""
    issues = []

    def visit(value: Any, path: str) -> None:
        if not isinstance(value, dict):
            return
        for key, item in value.items():
            if key.endswith("coverage_note"):
                issues.append({"component": path, "detail": item})
            elif key in {"commands", "disk_commands"}:
                for name, status in item.items():
                    valid_state = name == "system_state" and not status.get("timed_out") and value.get("system_state") in {"running", "degraded", "starting", "initializing", "maintenance", "stopping"}
                    if (not status.get("ok") and not valid_state) or status.get("truncated") or status.get("stderr_truncated") or status.get("parse_errors"):
                        issues.append({"component": f"{path}.{name}", "detail": "collection failed, was truncated, or contained unparsed data", "command": status})
            else:
                visit(item, f"{path}.{key}")
    visit(metrics, "metrics")
    if metrics["network"].get("listening_ports_truncated"):
        issues.append({"component": "metrics.network.listening_ports", "detail": "listener list is a bounded sample"})
    if metrics["journal"].get("truncated_at"):
        issues.append({"component": "metrics.journal", "detail": "journal count is a lower bound; retained records are a sample"})
    for finding in findings or []:
        if finding["category"] == "coverage":
            issues.append({"component": finding["evidence"].get("metric", "scan"), "detail": finding["title"]})
    return {"status": "partial" if issues else "complete", "limitations": issues}


def redact_tree(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {redact(str(k)): redact_tree(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_tree(v) for v in value]
    return value


def write_report(path: str, rendered: str) -> None:
    """Publish a complete private artifact; never follow a target symlink."""
    target = Path(path)
    if target.is_symlink() or (target.exists() and not target.is_file()):
        raise OSError("output must be a regular file, not a symlink or directory")
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(rendered + "\n")
            f.flush()
            os.fsync(f.fileno())
        # os.replace replaces the directory entry, even if a symlink appeared
        # since the check above; it does not overwrite that symlink's target.
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main() -> int:
    args = parse_args()
    started = time.monotonic()
    logical_cpus = os.cpu_count() or 1
    try:
        load1, load5, load15 = os.getloadavg()
    except (OSError, AttributeError):
        load1 = load5 = load15 = None
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = "unknown"
    disk_commands: Dict[str, Any] = {}
    data: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scan_mode": "local_read_only",
        "scanned_at_utc": utc_now_iso(),
        "host": {
            "hostname": hostname,
            "fqdn": None,
            "fqdn_note": "Reverse DNS lookup omitted to keep the scan local and bounded",
            "platform": platform.platform(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "execution_context_note": "Metrics reflect the OS namespace visible to the OpenClaw process. If OpenClaw runs in a container without host mounts/privileges, this may describe the container rather than the physical/VM host.",
        },
        "uptime": get_uptime(),
        "metrics": {
            "cpu": {"logical_cpus": logical_cpus, "usage_percent": cpu_usage(args.cpu_sample_seconds), "load_1m": round(load1, 2) if load1 is not None else None, "load_5m": round(load5, 2) if load5 is not None else None, "load_15m": round(load15, 2) if load15 is not None else None},
            "memory": memory_metrics(read_meminfo()),
            "disks": merge_disk_rows(disk_commands),
            "disk_commands": disk_commands,
            "processes": process_state(),
            "services": get_services(),
            "network": get_network(args.ping_gateway, args.max_ports),
            "journal": {"available": False, "ok": False, "skipped": True, "coverage_note": "Journal collection disabled by --no-journal", "entries": [], "observed_count": None} if args.no_journal else get_journal(args.journal_since, args.journal_lines),
        },
        "thresholds": {"cpu_warning_percent": args.cpu_warning, "cpu_critical_percent": args.cpu_critical, "memory_warning_percent": args.mem_warning, "memory_critical_percent": args.mem_critical, "swap_warning_percent": args.swap_warning, "swap_critical_percent": args.swap_critical, "disk_warning_percent": args.disk_warning, "disk_critical_percent": args.disk_critical, "inode_warning_percent": args.inode_warning, "inode_critical_percent": args.inode_critical, "load_warning_per_cpu": args.load_warning_per_cpu, "load_critical_per_cpu": args.load_critical_per_cpu, "zombie_warning_count": args.zombie_warning_count, "zombie_critical_count": args.zombie_critical_count, "journal_warning_count": args.journal_warning_count},
    }
    findings = classify(data, args)
    data["findings"] = findings
    critical = sum(1 for f in findings if f["severity"] == "critical")
    warning = sum(1 for f in findings if f["severity"] == "warning")
    data["coverage"] = collect_coverage(data["metrics"], findings)
    data["summary"] = {"overall_status": "Critical" if critical else ("Warning" if warning else "Healthy"), "critical_findings": critical, "warning_findings": warning, "finding_count": len(findings), "coverage_status": data["coverage"]["status"]}
    data["completed_at_utc"] = utc_now_iso()
    data["duration_seconds"] = round(time.monotonic() - started, 3)
    rendered = json.dumps(redact_tree(data), ensure_ascii=False, indent=2, allow_nan=False)
    if args.output:
        try:
            write_report(args.output, rendered)
        except OSError as e:
            print(f"Could not publish report: {redact(str(e))}", file=sys.stderr)
            return 1
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
