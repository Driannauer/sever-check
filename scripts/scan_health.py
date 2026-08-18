#!/usr/bin/env python3
"""Read-only Linux server health scanner for OpenClaw-hosted execution.

Produces bounded JSON suitable for a language model to summarize. The script
never uses sudo and never changes services, processes, files, firewall rules,
or system configuration.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = "1.0"
MAX_CMD_CHARS = 120_000


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def run_cmd(cmd: List[str], timeout: float = 4.0, max_chars: int = MAX_CMD_CHARS) -> Dict[str, Any]:
    if not cmd or shutil.which(cmd[0]) is None:
        return {"available": False, "ok": False, "returncode": None, "stdout": "", "stderr": "command not available"}
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        out = p.stdout[:max_chars]
        err = p.stderr[:20_000]
        return {
            "available": True,
            "ok": p.returncode == 0,
            "returncode": p.returncode,
            "stdout": out,
            "stderr": err,
            "truncated": len(p.stdout) > len(out),
        }
    except subprocess.TimeoutExpired as e:
        return {
            "available": True,
            "ok": False,
            "returncode": None,
            "stdout": (e.stdout or "")[:max_chars] if isinstance(e.stdout, str) else "",
            "stderr": "command timed out",
            "timed_out": True,
        }
    except Exception as e:  # keep scan resilient
        return {"available": True, "ok": False, "returncode": None, "stdout": "", "stderr": str(e)}


def redact(text: str) -> str:
    """Best-effort redaction for common credential shapes in log excerpts."""
    text = re.sub(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}", r"\1 <redacted>", text)
    text = re.sub(
        r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization)\b(\s*[:=]\s*)([^\s,;]+)",
        r"\1\2<redacted>",
        text,
    )
    text = re.sub(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/@:\s]+):([^/@\s]+)@", r"\1<redacted>:<redacted>@", text)
    return text


def parse_proc_stat_cpu() -> Optional[Tuple[int, int]]:
    try:
        with open("/proc/stat", "r", encoding="utf-8") as f:
            line = f.readline().strip()
        parts = line.split()
        if not parts or parts[0] != "cpu":
            return None
        vals = [int(x) for x in parts[1:]]
        total = sum(vals)
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
    if total_delta <= 0:
        return None
    return round(100.0 * (1.0 - idle_delta / total_delta), 1)


def read_meminfo() -> Dict[str, int]:
    data: Dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as f:
            for line in f:
                key, rest = line.split(":", 1)
                value = rest.strip().split()[0]
                data[key] = int(value) * 1024  # kB -> bytes
    except Exception:
        pass
    return data


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


def parse_df(mode: str) -> List[Dict[str, Any]]:
    # POSIX format gives one filesystem per line. Keep overlay because OpenClaw may run in a container.
    cmd = ["df", "-P"] if mode == "space" else ["df", "-Pi"]
    for fs_type in ("tmpfs", "devtmpfs", "squashfs"):
        cmd.extend(["-x", fs_type])
    res = run_cmd(cmd, timeout=5.0)
    if not res["ok"]:
        return []
    rows: List[Dict[str, Any]] = []
    lines = res["stdout"].splitlines()
    for line in lines[1:]:
        parts = line.split(None, 5)
        if len(parts) != 6:
            continue
        filesystem, total, used, avail, use_pct, mount = parts
        try:
            percentage = float(use_pct.rstrip("%"))
        except ValueError:
            continue
        row = {"filesystem": filesystem, "mount": mount, "used_percent": percentage}
        if mode == "space":
            try:
                row.update({
                    "total_bytes": int(total) * 1024,
                    "used_bytes": int(used) * 1024,
                    "available_bytes": int(avail) * 1024,
                })
            except ValueError:
                pass
        else:
            try:
                row.update({"inodes_total": int(total), "inodes_used": int(used), "inodes_free": int(avail)})
            except ValueError:
                pass
        rows.append(row)
    return rows


def merge_disk_rows() -> List[Dict[str, Any]]:
    space = parse_df("space")
    inode = parse_df("inode")
    inode_map = {(r.get("filesystem"), r.get("mount")): r for r in inode}
    result: List[Dict[str, Any]] = []
    for row in space:
        key = (row.get("filesystem"), row.get("mount"))
        i = inode_map.get(key, {})
        merged = dict(row)
        if i:
            merged["inode_used_percent"] = i.get("used_percent")
            for k in ("inodes_total", "inodes_used", "inodes_free"):
                if k in i:
                    merged[k] = i[k]
        result.append(merged)
    return result


def process_state() -> Dict[str, Any]:
    total = 0
    zombies: List[Dict[str, Any]] = []
    proc = Path("/proc")
    if proc.exists():
        for child in proc.iterdir():
            if not child.name.isdigit():
                continue
            total += 1
            try:
                stat = (child / "stat").read_text(encoding="utf-8", errors="replace")
                # pid (comm) state ...; comm can contain spaces, so split after final ') '
                right = stat.rsplit(") ", 1)[1]
                state = right.split()[0]
                if state == "Z":
                    comm = (child / "comm").read_text(encoding="utf-8", errors="replace").strip()[:120]
                    zombies.append({"pid": int(child.name), "comm": comm})
            except Exception:
                continue
    top_cpu = top_processes("-%cpu")
    top_mem = top_processes("-%mem")
    return {"count": total, "zombie_count": len(zombies), "zombies": zombies[:20], "top_cpu": top_cpu, "top_memory": top_mem}


def top_processes(sort_key: str, limit: int = 10) -> List[Dict[str, Any]]:
    res = run_cmd(["ps", "-eo", "pid,user,stat,%cpu,%mem,comm", f"--sort={sort_key}"], timeout=4.0)
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


def get_services() -> Dict[str, Any]:
    systemctl_available = shutil.which("systemctl") is not None
    manager_available = os.path.isdir("/run/systemd/system")
    out: Dict[str, Any] = {
        "systemctl_available": systemctl_available,
        "systemd_manager_available": manager_available,
        "failed_units": [],
        "failed_count": 0,
        "openclaw_units": [],
    }
    if not systemctl_available or not manager_available:
        out["system_state"] = None
        out["coverage_note"] = "systemd manager is not visible in this execution namespace"
        return out

    state = run_cmd(["systemctl", "is-system-running", "--no-pager"], timeout=4.0)
    out["system_state"] = state["stdout"].strip() or None
    out["system_state_ok"] = state["ok"]

    failed = run_cmd(["systemctl", "--failed", "--no-pager", "--no-legend", "--plain"], timeout=5.0)
    failed_units = []
    if failed["available"]:
        for line in failed["stdout"].splitlines():
            if not line.strip():
                continue
            parts = line.split(None, 4)
            failed_units.append({
                "unit": parts[0] if len(parts) > 0 else line.strip(),
                "load": parts[1] if len(parts) > 1 else None,
                "active": parts[2] if len(parts) > 2 else None,
                "sub": parts[3] if len(parts) > 3 else None,
                "description": parts[4] if len(parts) > 4 else None,
            })
    out["failed_units"] = failed_units[:50]
    out["failed_count"] = len(failed_units)

    all_services = run_cmd(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain"], timeout=6.0)
    openclaw = []
    if all_services["ok"]:
        for line in all_services["stdout"].splitlines():
            if "openclaw" in line.lower():
                openclaw.append(line.strip()[:500])
    out["openclaw_units"] = openclaw[:20]
    return out


def get_network(ping_gateway: bool, max_ports: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    addr = run_cmd(["ip", "-brief", "address"], timeout=4.0)
    out["interfaces"] = [redact(x[:500]) for x in addr["stdout"].splitlines()[:100]] if addr["available"] else []

    route = run_cmd(["ip", "route", "show", "default"], timeout=4.0)
    defaults = route["stdout"].splitlines()[:20] if route["available"] else []
    out["default_routes"] = [x[:500] for x in defaults]

    nameservers: List[str] = []
    try:
        for line in Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                nameservers.append(parts[1])
    except Exception:
        pass
    out["dns_nameservers"] = nameservers[:10]

    ss = run_cmd(["ss", "-lntupH"], timeout=5.0, max_chars=80_000)
    listen = [redact(x[:700]) for x in ss["stdout"].splitlines() if x.strip()] if ss["available"] else []
    out["listening_ports"] = listen[:max_ports]
    out["listening_ports_total_observed"] = len(listen)
    out["listening_ports_truncated"] = len(listen) > max_ports or bool(ss.get("truncated"))

    gateway = None
    for line in defaults:
        m = re.search(r"\bvia\s+(\S+)", line)
        if m:
            gateway = m.group(1)
            break
    out["default_gateway"] = gateway
    if ping_gateway and gateway:
        ping = run_cmd(["ping", "-c", "1", "-W", "1", gateway], timeout=3.0, max_chars=10_000)
        out["gateway_ping"] = {"attempted": ping["available"], "ok": ping["ok"], "detail": redact((ping["stdout"] or ping["stderr"])[:1000])}
    else:
        out["gateway_ping"] = {"attempted": False, "ok": None}
    return out


def get_journal(since: str, max_lines: int) -> Dict[str, Any]:
    res = run_cmd(
        ["journalctl", "-p", "err..alert", "--since", since, "--no-pager", "--output=short-iso", "-n", str(max_lines)],
        timeout=7.0,
        max_chars=100_000,
    )
    if not res["available"]:
        return {"available": False, "entries": [], "observed_count": 0}
    lines = [redact(x[:1000]) for x in res["stdout"].splitlines() if x.strip()]
    # journalctl may print "-- No entries --"; normalize it away.
    lines = [x for x in lines if x.strip() != "-- No entries --"]
    return {
        "available": True,
        "ok": res["ok"],
        "since": since,
        "entries": lines,
        "observed_count": len(lines),
        "truncated_at": max_lines if len(lines) >= max_lines else None,
        "error": redact(res["stderr"][:1000]) if res["stderr"] else None,
    }


def add_finding(findings: List[Dict[str, Any]], severity: str, category: str, title: str, detail: str, evidence: Dict[str, Any]) -> None:
    findings.append({"severity": severity, "category": category, "title": title, "detail": detail, "evidence": evidence})


def classify(data: Dict[str, Any], args: argparse.Namespace) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    cpu = data["metrics"]["cpu"]
    usage = cpu.get("usage_percent")
    if usage is not None:
        if usage >= args.cpu_critical:
            add_finding(findings, "critical", "cpu", "CPU utilization is critical", f"CPU usage is {usage:.1f}%.", {"usage_percent": usage, "threshold": args.cpu_critical})
        elif usage >= args.cpu_warning:
            add_finding(findings, "warning", "cpu", "CPU utilization is high", f"CPU usage is {usage:.1f}%.", {"usage_percent": usage, "threshold": args.cpu_warning})

    load1 = cpu.get("load_1m")
    cpu_count = cpu.get("logical_cpus") or 1
    if load1 is not None and cpu_count:
        ratio = load1 / cpu_count
        if ratio >= args.load_critical_per_cpu:
            add_finding(findings, "critical", "cpu", "Load average is critical", f"1-minute load per logical CPU is {ratio:.2f}.", {"load_1m": load1, "logical_cpus": cpu_count, "ratio": round(ratio, 2)})
        elif ratio >= args.load_warning_per_cpu:
            add_finding(findings, "warning", "cpu", "Load average is elevated", f"1-minute load per logical CPU is {ratio:.2f}.", {"load_1m": load1, "logical_cpus": cpu_count, "ratio": round(ratio, 2)})

    mem = data["metrics"]["memory"]
    mem_pct = mem.get("used_percent")
    if mem_pct is not None:
        if mem_pct >= args.mem_critical:
            add_finding(findings, "critical", "memory", "Memory pressure is critical", f"Memory used is {mem_pct:.1f}%.", {"used_percent": mem_pct, "threshold": args.mem_critical})
        elif mem_pct >= args.mem_warning:
            add_finding(findings, "warning", "memory", "Memory usage is high", f"Memory used is {mem_pct:.1f}%.", {"used_percent": mem_pct, "threshold": args.mem_warning})

    swap_pct = mem.get("swap_used_percent")
    if swap_pct is not None and mem.get("swap_total_bytes", 0) > 0:
        if swap_pct >= 95:
            add_finding(findings, "critical", "memory", "Swap usage is critical", f"Swap used is {swap_pct:.1f}%.", {"swap_used_percent": swap_pct})
        elif swap_pct >= 80:
            add_finding(findings, "warning", "memory", "Swap usage is high", f"Swap used is {swap_pct:.1f}%.", {"swap_used_percent": swap_pct})

    for disk in data["metrics"]["disks"]:
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
    z = procs.get("zombie_count", 0)
    if z >= 10:
        add_finding(findings, "critical", "process", "Many zombie processes detected", f"Detected {z} zombie processes.", {"zombie_count": z})
    elif z > 0:
        add_finding(findings, "warning", "process", "Zombie processes detected", f"Detected {z} zombie process(es).", {"zombie_count": z})

    services = data["metrics"]["services"]
    if services.get("systemd_manager_available"):
        failed_count = services.get("failed_count", 0)
        if failed_count > 0:
            add_finding(findings, "warning", "service", "Failed systemd units detected", f"systemd reports {failed_count} failed unit(s).", {"failed_count": failed_count})
        system_state = (services.get("system_state") or "").strip().lower()
        if system_state in {"maintenance", "stopping", "offline", "unknown"}:
            add_finding(findings, "critical", "service", f"Systemd state is {system_state}", "The overall systemd state is unhealthy.", {"system_state": system_state})
        elif system_state == "degraded":
            add_finding(findings, "warning", "service", "Systemd reports degraded state", "One or more units may be unhealthy.", {"system_state": system_state})

    journal = data["metrics"]["journal"]
    jcount = journal.get("observed_count", 0) if journal.get("available") else 0
    if jcount >= args.journal_warning_count:
        add_finding(findings, "warning", "log", "Recent error-level journal entries detected", f"Observed at least {jcount} error-or-higher journal entries in the requested window.", {"observed_count": jcount, "since": journal.get("since")})

    network = data["metrics"]["network"]
    gw_ping = network.get("gateway_ping", {})
    if gw_ping.get("attempted") and gw_ping.get("ok") is False:
        add_finding(findings, "warning", "network", "Default gateway ping failed", "A one-packet ICMP check to the default gateway did not succeed. ICMP may be blocked, so treat this as supporting evidence rather than proof of an outage.", {"gateway": network.get("default_gateway")})

    return findings


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Read-only local Linux server health scan")
    p.add_argument("--output", help="Write JSON to this file instead of stdout")
    p.add_argument("--cpu-sample-seconds", type=float, default=0.5)
    p.add_argument("--cpu-warning", type=float, default=85.0)
    p.add_argument("--cpu-critical", type=float, default=95.0)
    p.add_argument("--mem-warning", type=float, default=85.0)
    p.add_argument("--mem-critical", type=float, default=95.0)
    p.add_argument("--disk-warning", type=float, default=80.0)
    p.add_argument("--disk-critical", type=float, default=90.0)
    p.add_argument("--inode-warning", type=float, default=85.0)
    p.add_argument("--inode-critical", type=float, default=95.0)
    p.add_argument("--load-warning-per-cpu", type=float, default=1.0)
    p.add_argument("--load-critical-per-cpu", type=float, default=2.0)
    p.add_argument("--journal-since", default="1 hour ago")
    p.add_argument("--journal-lines", type=int, default=50)
    p.add_argument("--journal-warning-count", type=int, default=20)
    p.add_argument("--max-ports", type=int, default=80)
    p.add_argument("--no-journal", action="store_true")
    p.add_argument("--ping-gateway", action="store_true", help="Attempt one ICMP ping to the default gateway")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    logical_cpus = os.cpu_count() or 1
    try:
        load1, load5, load15 = os.getloadavg()
    except (OSError, AttributeError):
        load1 = load5 = load15 = None

    mem = read_meminfo()
    total = mem.get("MemTotal", 0)
    available = mem.get("MemAvailable", mem.get("MemFree", 0))
    used = max(0, total - available)
    swap_total = mem.get("SwapTotal", 0)
    swap_free = mem.get("SwapFree", 0)
    swap_used = max(0, swap_total - swap_free)

    try:
        hostname = socket.gethostname()
        fqdn = socket.getfqdn()
    except Exception:
        hostname, fqdn = "unknown", "unknown"

    data: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scan_mode": "local_read_only",
        "scanned_at_utc": utc_now_iso(),
        "host": {
            "hostname": hostname,
            "fqdn": fqdn,
            "platform": platform.platform(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "execution_context_note": "Metrics reflect the OS namespace visible to the OpenClaw process. If OpenClaw runs in a container without host mounts/privileges, this may describe the container rather than the physical/VM host.",
        },
        "uptime": get_uptime(),
        "metrics": {
            "cpu": {
                "logical_cpus": logical_cpus,
                "usage_percent": cpu_usage(args.cpu_sample_seconds),
                "load_1m": round(load1, 2) if load1 is not None else None,
                "load_5m": round(load5, 2) if load5 is not None else None,
                "load_15m": round(load15, 2) if load15 is not None else None,
            },
            "memory": {
                "total_bytes": total,
                "available_bytes": available,
                "used_bytes": used,
                "used_percent": pct(used, total),
                "swap_total_bytes": swap_total,
                "swap_used_bytes": swap_used,
                "swap_used_percent": pct(swap_used, swap_total) if swap_total else 0.0,
            },
            "disks": merge_disk_rows(),
            "processes": process_state(),
            "services": get_services(),
            "network": get_network(args.ping_gateway, max(1, min(args.max_ports, 500))),
            "journal": {"available": False, "entries": [], "observed_count": 0} if args.no_journal else get_journal(args.journal_since, max(1, min(args.journal_lines, 200))),
        },
        "thresholds": {
            "cpu_warning_percent": args.cpu_warning,
            "cpu_critical_percent": args.cpu_critical,
            "memory_warning_percent": args.mem_warning,
            "memory_critical_percent": args.mem_critical,
            "disk_warning_percent": args.disk_warning,
            "disk_critical_percent": args.disk_critical,
            "inode_warning_percent": args.inode_warning,
            "inode_critical_percent": args.inode_critical,
            "load_warning_per_cpu": args.load_warning_per_cpu,
            "load_critical_per_cpu": args.load_critical_per_cpu,
        },
    }

    findings = classify(data, args)
    data["findings"] = findings
    critical = sum(1 for f in findings if f["severity"] == "critical")
    warning = sum(1 for f in findings if f["severity"] == "warning")
    data["summary"] = {
        "overall_status": "Critical" if critical else ("Warning" if warning else "Healthy"),
        "critical_findings": critical,
        "warning_findings": warning,
        "finding_count": len(findings),
    }

    rendered = json.dumps(data, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
