---
name: server-health-scan
description: Scan the health of the single Linux server or execution namespace where OpenClaw is running, using a bundled read-only local scanner and producing a structured health report. Use when the user asks to inspect, scan, diagnose, check, audit, or report the local OpenClaw host's CPU, load, memory, swap, disks, inodes, processes, zombie processes, systemd services, listening ports, network basics, or recent error logs. Designed for an OpenClaw runtime configured to use gpt-5.6-sol-xhigh; it does not SSH to other hosts and does not perform automatic remediation.
---

# Server Health Scan

Perform a local, read-only Linux health scan and turn the collected evidence into a concise operational report.

## Runtime contract

- Run only against the machine namespace visible to the current OpenClaw process.
- Never SSH to other servers.
- Assume OpenClaw is configured to use `gpt-5.6-sol-xhigh`. Do not claim this Skill can switch the runtime model itself.
- Never use `sudo` or privileged container escape techniques.
- Never restart services, kill processes, delete files, clear logs, change firewall rules, install packages, or edit system configuration during a scan.
- If OpenClaw is containerized, report that metrics may describe the container namespace instead of the underlying host unless host visibility is confirmed.

## Workflow

1. Run the bundled scanner:

   ```bash
   python3 scripts/scan_health.py --output /tmp/server-health-scan.json
   ```

2. If the user explicitly wants an ICMP check to the default gateway, add `--ping-gateway`. Do not enable it by default.
3. If reading journal entries is inappropriate or unavailable, add `--no-journal` and explicitly report that log coverage is missing.
4. Read `/tmp/server-health-scan.json` and inspect both `summary`/`findings` and the raw metrics.
5. Produce the final report using [references/report-format.md](references/report-format.md).
6. Surface unavailable commands or missing data as coverage limitations instead of guessing.

## What the scanner collects

Collect bounded, read-only evidence for:

- Host identity, kernel, architecture, uptime.
- CPU utilization sampled from `/proc/stat`, logical CPU count, and 1/5/15-minute load averages.
- Memory availability and swap usage from `/proc/meminfo`.
- Filesystem space and inode consumption with `df`, excluding volatile tmpfs/devtmpfs/squashfs mounts.
- Process count, zombie processes, and top CPU/memory processes without full command arguments.
- systemd overall state, failed units, and units whose names/descriptions contain `openclaw`, when systemd is available.
- Network interfaces, default route, DNS nameservers, and bounded listening-port data with `ss`, when available.
- Recent `journalctl` entries at error severity or higher, capped and best-effort redacted.

Do not fail the entire scan because an optional utility is missing. Report partial coverage.

## Default severity policy

Use these scanner defaults unless the user provides different thresholds:

- CPU: Warning >= 85%, Critical >= 95%.
- Memory: Warning >= 85%, Critical >= 95%.
- Disk: Warning >= 80%, Critical >= 90%.
- Inodes: Warning >= 85%, Critical >= 95%.
- 1-minute load per logical CPU: Warning >= 1.0, Critical >= 2.0.
- Swap: Warning >= 80%, Critical >= 95% when swap exists.
- Zombie processes: Warning > 0, Critical >= 10.
- Failed systemd units: Warning; investigate relevance before escalating.
- Recent journal errors: Warning when at least 20 error-or-higher entries are observed in the default window.

Treat the overall state as `Critical` if any critical finding exists, otherwise `Warning` if any warning exists, otherwise `Healthy`. Downgrade confidence when important coverage is unavailable.

## Report behavior

- Default to Simplified Chinese.
- Lead with the overall status and highest-severity findings.
- Include actual measured values and the threshold or evidence behind each conclusion.
- Summarize ports and logs; do not dump large raw lists into the final response.
- Keep credential-like data redacted. Do not reproduce secrets even if a log line appears to contain one.
- Distinguish observation from diagnosis. Phrase uncertain causes as hypotheses.
- Give concrete next-step recommendations, but do not execute mutating remediation unless the user explicitly requests a separate remediation action.

## Common invocations

Standard scan:

```bash
python3 scripts/scan_health.py --output /tmp/server-health-scan.json
```

Exclude journal collection:

```bash
python3 scripts/scan_health.py --no-journal --output /tmp/server-health-scan.json
```

Use stricter disk thresholds:

```bash
python3 scripts/scan_health.py --disk-warning 75 --disk-critical 85 --output /tmp/server-health-scan.json
```
