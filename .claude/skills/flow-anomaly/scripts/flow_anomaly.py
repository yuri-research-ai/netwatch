#!/usr/bin/env python3
"""Find suspicious traffic in netwatch flow logs (netwatch.flow.v0, flows.*.ndjson).

Standard library only. Reads flow log files, or a directory of them, splits the
events into a recent window and a baseline (everything older), then:

  * classifies each connection (suspicious port, plaintext HTTP, protocol
    mismatch, DNS to an unknown resolver, no owner, no name, LAN);
  * detects anomalies against the baseline (new destinations, upload spikes,
    beaconing, fan-out, DNS tunnelling / DGA-like names, NXDOMAIN storms);
  * groups the traffic by process and by destination organisation, and ranks
    processes by a risk score.

A finding is a lead to check, not a verdict.

    python3 flow_anomaly.py /var/log/netwatch --window-hours 2
    python3 flow_anomaly.py /var/log/netwatch --json > report.json
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import ipaddress
import json
import statistics
import sys
from pathlib import Path

FLOW_TYPES = ("open", "close", "connect", "dns", "dropped")
CONN_TYPES = ("open", "close", "connect")
SEV_ORDER = {"high": 0, "medium": 1, "low": 2}
SEV_WEIGHT = {"high": 10, "medium": 4, "low": 1}

# Ports that are rarely legitimate as outbound destinations from a workstation.
# Backdoor and IRC defaults first, then remote-access and file-sharing ports.
SUSPICIOUS_PORTS_HIGH = {4444, 5555, 6666, 6667, 6697, 1337, 31337}
SUSPICIOUS_PORTS_MEDIUM = {23, 2323, 135, 139, 445, 3389, 5900}
KNOWN_RESOLVERS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"}


# ── loading ────────────────────────────────────────────────────────────────


def parse_ts(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def split_addr(addr: str) -> tuple[str, str]:
    """'1.2.3.4:443' -> ('1.2.3.4', '443'); '[2001:db8::1]:443' -> ('2001:db8::1', '443')."""
    if not addr:
        return "", ""
    if addr.startswith("["):
        host, _, port = addr[1:].rpartition("]:")
        return host, port
    if ":" not in addr:
        return addr, ""
    host, _, port = addr.rpartition(":")
    return host, port


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_unspecified or a.is_reserved)


def load(paths: list[str]) -> tuple[list[dict], collections.Counter]:
    files: list[Path] = []
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_dir():
            files += sorted(p.glob("flows.*.ndjson"))
        else:
            files.append(p)

    events: list[dict] = []
    stats: collections.Counter = collections.Counter()
    for path in files:
        try:
            handle = path.open(encoding="utf-8", errors="replace")
        except OSError as err:
            print(f"skip {path}: {err}", file=sys.stderr)
            stats["unreadable_files"] += 1
            continue
        with handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    stats["bad_lines"] += 1
                    continue
                if "_meta" in ev or ev.get("event") not in FLOW_TYPES:
                    continue
                try:
                    ev["ts"] = parse_ts(ev["ts"])
                except (KeyError, ValueError):
                    stats["bad_timestamps"] += 1
                    continue
                events.append(ev)
                stats["events"] += 1
    events.sort(key=lambda e: e["ts"])
    return events, stats


# ── helpers ────────────────────────────────────────────────────────────────


def proc(e: dict) -> str:
    return e.get("process") or "(unknown)"


def name_of(e: dict) -> str:
    return e.get("host") or e.get("dns_name") or e.get("rdns") or ""


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def finding(sev: str, check: str, process: str, summary: str, details: list[str] | None = None) -> dict:
    return {"severity": sev, "check": check, "process": process,
            "summary": summary, "details": details or []}


def is_service_discovery(qname: str) -> bool:
    """mDNS / DNS-SD names (Bonjour, AirPlay, printers): long by design, not tunnels."""
    if qname.endswith((".local", ".arpa")):
        return True
    return any(lbl.startswith("_") for lbl in qname.split("."))


def is_outbound(e: dict) -> bool:
    """A connection this host started. `direction: "in"` marks one the far side
    started to a listening port here: its remote port is the client's, and it
    says nothing about where this host goes. Logs older than the field have no
    direction, and count as outbound."""
    return e["event"] in CONN_TYPES and e.get("direction") != "in"


def outgoing(e: dict) -> bool:
    return is_outbound(e) and bool(e.get("remote"))


def user_of(e: dict) -> str:
    """`1013`, or `0<-1013` when someone logged in as 1013 runs it as root."""
    uid, euid, auid = e.get("uid"), e.get("euid"), e.get("auid")
    if euid is None:
        return ""
    who = str(euid if uid == euid else f"{euid}/{uid}")
    return f"{who}<-{auid}" if auid is not None and auid != uid else who


def dest_of(e: dict) -> tuple[str, int | None]:
    ip, port = split_addr(e.get("remote") or "")
    try:
        return ip, int(port)
    except ValueError:
        return ip, None


# ── classification (per connection) ────────────────────────────────────────


def classify(e: dict) -> list[tuple[str, str]]:
    """Return (tag, severity) pairs for one connection event. Tags aggregate later."""
    if not is_outbound(e):
        return []
    ip, port = dest_of(e)
    if not ip or not is_public(ip):
        return []
    tags: list[tuple[str, str]] = []
    if port in SUSPICIOUS_PORTS_HIGH:
        tags.append((f"suspicious-port-{port}", "high"))
    elif port in SUSPICIOUS_PORTS_MEDIUM:
        tags.append((f"suspicious-port-{port}", "medium"))
    if e.get("app_protocol") == "http":
        tags.append(("plaintext-http", "low"))
    if (port == 443 and e.get("app_protocol") == "http") or (port == 80 and e.get("app_protocol") == "tls"):
        tags.append(("protocol-mismatch", "medium"))
    if not e.get("process"):
        tags.append(("unattributed", "low"))
    if not name_of(e):
        tags.append(("no-name", "low"))
    return tags


def check_classified(recent: list[dict], out: list[dict], t: dict) -> None:
    buckets: dict[tuple[str, str], dict] = {}
    for e in recent:
        for tag, sev in classify(e):
            key = (proc(e), tag)
            b = buckets.setdefault(key, {"sev": sev, "n": 0, "ex": []})
            b["n"] += 1
            if len(b["ex"]) < 5:
                ip, port = dest_of(e)
                b["ex"].append(f"{ip}:{port} {name_of(e)}".rstrip())
    for (p, tag), b in buckets.items():
        if tag == "no-name" and b["n"] < t["no_name_min"]:
            continue  # a few nameless flows are normal (QUIC, bare IPs)
        if tag == "unattributed" and b["n"] < t["unattributed_min"]:
            continue
        out.append(finding(b["sev"], tag, p, f"{b['n']} connection(s)", b["ex"]))


def check_dns_resolvers(recent: list[dict], out: list[dict]) -> None:
    per: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    for e in recent:
        if e["event"] == "dns" and e.get("server"):
            server = split_addr(e["server"])[0]
            if is_public(server) and server not in KNOWN_RESOLVERS:
                per[(proc(e), server)].append(e.get("qname") or "")
    for (p, server), names in per.items():
        out.append(finding("medium", "dns-to-unknown-resolver", p,
                           f"{len(names)} DNS queries sent to {server}, not a known public resolver",
                           sorted(set(names))[:5]))


# ── anomalies against the baseline ─────────────────────────────────────────


def check_new_destinations(recent, base, out, t):
    seen: dict[str, set[str]] = collections.defaultdict(set)
    for e in base:
        if outgoing(e):
            seen[proc(e)].add(dest_of(e)[0])
    new: dict[str, dict[str, str]] = collections.defaultdict(dict)
    for e in recent:
        if outgoing(e):
            ip = dest_of(e)[0]
            if ip not in seen[proc(e)]:
                new[proc(e)].setdefault(ip, name_of(e))
    for p, dests in new.items():
        n = len(dests)
        sev = "medium" if n >= t["new_dest_medium"] else "low"
        examples = [f"{ip} {name}".rstrip() for ip, name in list(dests.items())[:10]]
        out.append(finding(sev, "new-destinations", p,
                           f"{n} destination(s) not seen in the baseline", examples))


def check_volume(recent, base, rec_h, base_h, out, t):
    def upload_by_proc(evs):
        totals: collections.Counter = collections.Counter()
        for e in evs:
            # An inbound flow's bytes out are what this host served.
            if e["event"] == "close" and is_outbound(e):
                totals[proc(e)] += int(e.get("bytes_out") or 0)
        return totals

    now, before = upload_by_proc(recent), upload_by_proc(base)
    for p, sent in now.items():
        if sent < t["min_bytes"]:
            continue
        prior = before.get(p, 0) / base_h
        if prior == 0:
            out.append(finding("high", "upload-volume", p,
                               f"sent {human(sent)} in the window, nothing outbound in the baseline"))
            continue
        ratio = (sent / rec_h) / prior
        if ratio >= t["volume_ratio"]:
            sev = "high" if ratio >= 3 * t["volume_ratio"] else "medium"
            out.append(finding(sev, "upload-volume", p,
                               f"sent {human(sent)} in the window, {ratio:.1f}x its baseline rate"))


def check_beacons(recent, out, t):
    times: dict[tuple[str, str], list[float]] = collections.defaultdict(list)
    for e in recent:
        if e["event"] in ("open", "connect") and outgoing(e):
            ip = dest_of(e)[0]
            if is_public(ip):
                times[(proc(e), ip)].append(e["ts"].timestamp())
    for (p, ip), ts in times.items():
        if len(ts) < t["beacon_min"]:
            continue
        ts.sort()
        gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
        if len(gaps) < t["beacon_min"] - 1:
            continue
        mean = statistics.fmean(gaps)
        if not 5 <= mean <= 3600:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv <= t["beacon_cv"]:
            sev = "high" if cv <= t["beacon_cv"] / 2 else "medium"
            out.append(finding(sev, "beacon", p,
                               f"{len(ts)} connections to {ip} at ~{mean:.0f} s intervals (jitter cv {cv:.2f})",
                               ["regular check-ins are also how a keepalive or NTP client looks; "
                                "confirm the destination"]))


def check_fanout(recent, out, t):
    hosts: dict[str, set[str]] = collections.defaultdict(set)
    ports: dict[tuple[str, str], set[int | None]] = collections.defaultdict(set)
    for e in recent:
        if e["event"] in ("open", "connect") and outgoing(e):
            ip, port = dest_of(e)
            hosts[proc(e)].add(ip)
            ports[(proc(e), ip)].add(port)
    for p, dests in hosts.items():
        if len(dests) >= t["fanout_hosts"]:
            out.append(finding("medium", "many-destinations", p,
                               f"connected to {len(dests)} distinct hosts in the window"))
    for (p, ip), pset in ports.items():
        if len(pset) >= t["fanout_ports"]:
            out.append(finding("high", "many-ports", p,
                               f"{len(pset)} distinct ports on {ip}, port-scan shaped"))


def check_closes(recent, out, t):
    retrans: collections.Counter = collections.Counter()
    long_lived: collections.Counter = collections.Counter()
    for e in recent:
        if e["event"] != "close":
            continue
        if int(e.get("retransmits") or 0) >= t["retransmits"]:
            retrans[proc(e)] += 1
        if int(e.get("duration_ms") or 0) >= t["long_hours"] * 3_600_000:
            long_lived[proc(e)] += 1
    for p, n in retrans.items():
        out.append(finding("low", "retransmits", p, f"{n} connection(s) with >= {t['retransmits']} retransmits"))
    for p, n in long_lived.items():
        out.append(finding("low", "long-lived", p, f"{n} connection(s) open longer than {t['long_hours']:g} h"))


def check_dns(recent, out, t):
    per: dict[str, dict] = collections.defaultdict(
        lambda: {"n": 0, "nx": 0, "names": set(), "long": []})
    for e in recent:
        if e["event"] != "dns":
            continue
        d = per[proc(e)]
        qname = (e.get("qname") or "").rstrip(".")
        if is_service_discovery(qname):
            continue
        d["n"] += 1
        d["names"].add(qname)
        if "NXDOMAIN" in str(e.get("rcode", "")).upper():
            d["nx"] += 1
        if len(qname) > t["qname_len"] or any(len(lbl) > t["label_len"] for lbl in qname.split(".")):
            d["long"].append(qname)

    for p, d in per.items():
        if d["n"] >= 20 and d["nx"] / d["n"] >= 0.3:
            out.append(finding("medium", "nxdomain-heavy", p,
                               f"{d['nx']} of {d['n']} DNS queries returned NXDOMAIN"))
        if len(d["long"]) >= 5:
            out.append(finding("high", "long-dns-names", p,
                               f"{len(d['long'])} DNS names are unusually long, possible tunnelling",
                               d["long"][:5]))
        under: collections.Counter = collections.Counter()
        for q in d["names"]:
            parts = q.split(".")
            if len(parts) >= 2:
                under[".".join(parts[-2:])] += 1
        for domain, n in under.most_common(3):
            if n >= t["dns_unique"]:
                out.append(finding("high", "many-unique-names", p,
                                   f"{n} distinct names under {domain}, possible DGA or tunnelling"))


# Writable scratch directories: a binary run from one was dropped there.
EXE_DIRS_HIGH = ("/dev/shm/",)
EXE_DIRS_MEDIUM = ("/tmp/", "/var/tmp/", "/run/user/")


def check_executables(recent, out):
    """Processes running a deleted binary, or one from a scratch directory."""
    per: dict[tuple[str, str, str], set[str]] = collections.defaultdict(set)
    for e in recent:
        exe = e.get("exe")
        if not exe or e["event"] not in CONN_TYPES + ("dns",):
            continue
        dest = e.get("remote") or e.get("server") or ""
        if exe.endswith(" (deleted)"):
            per[("medium", "deleted-executable", proc(e))].add(f"{exe} -> {dest}")
        path = exe.removesuffix(" (deleted)")
        if path.startswith(EXE_DIRS_HIGH):
            per[("high", "exe-in-scratch-dir", proc(e))].add(f"{exe} -> {dest}")
        elif path.startswith(EXE_DIRS_MEDIUM):
            per[("medium", "exe-in-scratch-dir", proc(e))].add(f"{exe} -> {dest}")
    for (sev, check, p), seen in per.items():
        summary = ("runs a binary deleted or replaced since it started"
                   if check == "deleted-executable" else "runs a binary from a writable scratch directory")
        out.append(finding(sev, check, p, f"{summary}, {len(seen)} connection(s)", sorted(seen)[:5]))


def check_dropped(recent, out):
    dropped = sum(int(e.get("count") or 0) for e in recent if e["event"] == "dropped")
    if dropped:
        out.append(finding("low", "dropped-events", "(daemon)",
                           f"{dropped} event(s) dropped in the window, results may be incomplete"))


# ── grouping ───────────────────────────────────────────────────────────────


def group_by_process(recent: list[dict]) -> dict[str, dict]:
    groups: dict[str, dict] = collections.defaultdict(
        lambda: {"opens": 0, "inbound": 0, "dests": set(), "ports": collections.Counter(),
                 "orgs": collections.Counter(), "users": collections.Counter(),
                 "exes": collections.Counter(), "up": 0, "down": 0})
    for e in recent:
        g = groups[proc(e)]
        if e.get("exe"):
            g["exes"][e["exe"]] += 1
        if user_of(e):
            g["users"][user_of(e)] += 1
        if e["event"] == "open":
            g["opens"] += 1
            if not is_outbound(e):
                g["inbound"] += 1
        if outgoing(e):
            ip, port = dest_of(e)
            g["dests"].add(ip)
            if port is not None:
                g["ports"][port] += 1
        if e["event"] == "close":
            g["up"] += int(e.get("bytes_out") or 0)
            g["down"] += int(e.get("bytes_in") or 0)
            if e.get("asn_org"):
                g["orgs"][e["asn_org"]] += 1
    return groups


def group_by_org(recent: list[dict]) -> dict[str, dict]:
    orgs: dict[str, dict] = collections.defaultdict(
        lambda: {"procs": collections.Counter(), "dests": set(), "up": 0, "down": 0})
    for e in recent:
        org = e.get("asn_org")
        if not org:
            continue
        o = orgs[org]
        o["procs"][proc(e)] += 1
        if outgoing(e):
            o["dests"].add(dest_of(e)[0])
        if e["event"] == "close":
            o["up"] += int(e.get("bytes_out") or 0)
            o["down"] += int(e.get("bytes_in") or 0)
    return orgs


def group_inbound(recent: list[dict]) -> list[dict]:
    """Connections the far side started, by the local port they came to."""
    ports: dict[tuple[str, str], dict] = collections.defaultdict(
        lambda: {"opens": 0, "clients": collections.Counter()})
    for e in recent:
        if e["event"] == "open" and not is_outbound(e):
            g = ports[(proc(e), split_addr(e.get("local") or "")[1])]
            g["opens"] += 1
            g["clients"][dest_of(e)[0]] += 1
    return [
        {"process": p, "port": port, "opens": g["opens"], "clients": len(g["clients"]),
         "top_clients": g["clients"].most_common(3)}
        for (p, port), g in sorted(ports.items(), key=lambda kv: -kv[1]["opens"])
    ]


def risk_by_process(findings: list[dict]) -> collections.Counter:
    risk: collections.Counter = collections.Counter()
    for f in findings:
        risk[f["process"]] += SEV_WEIGHT[f["severity"]]
    return risk


# ── analysis ───────────────────────────────────────────────────────────────


def analyse(events: list[dict], args: argparse.Namespace) -> dict:
    t = vars(args)
    end = events[-1]["ts"]
    start = events[0]["ts"]
    recent_start = end - dt.timedelta(hours=args.window_hours)
    recent = [e for e in events if e["ts"] >= recent_start]
    base = [e for e in events if e["ts"] < recent_start]
    rec_h = max((end - max(recent_start, start)).total_seconds() / 3600, 1 / 60)
    base_h = (recent_start - start).total_seconds() / 3600 if base else 0.0

    findings: list[dict] = []
    if base:
        check_new_destinations(recent, base, findings, t)
        check_volume(recent, base, rec_h, base_h, findings, t)
    else:
        findings.append(finding("low", "no-baseline", "(all)",
                                "log covers only the window, so new-destination and volume checks were skipped"))
    check_beacons(recent, findings, t)
    check_fanout(recent, findings, t)
    check_closes(recent, findings, t)
    check_classified(recent, findings, t)
    check_dns_resolvers(recent, findings)
    check_dns(recent, findings, t)
    check_dropped(recent, findings)
    check_executables(recent, findings)
    findings.sort(key=lambda f: SEV_ORDER[f["severity"]])

    procs = group_by_process(recent)
    risk = risk_by_process(findings)
    return {
        "meta": {
            "first_event": start.isoformat(),
            "last_event": end.isoformat(),
            "window_hours": round(rec_h, 2),
            "baseline_hours": round(base_h, 2),
            "events_in_window": len(recent),
            "events_in_baseline": len(base),
        },
        "findings": findings,
        "processes": [
            {"process": p, "risk": risk.get(p, 0), "opens": g["opens"], "inbound": g["inbound"],
             "destinations": len(g["dests"]), "users": [u for u, _ in g["users"].most_common(3)],
             "exes": [x for x, _ in g["exes"].most_common(3)],
             "up": g["up"], "down": g["down"],
             "top_ports": g["ports"].most_common(3), "top_orgs": g["orgs"].most_common(3)}
            for p, g in sorted(procs.items(), key=lambda kv: (-risk.get(kv[0], 0), -kv[1]["up"]))
        ],
        "inbound": group_inbound(recent)[: args.top],
        "organisations": [
            {"org": org, "processes": o["procs"].most_common(5), "destinations": len(o["dests"]),
             "up": o["up"], "down": o["down"]}
            for org, o in sorted(group_by_org(recent).items(), key=lambda kv: -(kv[1]["up"] + kv[1]["down"]))
        ][: args.top],
    }


def render(report: dict, stats: collections.Counter, top: int) -> str:
    m = report["meta"]
    lines = [
        f"events {m['first_event']} .. {m['last_event']}",
        f"window {m['window_hours']} h ({m['events_in_window']} events), "
        f"baseline {m['baseline_hours']} h ({m['events_in_baseline']} events)",
    ]
    if stats["bad_lines"]:
        lines.append(f"skipped {stats['bad_lines']} malformed line(s)")

    findings = report["findings"]
    lines.append("")
    lines.append(f"== Findings ({len(findings)}) ==")
    if not findings:
        lines.append("none")
    for f in findings[: top * 4]:
        lines.append(f"[{f['severity'].upper()}] {f['check']} · {f['process']}: {f['summary']}")
        for d in f["details"]:
            lines.append(f"    {d}")

    lines.append("")
    lines.append("== Processes, by risk ==")
    lines.append(f"{'process':<22}{'users':<14}{'risk':>6}{'conns':>8}{'in':>6}{'dests':>7}{'up':>11}{'down':>11}"
                 "  top ports / orgs")
    for p in report["processes"][:top]:
        ports = ", ".join(f"{port}:{n}" for port, n in p["top_ports"])
        orgs = ", ".join(f"{org}({n})" for org, n in p["top_orgs"])
        users = ",".join(p["users"])
        lines.append(f"{p['process'][:21]:<22}{users[:13]:<14}{p['risk']:>6}{p['opens']:>8}{p['inbound']:>6}"
                     f"{p['destinations']:>7}{human(p['up']):>11}{human(p['down']):>11}  {ports} | {orgs}")
        if p["exes"]:
            lines.append(f"{'':<22}exe {', '.join(p['exes'])}")

    lines.append("")
    lines.append("== Inbound, by local port ==")
    lines.append(f"{'process':<22}{'port':>7}{'conns':>8}{'clients':>9}  top clients")
    if not report["inbound"]:
        lines.append("none (or a log older than the direction field)")
    for i in report["inbound"]:
        clients = ", ".join(f"{ip}({n})" for ip, n in i["top_clients"])
        lines.append(f"{i['process'][:21]:<22}{i['port']:>7}{i['opens']:>8}{i['clients']:>9}  {clients}")

    lines.append("")
    lines.append("== Destinations, by organisation ==")
    lines.append(f"{'organisation':<30}{'dests':>7}{'up':>11}{'down':>11}  processes")
    for o in report["organisations"]:
        procs = ", ".join(f"{name}({n})" for name, n in o["processes"])
        lines.append(f"{o['org'][:29]:<30}{o['destinations']:>7}{human(o['up']):>11}{human(o['down']):>11}  {procs}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="flow log files, or a directory holding flows.*.ndjson")
    ap.add_argument("--window-hours", type=float, default=2.0, help="recent window; older events are the baseline")
    ap.add_argument("--top", type=int, default=15, help="rows per table")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    ap.add_argument("--volume-ratio", type=float, default=3.0, help="upload rate vs baseline that is flagged")
    ap.add_argument("--min-bytes", type=int, default=50 * 2**20, help="ignore uploads below this in the window")
    ap.add_argument("--new-dest-medium", type=int, default=10, help="new destinations that make a process medium")
    ap.add_argument("--beacon-min", type=int, default=8, help="connections needed to test for beaconing")
    ap.add_argument("--beacon-cv", type=float, default=0.15, help="max jitter (stdev/mean of intervals)")
    ap.add_argument("--fanout-hosts", type=int, default=100, help="distinct hosts per process")
    ap.add_argument("--fanout-ports", type=int, default=50, help="distinct ports on one host")
    ap.add_argument("--no-name-min", type=int, default=20, help="nameless connections per process to report")
    ap.add_argument("--unattributed-min", type=int, default=20)
    ap.add_argument("--long-hours", type=float, default=12.0)
    ap.add_argument("--retransmits", type=int, default=50)
    ap.add_argument("--qname-len", type=int, default=80)
    ap.add_argument("--label-len", type=int, default=50)
    ap.add_argument("--dns-unique", type=int, default=100, help="distinct names under one domain")
    args = ap.parse_args(argv)

    events, stats = load(args.paths)
    if not events:
        print("no flow events found", file=sys.stderr)
        return 1

    report = analyse(events, args)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
    else:
        print(render(report, stats, args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
