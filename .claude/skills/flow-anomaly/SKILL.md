---
name: flow-anomaly
description: Find suspicious traffic in netwatch daemon flow logs (netwatch.flow.v0, flows.*.ndjson). Classifies connections, detects beaconing, upload spikes, new destinations, port-scan-shaped fan-out, DNS tunnelling and DGA-like names, DNS to unknown resolvers, and plaintext HTTP. Groups traffic by process and by destination organisation and ranks processes by risk. Use when the user asks about suspicious or anomalous traffic, what a process is talking to, or what the flow log shows.
---

# flow-anomaly

Analyses the flow log that `netwatch daemon --flow-log` writes. The main job is to find
suspicious traffic. Grouping and classification support that.

## Run it

From the repo root:

```bash
python3 .claude/skills/flow-anomaly/scripts/flow_anomaly.py /var/log/netwatch --window-hours 2
```

- `--window-hours` sets the recent window. Older events form the baseline that new
  destinations and volume are compared against. Use a longer baseline when the log has
  days of data.
- `--json` prints the full report for further processing.
- `--top N` sets the row count of the tables.
- Thresholds are flags: `--volume-ratio`, `--min-bytes`, `--beacon-cv`, `--fanout-ports`,
  and others. Run `--help`.

The script uses the standard library only. It reads files, or a directory of
`flows.*.ndjson`, and writes nothing.

Reading `/var/log/netwatch` needs the ACL the user set up for their account. If the read
fails with `Permission denied`, say so and do not change permissions.

## What the report contains

1. **Findings**, most severe first. Each has a severity, a check name, the process, and
   details.
2. **Processes, by risk.** The risk score adds 10 per high, 4 per medium, and 1 per low
   finding. Columns: connections, destinations, bytes up and down, top ports, top
   organisations.
3. **Destinations, by organisation**, from the ASN organisation on close events.

## Checks

| Check | Severity | What it means |
|---|---|---|
| `beacon` | high / medium | Regular connections to one host with tiny jitter. Typical of C2 check-ins. Keepalives and NTP look the same, so confirm the destination. |
| `suspicious-port-<n>` | high / medium | Outbound to a port common for backdoors and IRC (4444, 1337, 6667...) or remote access and SMB (23, 445, 3389...). |
| `upload-volume` | high / medium | Bytes sent in the window far above the process's baseline rate, or uploads with no baseline at all. Exfiltration shape. |
| `long-dns-names` | high | Many DNS names with very long names or labels. Possible DNS tunnel. mDNS and `.local` names are skipped. |
| `many-unique-names` | high | Many distinct names under one domain. Possible DGA or tunnel. |
| `many-ports` | high | One process hits many ports on one host. Port-scan shape. |
| `dns-to-unknown-resolver` | medium | DNS sent to a public IP that is not a known resolver. Can mean malware or a hijacked resolver. |
| `nxdomain-heavy` | medium | Many NXDOMAIN answers. Often DGA probing. |
| `new-destinations` | low / medium | Destinations not seen in the baseline. Medium when there are many. |
| `many-destinations` | medium | One process talks to very many hosts. Normal for browsers. |
| `plaintext-http` | low | Unencrypted HTTP to a public address. |
| `protocol-mismatch` | medium | TLS on port 80, or plaintext HTTP on 443. |
| `unattributed` | low | Connections with no owning process. Attribution gaps or a hidden process. |
| `no-name` | low | Connections with no SNI, host, or reverse name. Often QUIC or bare IPs. |
| `retransmits`, `long-lived` | low | Lossy or very long connections. Context only. |
| `no-baseline` | low | The log covers only the window, so new-destination and volume checks were skipped. |

## How to report

- Lead with the high findings, then the processes with the highest risk.
- For each suspicious item, say what the evidence is and what the innocent explanation
  could be. A finding is a lead, not a verdict.
- Name the process, the destination IP or name, and the organisation. Then suggest the
  next check, such as `lsof -i`, `codesign -dv` on the binary, or the destination's
  reputation. Do not run network lookups against the destination without asking.
- If the report is empty, say so. Do not invent findings.

## Limits

- The flow log only sees connections that survive a poll. Connections shorter than one
  poll interval are missing, so beacon and volume numbers are estimates.
- Byte counts need packet capture. Without it, `upload-volume` finds nothing.
- Beacon jitter is measured on poll timestamps, so the interval is quantised to
  `refresh_rate_ms`.
- Organisation names come from the GeoIP databases. Without them, the organisation table
  is empty.
- Attribution is best effort, so a process name can be wrong. `(unknown)` is a signal,
  not proof.

## Privacy

The log holds remote addresses and hostnames. Keep the analysis local. Do not paste raw
log lines or the full JSON into external services or issue trackers without the user's
go-ahead.
