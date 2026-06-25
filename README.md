# DNS TXT Command-and-Control — Network Forensics Investigation

A self-contained DFIR walkthrough: take an unknown packet capture, work it like a SOC
triage, prove a DNS-tunneled PowerShell C2 channel end to end, and ship behavioral
detections that survive a domain rotation.

**TL;DR** — Host `192.168.100.121` ran a PowerShell agent that uses **DNS TXT records** as
its C2 transport. It pulled itself down in 17 base64 chunks over an `l.<n>.ns.ostrykebs[.]pl`
"load" channel, then beaconed for tasking on a session-scoped `c.<id>.<session>.ns…` channel.
The agent `iex`-executes whatever the server returns and hex-encodes results back over DNS.
No command was tasked during the 62-second capture, so no exfil occurred in-window.

ATT&CK: **T1071.004**, **T1572**, **T1132.001**, **T1140**, **T1059.001**, **T1105**, **T1048.003**

## Read order
1. [`report/investigation.md`](report/investigation.md) — full writeup + reasoning trail
2. [`evidence/decoded_agent_analysis.md`](evidence/decoded_agent_analysis.md) — what the agent does
3. [`iocs/`](iocs/) — indicators (behavioral first, point indicators second)
4. [`detections/`](detections/) — Suricata (network) + Sigma (endpoint)
5. [`methodology/commands.md`](methodology/commands.md) — reproduce every figure

## Detections at a glance
| Layer | File | Catches |
|-------|------|---------|
| Network | `detections/suricata/local.rules` | `l.`/`c.`/`r.` channel grammar + domain |
| Endpoint | `detections/sigma/powershell_nslookup_dns_c2.yml` | powershell.exe -> nslookup.exe `-q=txt` |

Validated: Suricata fires 17 staging / 32 beacon / 50 domain alerts on the capture.

## Data
Capture is third-party lab data containing a live agent and is **not redistributed** —
fetch + SHA-256 in [`captures/README.md`](captures/README.md).
Source: [sbousseaden/PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK).

## Tooling
`tshark` · `suricata` · `sigma-cli` — see methodology for exact invocations.
