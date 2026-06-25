# Investigation: DNS TXT Command and Control on 192.168.100.121

**Analyst:** Paul Aguilera
**Date of analysis:** 2026-06-25
**Evidence:** `dns_c2.pcap` (301 packets, 62.3s, captured 2020-06-06 06:36:39 UTC)
**Classification:** Confirmed C2 — DNS tunneling (staged PowerShell agent)

---

## 1. Executive summary

A single workstation (`192.168.100.121`) was observed running a PowerShell-based
command-and-control (C2) agent that uses **DNS TXT records as its transport**. Over a
62-second window the host issued ~200 DNS queries to one second-level domain,
`ostrykebs[.]pl`, in two distinct phases: it first **downloaded and assembled an agent**
in 17 base64 chunks pulled from sequential TXT records, then **beaconed for tasking** on a
session-scoped subdomain. No operator command was tasked during the capture,but the agent was 
fully staged.

The activity maps to MITRE ATT&CK **T1071.004 (Application Layer Protocol: DNS)**,
**T1132.001 (Standard Encoding)**, **T1059.001 (PowerShell)**, and **T1105 (Ingress Tool
Transfer)**. It is detectable behaviorally without any domain blocklist, which is the basis
for the rules shipped in `/detections`.

---

## 2. How I got here

I worked the capture the way I'd triage an unknown PCAP in a SOC, letting each observation
decide the next question.

**Observation 1 — protocol mix is wrong for a workstation.**
The protocol hierarchy showed DNS accounting for the overwhelming majority of frames
(199 of 301), with almost nothing else of substance. A normal host generates DNS
*alongside* HTTP/TLS/etc. DNS as the near-exclusive protocol is the first tell that DNS is
being used as a transport rather than just for name resolution.

**Observation 2 — one host, one resolver, far too many queries.**
IP conversations collapsed to essentially one pair: `192.168.100.121 → 192.168.100.2`
(the local resolver) carrying 210 frames. Fifty TXT lookups to a single domain in one
minute is not human-driven browsing; it's automation.

**Observation 3 — the query names encode a protocol.**
Stripping out reverse-lookup noise (`*.in-addr.arpa`) and ISATAP chatter left a clear
pattern against `ostrykebs[.]pl`:

```
l.ns       l.1.ns   l.2.ns ... l.17.ns        <- "load" channel, sequential counter
c.1-1.24006.ns  (x32)                          <- "command" channel, session 24006
```

The incrementing counter on the `l.` channel is a chunked-download fingerprint. The `c.`
channel's stable `<cid>-<part>.<session>` shape is a beacon polling for work.

**Observation 4 — the TXT answers contain the malware.**
The first TXT answer (`l.ns`) returned a plaintext PowerShell **download cradle** that
loops `l.$i.ns…`, extracts the payload between `@…@` delimiters, base64-decodes each chunk,
concatenates them, and `iex`-executes the result. The `l.1`–`l.17` answers were the base64
chunks themselves. Reassembling and decoding them yields the full agent (see §4).

**Observation 5 — confirming intent.**
The decoded agent defines a results channel (`r.<hexdata>…`). I explicitly searched the
capture for `r.*` queries and found **none**, and the `c.*` beacon responses were empty TXT.
Conclusion stated precisely: the agent was staged and beaconing, but **un-tasked** during
the capture — so RCE capability is present, executed commands and exfil are not evidenced
here. (Both host MACs carry the `52:54:00` QEMU/KVM OUI, consistent with a lab capture.)

---

## 3. Attack Chain

| Phase | ATT&CK | Evidence in capture |
|-------|--------|---------------------|
| Stager retrieval | T1071.004 / T1105 | `l.ns` TXT returns PowerShell download cradle |
| Agent assembly | T1132.001 / T1140 | `l.1`–`l.17` base64 chunks → `iex` of decoded script |
| Execution | T1059.001 | Cradle and agent run via PowerShell `iex` |
| C2 beacon | T1071.004 / T1572 | 32× `c.1-1.24006.ns.ostrykebs[.]pl` TXT polls |
| (Capability) Result exfil | T1048.003 | `r.<hex>…` channel defined in agent; **not used in-window** |

---

## 4. The Decoded Agent

The 17 staged chunks reassemble into a ~3 KB PowerShell DNS C2 agent. Full annotated
breakdown — including the staging cradle, the hex-encode exfil routine, and the
`iex`-of-server-response command loop — is in
[`../evidence/decoded_agent_analysis.md`](../evidence/decoded_agent_analysis.md).

Key design facts that drive detection:
- Transport is **DNS TXT only**; the agent shells out to `nslookup -q=txt` rather than using
  a socket, so on the endpoint this looks like **PowerShell repeatedly spawning nslookup.exe**.
- Results are **hex-encoded** and split across dotted labels in the query name (`r.<hex>.…`),
  producing abnormally long, high-entropy subdomains.
- Session id is randomized per run (`Random -Maximum 50000`); here it was **24006**. Domain
  and channel-letter structure are static, which is what the behavioral rules target.

---

## 5. Impact Assessment

- **Confirmed:** code execution capability on `192.168.100.121` via a live, beaconing C2
  channel that bypasses web proxies by riding DNS.
- **Not evidenced in this capture:** specific commands executed, data staged, or data
  exfiltrated. Absence of `r.*` traffic is consistent with no tasking, not with proof of no
  prior activity — a longer capture or endpoint logs would be needed to bound that.
- **Containment priority:** DNS is frequently unmonitored and egress-allowed, so this channel
  likely evaded perimeter controls. Treat the host as compromised pending endpoint triage.

---

## 6. Where I'd take this with endpoint logs

The capture tells me *what* is crossing the wire, but it's blind to the two things that
actually set the severity of this incident: how the agent landed on the box, and whether it
did anything before I started watching. Both of those live on the endpoint, and for a host
like this I'd already have the telemetry — Sysmon (SwiftOnSecurity config) plus PowerShell
logging forwarding into the SIEM.

First stop is **PowerShell ScriptBlock logging (Event ID 4104)**. Because the agent
assembles itself from the staged chunks and runs every task through `iex`, 4104 records the
fully-decoded agent *and* any tasked command in cleartext, after AMSI has already stripped
the obfuscation. That single source closes the "capability present vs. actually used" gap I
flagged in §5: if a command ran before this capture started, 4104 will have it even though
the network never showed an `r.*` exfil query. Next I'd pull **Sysmon process creation
(Event ID 1)** and walk the parent chain — the PowerShell-spawning-nslookup loop is the
symptom, but I want the *grandparent*. If `powershell.exe` traces back to `winword.exe`,
`wscript.exe`, or a freshly-registered scheduled task, that's my initial-access story
(likely T1566 delivery). **Sysmon DnsQuery (Event ID 22)** gives me the same TXT lookups I
carved out of the PCAP, but bound to the offending PID, which makes the correlation airtight
and keeps working even if DNS gets encrypted on the wire later. From there it's a standard
persistence sweep — Run keys, scheduled tasks, and WMI event subscriptions (Sysmon 12/13 and
19–21) — to learn whether this survives a reboot, plus AmCache/Prefetch to anchor a
first-execution timestamp. Net effect: the capture proves the *channel*; the endpoint logs
give me root cause, blast radius, and a timeline I can actually defend in a report.

## 7. Recommendations

1. **Isolate** `192.168.100.121` and collect endpoint telemetry (PowerShell ScriptBlock logs,
   Sysmon process-creation, DNS client events).
2. **Deploy the behavioral detections** in `/detections` (Suricata + Sigma). The Sigma rule
   keys on `powershell.exe → nslookup.exe`, which survives a domain change.
3. **Sinkhole / block** `ostrykebs[.]pl` and alert on lookups to it (point detection, §IOCs).
4. **Hunt** retrospectively for the same `l.<n>.ns` and `c.<id>-<part>.<session>` label
   patterns and for any host exceeding a TXT-query-per-domain threshold.
5. **Reduce attack surface:** force internal hosts to use controlled resolvers and log all
   DNS; consider constrained PowerShell / Constrained Language Mode where feasible.

---

## 8. Reproducibility

Every figure above is regenerable from the source capture with the commands in
[`../methodology/commands.md`](../methodology/commands.md). The capture itself is not
redistributed here (it is third-party lab data containing a functional agent); fetch
instructions and a SHA-256 are in [`../captures/README.md`](../captures/README.md).
