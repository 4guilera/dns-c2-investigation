# Methodology — reproduce every finding

Tooling: `tshark` (Wireshark CLI) and `suricata`. Fetch the capture per
[`../captures/README.md`](../captures/README.md) and run from the repo root.

## 1. Triage overview
```bash
capinfos dns_c2.pcap
tshark -r dns_c2.pcap -q -z io,phs        # protocol hierarchy -> DNS dominance
tshark -r dns_c2.pcap -q -z conv,ip       # conversations -> one host, one resolver
```

## 2. Characterize the DNS
```bash
# query types: 16=TXT, 12=PTR, 1=A
tshark -r dns_c2.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.type | sort | uniq -c
# base domains, ignoring reverse-lookup noise
tshark -r dns_c2.pcap -Y "dns.flags.response==0" -T fields -e dns.qry.name \
  | awk -F. 'NF>=2{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn
# channel prefixes against the C2 domain
tshark -r dns_c2.pcap -Y 'dns.qry.name contains "ostrykebs" && dns.flags.response==0' \
  -T fields -e dns.qry.name | awk -F. '{print $1}' | sort | uniq -c
```

## 3. Recover the staged agent
```bash
# pair l.<n> query -> TXT answer, order, strip @...@, base64-decode
tshark -r dns_c2.pcap \
  -Y 'dns.qry.name matches "^l\\.[0-9]+\\.ns\\.ostrykebs" && dns.flags.response==1' \
  -T fields -e dns.qry.name -e dns.txt \
  | sort -t. -k2 -n | sed -E 's/^[^\t]*\t//; s/@//g' | tr -d '\n' \
  | base64 -d > staged_agent.ps1
```

## 4. Confirm tasking / exfil (negative result matters)
```bash
tshark -r dns_c2.pcap -Y 'dns.qry.name matches "^r\\."' -T fields -e dns.qry.name   # none
tshark -r dns_c2.pcap -Y 'dns.qry.name contains "c.1-1.24006" && dns.flags.response==1' \
  -T fields -e dns.txt | sort -u                                                    # empty
```

## 5. Validate detections
```bash
suricata -r dns_c2.pcap -S detections/suricata/local.rules -l ./out -k none
sort ./out/fast.log | uniq -c
# expected: 17 staging, 32 command-beacon, 50 domain hits
```

The Sigma rule in `detections/sigma/` is endpoint-side (process_creation) and is validated
against a SIEM with `sigma-cli`, e.g.:
```bash
sigma convert -t splunk detections/sigma/powershell_nslookup_dns_c2.yml
```
