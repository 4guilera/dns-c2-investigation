# Capture (not redistributed)

The raw PCAP is third-party lab data that contains a functional DNS C2 agent, so it is not
committed here. Reproduce by fetching it from the upstream source:

```bash
git clone --depth 1 https://github.com/sbousseaden/PCAP-ATTACK.git
cp "PCAP-ATTACK/Command and Control/cmds over dns txt queries and reponses.pcap" dns_c2.pcap
sha256sum dns_c2.pcap   # expect: 17492c2b577101d57c12f8a0122c3c76d327592e2f1d3b4247db2e5eb01299a3
```

**SHA-256:** `17492c2b577101d57c12f8a0122c3c76d327592e2f1d3b4247db2e5eb01299a3`
**Source:** sbousseaden/PCAP-ATTACK — `Command and Control/`
