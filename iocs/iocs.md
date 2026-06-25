# Indicators of Compromise

> Noticed the **behavioral** patterns first — they survive a
> domain rotation; the domain/host indicators are point-in-time.

## Network
| Type | Value | Notes |
|------|-------|-------|
| Domain (2LD) | `ostrykebs[.]pl` | C2 second-level domain |
| C2 nameserver label | `ns.ostrykebs[.]pl` | all channels nested under `ns.` |
| Infected host | `192.168.100.121` | issued all C2 lookups |
| Resolver used | `192.168.100.2` | local forwarder (also `8.8.8.8` seen) |
| Session id | `24006` | randomized per run (`Random -Max 50000`) |

## Behavioral (domain-independent)
| Pattern | Regex | Channel |
|---------|-------|---------|
| Staged download | `^l\.\d+\.ns\.` | agent retrieval |
| Command beacon | `^c\.\d+-\d+\.\d+\.ns\.` | tasking poll |
| Result exfil | `^r\.[0-9a-f.]+` | hex-encoded output |
| Host process | `powershell.exe` -> `nslookup.exe` (repeated) | endpoint tell |
| Volumetric | >N DNS TXT queries to one 2LD per host per minute | tunneling heuristic |

## ATT&CK
T1071.004, T1572, T1132.001, T1140, T1059.001, T1105, T1048.003
