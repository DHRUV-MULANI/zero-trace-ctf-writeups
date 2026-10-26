# Pauses Speak Louder — Full Writeup

**Event:** HackCTF (Hacklido) | **Category:** Forensics / Network / Covert Channel / Crypto / Stego | **Points:** 200

**Flag:** `HackCTF{t1m1ng_1s_3v3ryth1ng_gh0st_pr0t0c0l}`

---

## 1. Challenge

> Our IDS captured two minutes of traffic from a compromised workstation. Nobody saw anything leave.
> The attacker used no exploit kit, no known C2, and no encryption you can spot in the wire. Recover what was exfiltrated.
>
> Hint: *The message is in the packets. The key is in the pauses.*

**File:** `capture.pcap` (185,843 bytes, pcap v2.4, Ethernet)

### What the hint tells us

| Hint fragment | Meaning |
|---|---|
| "The message is in the packets" | Some packet **content** (payload) carries the data |
| "The key is in the pauses" | A **timing covert channel** (inter-packet delays) carries the key |
| "no encryption you can spot" | The payload is encrypted, but looks like random noise; the key is *not* in the payload |

So the expected solve path is: find the timing channel, decode the key, use it on the packet payloads.

---

## 2. TL;DR Solve Chain

```
capture.pcap
 ├─ DNS queries from 10.13.37.5 to update.cdn-sync.net
 │     └─ gap between queries: ~0.2s = 0, ~0.55s = 1  ──► 128 bits ──► AES-128 KEY
 └─ ICMP echo requests from 10.13.37.5
       └─ payload = [2-byte index][900 bytes data]
             └─ order by index, strip index ──► 46,128 bytes ciphertext
                   └─ AES-128-CBC (IV = first 16 bytes, key from timing)
                         └─ zlib stream (78 da) ──► 46,080 bytes of "noise"
                               └─ bit-plane 0 (LSB) reshaped 96 x 480
                                     └─ XOR with row parity ──► bitmap text ──► FLAG
```

---

## 3. Environment and Tools

- Python 3 with `scapy`, `pycryptodome`, `numpy`, `Pillow`
- No Wireshark/tshark was available in my sandbox, so everything was done with scapy.

```bash
pip install scapy pycryptodome numpy pillow --break-system-packages
```

---

## 4. Step 1 — Triage the capture

### 4.1 Basic info

```bash
file capture.pcap
# pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

### 4.2 Flow summary

```python
from scapy.all import *
from collections import Counter

pk = rdpcap('capture.pcap')
print(len(pk))                       # 564 packets
c = Counter()
for p in pk:
    if IP in p:
        proto = 'TCP' if TCP in p else 'UDP' if UDP in p else 'ICMP' if ICMP in p else str(p[IP].proto)
        dport = p[TCP].dport if TCP in p else p[UDP].dport if UDP in p else 0
        c[(p[IP].src, p[IP].dst, proto, dport)] += 1
for k, v in c.most_common():
    print(v, k)
print(pk[0].time, pk[-1].time)       # ~100 seconds of traffic
```

Result:

| Count | Source | Destination | Protocol |
|---:|---|---|---|
| 187 | 10.13.37.5 | 10.13.37.53 | UDP/53 (DNS) |
| 170 | 10.13.37.6 | 10.13.37.53 | UDP/53 (DNS) |
| 51 | 10.13.37.7 | 10.13.37.53 | UDP/53 (DNS) |
| 52 | 10.13.37.5 | 10.13.37.99 | ICMP |
| 52 | 10.13.37.6 | 10.13.37.99 | ICMP |
| 52 | 10.13.37.7 | 10.13.37.99 | ICMP |

Observations:

- Only two protocols: **DNS** and **ICMP echo**. No TCP, no HTTP, no TLS. Nothing "looks" like exfiltration.
- Three hosts, so likely **one real channel and two decoys**.
- `10.13.37.5` and `10.13.37.6` send a lot more DNS than `.7`.
- Every host sends exactly 52 ICMP packets, which is suspicious (uniform, generated).

---

## 5. Step 2 — Inspect DNS

### 5.1 Query names per host

```python
for src in ['10.13.37.5', '10.13.37.6', '10.13.37.7']:
    print('=====', src)
    n = 0
    for p in pk:
        if IP in p and p[IP].src == src and UDP in p:
            q = p[DNS].qd.qname.decode()
            print(round(float(p.time) - 1760000000, 4), q)
            n += 1
            if n > 25: break
```

Findings:

- `.5` and `.6` both repeatedly query **`update.cdn-sync.net`** (129 queries each), interleaved with background names (`time.example.org`, `wpad.corp.local`, `ntp.pool.net`, `mail.corp.local`).
- `.7` only queries background names. It's pure noise.
- The suspicious domain name is always identical, so **the data is not in the name**. All DNS packets are 79 bytes.

### 5.2 Check header fields for hidden data

I dumped DNS ID, UDP source port, IP ID, TTL, TOS, flags and qtype for the 129 queries from `.5`:

```python
rows = []
for p in pk:
    if IP in p and p[IP].src == '10.13.37.5' and UDP in p and p[DNS].qd \
       and p[DNS].qd.qname == b'update.cdn-sync.net.':
        rows.append((float(p.time) - 1760000000, p[DNS].id, p[UDP].sport,
                     p[IP].id, p[IP].ttl, p[IP].tos, p[DNS].qd.qtype, len(p)))
```

- DNS ID and source port: uniformly random, no structure (decoded as bytes → junk).
- IP ID = 1, TTL = 64, TOS = 0, qtype = A, length = 79 for all.

**Conclusion:** DNS headers carry no data. The only remaining variable is **time**, which matches the hint ("the key is in the pauses").

---

## 6. Step 3 — Analyse inter-arrival times (the timing channel)

Compute the gap between consecutive `update.cdn-sync.net` queries from each of `.5` and `.6`:

```python
import collections

for src in ['10.13.37.5', '10.13.37.6']:
    ts = [float(p.time) for p in pk
          if IP in p and p[IP].src == src and UDP in p and p[DNS].qd
          and p[DNS].qd.qname == b'update.cdn-sync.net.']
    d = [round(b - a, 3) for a, b in zip(ts, ts[1:])]
    print(src, len(ts), 'queries ->', len(d), 'gaps')
    print(sorted(collections.Counter(round(x, 1) for x in d).items()))
```

| Host | Gap distribution |
|---|---|
| `10.13.37.5` | **Bimodal**: ~0.16–0.24 s (61 gaps at 0.2) and ~0.51–0.59 s (67 gaps at 0.5/0.6). Nothing in between. |
| `10.13.37.6` | **Uniform/continuous** from 0.15 to 0.6 s. Looks like random jitter. |

So:

- **`.5` = real covert timing channel** (two-symbol: short vs long).
- **`.6` = decoy** that mimics the same traffic with random timing.

129 queries gives **128 gaps = 128 bits = 16 bytes**. That size matches an **AES-128 key** exactly (a good sign it's a key, as the hint says).

### 6.1 Decoding the bits

Threshold at 0.37 s (the midpoint of the empty gap between 0.24 and 0.51):

```python
ts = [float(p.time) for p in pk
      if IP in p and p[IP].src == '10.13.37.5' and UDP in p and p[DNS].qd
      and p[DNS].qd.qname == b'update.cdn-sync.net.']
gaps = [b - a for a, b in zip(ts, ts[1:])]
bits = ''.join('1' if g > 0.37 else '0' for g in gaps)
print(bits)
# 00000011000011010010010110011110011110111110001111101111111011001010010100010111100001001000100011001101101100011011101010110101

key = bytes(int(bits[i:i+8], 2) for i in range(0, 128, 8))
print(key.hex())
# 030d259e7be3efeca5178488cdb1bab5
```

Convention used: **short = 0, long = 1, MSB first**. Output is not readable text, which is consistent with it being a **binary key**, not the message.

---

## 7. Step 4 — Inspect the ICMP payloads (the "message")

```python
for src in ['10.13.37.5', '10.13.37.6', '10.13.37.7']:
    ch = {}
    for p in pk:
        if IP in p and p[IP].src == src and ICMP in p:
            ch[p[ICMP].seq] = bytes(p[ICMP].payload)
    print(src, len(ch), sorted(ch)[:3], sorted(ch)[-3:], set(len(v) for v in ch.values()))
    print(' index matches first 2 bytes:', all(int.from_bytes(ch[k][:2], 'big') == k for k in ch))
```

Findings:

- Each host: 52 echo requests, `seq` = 0..51.
- Payload is **902 bytes** for seq 0–50 and **230 bytes** for seq 51 (last chunk).
- The first **2 bytes of the payload equal the sequence number** (big-endian). This is a chunk index.
- The remaining bytes (900 + 228) are high entropy (~7.996 bits/byte).
- **Arrival order is shuffled** relative to `seq`, so the data must be reassembled by index, not by time.
- ICMP `id` is `0x4748` for `.5`/`.6` and `0x4749` for `.7` (not useful).

Reassembly:

```python
ch = {p[ICMP].seq: bytes(p[ICMP].payload) for p in pk
      if IP in p and p[IP].src == '10.13.37.5' and ICMP in p}
ct = b''.join(ch[k][2:] for k in sorted(ch))
print(len(ct), len(ct) % 16)   # 46128, 0
```

**46,128 = 16 x 2,883.** The total is an exact multiple of the AES block size. For random data that's a 1-in-16 coincidence, which strongly suggests **block-cipher output** (AES-128 matches the 16-byte timing key).

All three hosts have identical sizes and similar entropy. The decoys are probably `os.urandom` of the same length, so I could not tell which host is real from entropy alone. The timing key came from `.5`, so `.5` was the natural candidate.

---

## 8. Step 5 — Everything I tried (including dead ends)

This is the honest path, not just the final answer.

### 8.1 Dead end A: the timing bits are the message

I tried decoding the 128 bits directly as text with many framings:

- 5/6/7/8-bit groups, every start offset (0..w-1), normal and inverted, MSB- and LSB-first
- Differential decoding (bit = "did the symbol change")
- Manchester decoding

Everything produced junk. Reason: it is a **key**, not text.

### 8.2 Dead end B: simple XOR / printable-text check

XOR of the ICMP data with the 16-byte key (repeating), scoring by "fraction of printable ASCII" → nothing.

### 8.3 Dead end C: AES modes scored by printable text or file magic

I tried AES-ECB, CBC (zero IV), CBC (IV = first block), CTR with all 4 bit-conventions of the key (normal/inverted x MSB/LSB first), against all three hosts' data (both "strip index" and "full payload"), and scoring by:

- printable ratio > 0.7
- magic numbers (`PNG`, `PK`, `%PDF`, `JFIF`, `GIF8`, gzip, `HackCTF`, ...)
- lowest entropy of the first 4 KB

No hits. This is where it got misleading: the right decryption returned a **zlib stream**, whose first block is `78 da` and whose body is high-entropy, so none of my content-based detectors fired.

### 8.4 Dead end D: more ciphers and key derivations

Also tried RC4, key hashed with MD5 / SHA-256 / SHA-1(16), key as hex string, ChaCha20 with SHA-256 key, ICMP in **time order** instead of sequence order, and reversed order. Still nothing, again because my detector was blind to compressed output.

### 8.5 The breakthrough: use PKCS7 padding validity as the oracle

Content-independent test: after decrypting, a correctly decrypted final block with PKCS7 padding ends in `n` copies of byte `n`. A random wrong key passes this with a chance of about 1/256 for pad `01`, and astronomically less for larger pads.

For CBC the plaintext blocks 1..N do not depend on the IV (`P_i = D(C_i) XOR C_(i-1)`), so I could check the padding without knowing the IV:

```python
from Crypto.Cipher import AES

def padok(b):
    n = b[-1]
    return 1 <= n <= 16 and b[-n:] == bytes([n]) * n

def cbc_tail_ok(key, c):
    n = len(c) // 16 * 16
    D = AES.new(key, AES.MODE_ECB).decrypt(c[:n])
    pt = b''.join(bytes(a ^ b for a, b in zip(D[i:i+16], c[i-16:i])) for i in range(16, n, 16))
    return padok(pt), pt[-32:]
```

Scanning all combinations produced exactly **one convincing hit**:

| Item | Value |
|---|---|
| Key | `030d259e7be3efeca5178488cdb1bab5` (host `.5` timing, MSB first, short=0, long=1) |
| Ciphertext | host `.5` ICMP data, **sequence order**, 2-byte index stripped |
| Mode | AES-128-CBC |
| Tail | `... 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b` (11 x `0x0b`) |

Eleven correct padding bytes by chance is about 2^-88. This confirms the whole pipeline (key derivation, ordering, mode). The other "hits" in the scan were pad value `01` (trivial 1/256 coincidences) on unrelated key/ciphertext pairs.

### 8.6 Finding the IV

Since CBC and the first block is unknown, I tried both common conventions:

- IV = 16 zero bytes → first block garbled (output only becomes sane from offset 16)
- **IV = first 16 bytes of the ciphertext (prepended IV)** → plaintext starts cleanly with `78 da`

So the ciphertext layout is `IV || AES-CBC(key, IV, plaintext)`.

```python
from Crypto.Util.Padding import unpad
pt = unpad(AES.new(key, AES.MODE_CBC, ct[:16]).decrypt(ct[16:]), 16)
print(len(pt), pt[:2].hex())    # 46101  78da
```

`78 da` is a **zlib header** (best compression level).

---

## 9. Step 6 — Decompress

```python
import zlib
raw = zlib.decompress(pt)       # the Adler-32 check passes, so decryption is fully correct
print(len(raw))                 # 46080
```

Result: **46,080 bytes** that still look like random noise:

- no file magic at the start, no `HackCTF` string
- per-KB entropy about 7.8 bits/byte (typical of random 1 KB windows)
- all 256 byte values present, chi-square about 257 (consistent with uniform)
- no repeated 16-byte blocks

The zlib stream gave essentially no size reduction (the data was incompressible), so zlib was just a wrapper.

Useful observation: `46080 = 160 x 96 x 3`, a plausible raw RGB frame (also `96 x 480`). That hinted at **image data / steganography**.

### 9.1 Dead end E: second encryption layer

I tried the same 16-byte key (and MD5/SHA-256 of it) on the 46,080 bytes with XOR, AES-ECB, CBC (zero IV and prepended IV), CTR and RC4. Nothing readable. No second encryption layer.

---

## 10. Step 7 — Steganography: bit-plane analysis

If this is a raw image with a hidden message, look at each bit-plane. For each plane I measured the mean and the "neighbour agreement" (probability that consecutive bits are equal; 0.5 = random):

```python
import numpy as np
raw = np.frombuffer(raw_bytes, dtype=np.uint8)
for b in range(8):
    plane = (raw >> b) & 1
    print(b, round(plane.mean(), 4), round(np.mean(plane[1:] == plane[:-1]), 4))
```

```
0 0.5019 0.972     <-- bit-plane 0 (LSB) is highly structured
1 0.4956 0.4998
2 0.4997 0.4977
3 0.4998 0.4997
4 0.5011 0.5014
5 0.498  0.5001
6 0.4968 0.5024
7 0.4961 0.5026
```

Planes 1–7 are random noise (the cover). **Plane 0 (LSB) has 97.2% neighbour agreement**, meaning long runs and therefore structure.

### 10.1 Run-length analysis of the LSB plane

```python
import itertools
lsb = (raw & 1).astype(int)
runs = [(k, len(list(g))) for k, g in itertools.groupby(lsb)]
print(runs[:12])
# [(0, 480), (1, 480), (0, 480), (1, 480), ...]   43 runs of exactly 480
```

- The first 43 runs are exactly **480 bits long and alternate 0/1**, so the image is **480 pixels wide**, and each row is solid 0 or solid 1 alternating (horizontal stripes). That means a `96 x 480` bitmap.
- After row 43, the runs become short and irregular: that's where the **text overlay** sits.

### 10.2 Render it

```python
from PIL import Image

img = (raw & 1).reshape(96, 480)
Image.fromarray(img * 255).save('lsb_raw.png')
```

Raw LSB image: striped background with text rows overlaid. Because the background alternates per row, the text is hard to see. **XOR out the row parity** to remove the stripes:

```python
mask = img ^ (np.arange(96) % 2)[:, None]
rows = np.where(mask.any(axis=1))[0]
cols = np.where(mask.any(axis=0))[0]
print(rows.min(), rows.max(), cols.min(), cols.max())    # 43 58 11 432
band = mask[rows.min():rows.max()+1, cols.min():cols.max()+1]
Image.fromarray(((1 - band) * 255).astype(np.uint8)) \
     .resize((band.shape[1] * 3, band.shape[0] * 6), Image.NEAREST).save('flag.png')
```

The text occupies rows 43–58 and columns 11–432. Upscaled, it reads:

```
HackCTF{t1m1ng_1s_3v3ryth1ng_gh0st_pr0t0c0l}
```

### 10.3 Disambiguating look-alike characters

Leetspeak flags have `1/l/I` and `0/O` ambiguities, so I cropped and enlarged specific regions of the bitmap:

- The `1` glyphs (in `t1m1ng`, `1s`, `3v3ryth1ng`) have a **flag at top-left and a flat base serif** → digit **1**.
- The `0` glyphs (in `gh0st`, `pr0t0c0l`) are **slashed/dotted** → digit **0**.
- The final character before `}` has a **curved foot with no base bar** → lowercase **l** (L).

---

## 11. Full Solve Script (copy-paste)

```python
#!/usr/bin/env python3
"""
Pauses Speak Louder — full solver
deps: pip install scapy pycryptodome numpy pillow
"""
import zlib
import numpy as np
from PIL import Image
from scapy.all import rdpcap, IP, UDP, ICMP, DNS
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

PCAP   = 'capture.pcap'
SENDER = '10.13.37.5'                 # host with bimodal timing + real ciphertext
DOMAIN = b'update.cdn-sync.net.'
THRESH = 0.37                         # midpoint of the empty gap between 0.24 s and 0.51 s

pk = rdpcap(PCAP)

# ---- 1. Timing channel -> 128-bit AES key ---------------------------------
ts = [float(p.time) for p in pk
      if IP in p and p[IP].src == SENDER and UDP in p
      and p[DNS].qd and p[DNS].qd.qname == DOMAIN]
gaps = [b - a for a, b in zip(ts, ts[1:])]
assert len(gaps) == 128, len(gaps)
bits = ''.join('1' if g > THRESH else '0' for g in gaps)
key = bytes(int(bits[i:i+8], 2) for i in range(0, 128, 8))
print('[+] key =', key.hex())          # 030d259e7be3efeca5178488cdb1bab5

# ---- 2. ICMP payloads -> ciphertext (order by index, strip 2-byte index) --
chunks = {p[ICMP].seq: bytes(p[ICMP].payload) for p in pk
          if IP in p and p[IP].src == SENDER and ICMP in p}
assert all(int.from_bytes(v[:2], 'big') == k for k, v in chunks.items())
ct = b''.join(chunks[k][2:] for k in sorted(chunks))
print('[+] ciphertext bytes =', len(ct), '(mod 16 =', len(ct) % 16, ')')

# ---- 3. AES-128-CBC, IV = first block, then PKCS7 unpad -------------------
pt = unpad(AES.new(key, AES.MODE_CBC, ct[:16]).decrypt(ct[16:]), 16)
print('[+] plaintext header =', pt[:2].hex())   # 78da -> zlib

# ---- 4. zlib ---------------------------------------------------------------
raw = np.frombuffer(zlib.decompress(pt), dtype=np.uint8)
print('[+] decompressed bytes =', len(raw))     # 46080

# ---- 5. LSB bit-plane -> 96x480 bitmap, remove row-stripe background -------
lsb  = (raw & 1).reshape(96, 480)
mask = lsb ^ (np.arange(96) % 2)[:, None]
rows = np.where(mask.any(axis=1))[0]
cols = np.where(mask.any(axis=0))[0]
band = mask[rows.min():rows.max()+1, cols.min():cols.max()+1]

img = Image.fromarray(((1 - band) * 255).astype(np.uint8))
img = img.resize((band.shape[1] * 3, band.shape[0] * 6), Image.NEAREST)
img.save('flag.png')
print('[+] open flag.png -> HackCTF{t1m1ng_1s_3v3ryth1ng_gh0st_pr0t0c0l}')
```

---

## 12. Challenge Design Summary (what the author built)

| Layer | Technique | Decoys / traps |
|---|---|---|
| Transport | DNS + ICMP only, nothing "malicious-looking" | Background DNS names; third host with only noise |
| Key channel | **DNS timing covert channel**: 0.2 s / 0.55 s gaps, 128 bits | Host `.6` sends the same domain with uniform random timing |
| Payload | **ICMP echo payloads**, 900-byte chunks, 2-byte index, shuffled arrival | All three hosts send same-size random-looking ICMP data |
| Crypto | **AES-128-CBC**, prepended IV, PKCS7 | Entropy is indistinguishable from random, so no obvious "this is the real one" signal |
| Compression | **zlib** wrapper | Hides all file magic and defeats printable/entropy detectors |
| Stego | **LSB bit-plane** of a 96 x 480 bitmap, striped background XOR | Cover bits in planes 1–7 are random noise |
| Encoding | Leetspeak flag in a pixel font | `1` vs `l`, `0` vs `O` ambiguity |

---

## 13. Lessons Learned

1. **Look at time as a data field.** Packet timing is invisible to payload-only inspection but trivially machine-readable.
2. **Decoys come in matched sets.** Same domain, same packet count, same sizes. Look for the distribution that is *non-random* (bimodal vs uniform).
3. **A 16-byte output is a key.** Don't try to read it as text.
4. **Don't rely on content heuristics to validate decryption.** Compressed or stego-bearing plaintext looks random. Use a **structure-based oracle** such as PKCS7 padding validity, which also works for CBC without knowing the IV.
5. **After "random" data, check bit-planes.** Differences in neighbour agreement between planes instantly reveal LSB stego.
6. **Use run-length of the structured plane to infer image width** (here, exact 480-bit runs).
7. **Zoom before submitting leetspeak flags.** Confirm `1`/`l` and `0`/`O` from the glyphs.

## 14. Detection and Defence Notes (real-world takeaways)

- Flag DNS clients querying a single rarely-used domain at a steady cadence; measure **inter-query timing entropy** and detect bimodal timing patterns.
- ICMP echo requests with ~900-byte payloads and index prefixes are anomalous. Limit ICMP payload size and inspect payload entropy.
- Egress filtering: restrict DNS to approved resolvers and rate-limit or alert on ICMP to internal hosts.
- The attacker used only "normal" protocols; behavioural/statistical monitoring, not signatures, is what would have caught this.

---

**Final flag:** `HackCTF{t1m1ng_1s_3v3ryth1ng_gh0st_pr0t0c0l}`
