# Whisper Twice — CTF Writeup
**Challenge:** Whisper Twice | **Points:** 250 | **Category:** Forensics / Steganography  
**Flag:** `HackCTF{n0_0n3_h34rd_th3_gh0st_wh1sp3r_tw1c3}`

---

## Table of Contents
1. [Challenge Description](#1-challenge-description)
2. [First Look — What Do We Have?](#2-first-look--what-do-we-have)
3. [Stage 1 — Filesystem Recovery](#3-stage-1--filesystem-recovery)
   - 3.1 [Decompressing and Identifying the Image](#31-decompressing-and-identifying-the-image)
   - 3.2 [Mounting / Exploring with debugfs](#32-mounting--exploring-with-debugfs)
   - 3.3 [Recovering Deleted Files](#33-recovering-deleted-files)
   - 3.4 [Reading the Surviving Files](#34-reading-the-surviving-files)
4. [Stage 2 — PCAP Analysis & Beacon Decoding](#4-stage-2--pcap-analysis--beacon-decoding)
   - 4.1 [Initial Triage](#41-initial-triage)
   - 4.2 [Identifying the Beacon Traffic](#42-identifying-the-beacon-traffic)
   - 4.3 [Failed Attempt — NRZ / Old Scheme](#43-failed-attempt--nrz--old-scheme)
   - 4.4 [Manchester Decoding (Correct Approach)](#44-manchester-decoding-correct-approach)
   - 4.5 [Handling Retransmits](#45-handling-retransmits)
   - 4.6 [The Three Decoded Beacons](#46-the-three-decoded-beacons)
5. [Stage 3 — Vault Carving & Decryption](#5-stage-3--vault-carving--decryption)
   - 5.1 [Carving VLT1 Records from the Raw Image](#51-carving-vlt1-records-from-the-raw-image)
   - 5.2 [CRC Verification](#52-crc-verification)
   - 5.3 [AES Decryption — Which Beacon Opens Which Vault?](#53-aes-decryption--which-beacon-opens-which-vault)
6. [Stage 4 — Audio Steganography](#6-stage-4--audio-steganography)
   - 6.1 [Left Channel — Spectrogram Picture](#61-left-channel--spectrogram-picture)
   - 6.2 [Failed Attempt — Wrong Channel Order / No Reversal](#62-failed-attempt--wrong-channel-order--no-reversal)
   - 6.3 [Right Channel — LSB Payload Extraction](#63-right-channel--lsb-payload-extraction)
   - 6.4 [XOR Decryption and the Decoy](#64-xor-decryption-and-the-decoy)
7. [Summary of the Full Chain](#7-summary-of-the-full-chain)
8. [Key Files and Values](#8-key-files-and-values)

---

## 1. Challenge Description

> A drive was pulled from an air-gapped lab. The operator ran `rm` and shut the machine down.  
> Everything he exfiltrated left as DNS chatter. Everything he stored is "gone".  
> Three hosts were talking that night. Only one of them was telling the truth.
>
> 💡 Hint: Two of the three vaults open, but only one picture tells the truth

We receive a single file: `1792935412801_evidence_img.gz`

The challenge has four layers:
1. A forensic disk image (ext4) with a deleted file
2. A PCAP of DNS traffic carrying a covert beacon
3. Encrypted vaults hidden in the raw image
4. Audio steganography inside the decrypted WAV files

---

## 2. First Look — What Do We Have?

The uploaded file is a gzip archive. The filename suffix `_evidence_img.gz` strongly hints at a disk image. Standard approach: decompress, `file` to identify, then plan.

```bash
stat -c '%s bytes' 1792935412801_evidence_img.gz
# 1224477 bytes

file 1792935412801_evidence_img.gz
# gzip compressed data, was "evidence.img", last modified: Tue Oct 20 04:15:15 2026
```

Original file was named `evidence.img`. The modification timestamp (2026-10-20 04:15:15 UTC) will turn out to match every inode in the image — the operator created this image right before wiping.

---

## 3. Stage 1 — Filesystem Recovery

### 3.1 Decompressing and Identifying the Image

```bash
zcat 1792935412801_evidence_img.gz > evidence.img
file evidence.img
# Linux rev 1.0 ext4 filesystem data, UUID=b2e030e6-9628-4d5e-b8ef-21aed4e6f2db,
# volume name "EVIDENCE" (extents) (64bit) (large files) (huge files)
```

We have a 24 MB ext4 filesystem labelled **EVIDENCE**. It is not mounted anywhere, so we work on it directly with `debugfs` — the safest read-only tool for this scenario, and available without root.

### 3.2 Mounting / Exploring with debugfs

```bash
debugfs -R "ls -l" evidence.img
#       2   40755 (2)      0      0    1024  .
#       2   40755 (2)      0      0    1024  ..
#      11   40700 (2)      0      0   12288  lost+found
#      13   40755 (2)   1000   1000    1024  home

debugfs -R "ls -l /home" evidence.img
#      13   40755 (2)   1000   1000    1024  .
#       2   40755 (2)      0      0    1024  ..
#      14   40755 (2)   1000   1000    1024  op

debugfs -R "ls -l /home/op" evidence.img
#      14   40755 (2)   1000   1000    1024  .
#      13   40755 (2)   1000   1000    1024  ..
#      15  100644 (1)   1000   1000      48  .bash_history
#      16  100644 (1)   1000   1000  119446  capture.pcap
#      17  100644 (1)   1000   1000     475  lab_notes.txt
#      18  100644 (1)   1000   1000      84  notes_old.txt
```

Four live files under `/home/op`. The user is named `op` (operator). 

### 3.3 Recovering Deleted Files

A key feature of `debugfs` is `lsdel`, which lists deleted inodes that still have their block pointers intact:

```bash
debugfs -R "lsdel" evidence.img
#  Inode  Owner  Mode    Size        Blocks   Time deleted
#     19   1000 100644  1172415   1145/  1145  Tue Oct 20 04:15:15 2026
# 1 deleted inodes found.
```

Inode 19, deleted at **04:15:15** (one second after the image's create time), is 1,172,415 bytes — roughly 1.1 MB. This is the `vault.bin` that `.bash_history` tells us the operator deleted:

```
ls
cd /tmp
rm -f vault.bin
sudo shutdown -h now
```

We dump it with `debugfs`:

```bash
debugfs -R "dump <19> vault_recovered.bin" evidence.img
file vault_recovered.bin
# DOS executable (COM)  ← debugfs dumps raw blocks; file(1) sees random bytes
```

The first few bytes look like binary noise, which is expected — it is an encrypted blob, not a filesystem or executable. We save it and come back later. The block extents for inode 19 are at disk blocks 1904–3048, which means the data starts at byte offset `1904 × 512 = 975,872` in the raw image. This fact matters when we carve the image later.

### 3.4 Reading the Surviving Files

We dump all four live files and read them:

```bash
debugfs -R "dump /home/op/.bash_history .bash_history" evidence.img
debugfs -R "dump /home/op/lab_notes.txt lab_notes.txt" evidence.img
debugfs -R "dump /home/op/notes_old.txt notes_old.txt" evidence.img
debugfs -R "dump /home/op/capture.pcap capture.pcap" evidence.img
```

**`.bash_history`:**
```
ls
cd /tmp
rm -f vault.bin
sudo shutdown -h now
```

The operator worked in `/tmp`, deleted `vault.bin`, and powered off. Simple and clean. The vault was in `/tmp`, which is why there is no live inode for it under a home directory path.

**`notes_old.txt`:**
```
old scheme (abandoned): stride 5 from 512, key = md5(word), plain NRZ gaps 0.2/0.55
```

This is a **red herring / dead end** — an old protocol the operator abandoned. I initially tried to implement this (see §4.3 below).

**`lab_notes.txt`** — the critical document:
```
vault layout: 'VLT1' | salt(16) | len(be32) | ct | crc32(salt||ct)   (crc alone proves nothing)
cipher: aes-256-cbc, iv = salt, key = sha256( beacon16 || salt ), then zlib
beacon: dns gaps, manchester. short->long = 1, long->short = 0. skip the sync pause. ignore retransmits.
inner: left ear = picture (played backwards, my bad). right ear: header 'FNL!' + be16 len + data,
       one bit per sample, stride 7 starting at 1000. data ^= the word from the picture, repeating.
```

This one note specifies the entire protocol chain. Let's break it down:

| Part | Description |
|------|-------------|
| Vault structure | Magic `VLT1` + 16-byte salt + 4-byte big-endian length + ciphertext + CRC32(salt \|\| ciphertext) |
| Encryption | AES-256-CBC; IV = salt; key = SHA-256(beacon16-bytes \|\| salt) |
| Post-decrypt | zlib decompress |
| Beacon | Encoded in DNS query timing gaps; Manchester encoding; skip sync pause; ignore retransmits |
| Inner payload | Two-channel WAV: left = spectrogram picture (played backwards); right = LSB data, stride 7 from sample 1000, XOR'd with the picture word |

The phrase **"my bad"** next to "played backwards" tells us the operator made a mistake when embedding — the image is stored reversed. That matters a lot in §6.

---

## 4. Stage 2 — PCAP Analysis & Beacon Decoding

### 4.1 Initial Triage

```bash
file capture.pcap
# pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)
```

We parse the pcap manually in Python (no Scapy available in this environment, just the standard library):

```python
import struct, collections

d = open('capture.pcap', 'rb').read()
off = 24  # global header is 24 bytes
rows = []
while off < len(d):
    ts, us, cl, ol = struct.unpack('<IIII', d[off:off+16])
    off += 16
    p = d[off:off+cl]
    off += cl
    src = p[26:30]
    ip = '.'.join(map(str, src))
    dns_id = struct.unpack('>H', p[42:44])[0]
    # parse QNAME at byte 54
    i = 54; parts = []
    while p[i]:
        l = p[i]; parts.append(p[i+1:i+1+l].decode()); i += l + 1
    rows.append((ts + us/1e6, ip, dns_id, '.'.join(parts)))
```

**Total packets:** 1,269  
**Three source IPs:** `10.13.37.5`, `10.13.37.6`, `10.13.37.7`

Query breakdown per host:

| Source IP | Domain | Count |
|-----------|--------|-------|
| 10.13.37.5 | cdn-sync.net | 28 |
| 10.13.37.5 | mail.corp.local | 24 |
| 10.13.37.5 | ntp.pool.net | 31 |
| 10.13.37.5 | time.example.org | 28 |
| 10.13.37.5 | **update.cdn-sync.net** | **285** |
| 10.13.37.5 | wpad.corp.local | 32 |
| 10.13.37.6 | cdn-sync.net | 24 |
| 10.13.37.6 | mail.corp.local | 23 |
| 10.13.37.6 | ntp.pool.net | 22 |
| 10.13.37.6 | time.example.org | 20 |
| 10.13.37.6 | **update.cdn-sync.net** | **295** |
| 10.13.37.6 | wpad.corp.local | 23 |
| 10.13.37.7 | cdn-sync.net | 30 |
| 10.13.37.7 | mail.corp.local | 28 |
| 10.13.37.7 | ntp.pool.net | 23 |
| 10.13.37.7 | **telemetry.cdn-sync.net** | **289** |
| 10.13.37.7 | time.example.org | 26 |
| 10.13.37.7 | wpad.corp.local | 38 |

The noise domains (`mail.corp.local`, `time.example.org`, `ntp.pool.net`, `wpad.corp.local`, `cdn-sync.net`) are cover traffic — they appear on every host with similar counts.

The **beacon domains** are the outliers:
- `.5` and `.6`: `update.cdn-sync.net` (~285–295 queries each)
- `.7`: `telemetry.cdn-sync.net` (~289 queries)

Notice that `.7` uses a **different subdomain** from the other two. This is our first hint that `.7` may be a different entity.

### 4.2 Identifying the Beacon Traffic

`lab_notes.txt` says the beacon is encoded in **DNS inter-query timing gaps**. The gap distribution for each host's beacon stream looks like:

```
sorted unique gaps (sample):
[0.27, 0.28, 0.29, 0.30, 0.31, 0.32, 0.33,   ← "short" gaps (~0.27–0.33 s)
 0.42, 0.43, 0.44, 0.45, 0.46, 0.47, 0.48]   ← "long" gaps (~0.42–0.48 s)
```

There are clearly only two gap classes, which is exactly what Manchester encoding needs. The spread within each class (~0.06 s) is timing jitter.

### 4.3 Failed Attempt — NRZ / Old Scheme

My first instinct, before carefully reading both notes files, was to look at `notes_old.txt`:

```
old scheme (abandoned): stride 5 from 512, key = md5(word), plain NRZ gaps 0.2/0.55
```

I initially tried to decode the beacon using **NRZ** (non-return-to-zero): gaps near 0.2 s = 0, gaps near 0.55 s = 1. But the gap values in the capture are **0.27–0.33** and **0.42–0.48**, which don't match 0.2/0.55 at all. I got garbage output. This was the abandoned old scheme, clearly documented — don't implement the notes_old.txt protocol.

### 4.4 Manchester Decoding (Correct Approach)

`lab_notes.txt` specifies:
- **Manchester encoding**: `short→long = 1`, `long→short = 0`
- **Skip the sync pause** (gap > 1.0 s at the very beginning)
- **Ignore retransmits**

Manchester encoding reads gaps **in pairs** (a transition). Each pair of consecutive gaps encodes one bit:

| Pair pattern | Bit |
|---|---|
| `short` then `long` (s→l) | `1` |
| `long` then `short` (l→s) | `0` |

Classification thresholds (empirical): gaps < 0.38 s → "short" (`s`), gaps > 0.38 s → "long" (`l`), gaps > 1.0 s → sync pause (`S`).

Classified gap string for `.5` (first 50 after sync):
```
slsllslsslslsllslslslslslssllssllslslssllslssl...
```

Reading pairs: `sl`=1, `ls`=0, `sl`=1, `ls`=0, etc.

### 4.5 Handling Retransmits

`lab_notes.txt` says "ignore retransmits." In the pcap, retransmits appear as a second DNS query with the **same DNS transaction ID** and a very short gap (< 50 ms). If we include them, the gap sequence gets corrupted.

**Wrong approach (what happens if you forget this step):** retransmit pairs inject spurious sub-10ms gaps which break the classification entirely — you'd see lots of "short, short" pairs with no Manchester meaning.

**Correct approach:** deduplicate by DNS ID, keeping the first occurrence only. After deduplication, each beacon stream has exactly 257 gaps per host (one sync gap + 256 data gaps = 128 bits = 16 bytes).

```python
def uniq(ip, name):
    rs = [r for r in rows if r[1] == ip and r[3] == name]
    u = []
    for r in rs:
        # discard if same DNS ID as previous AND <50ms later (retransmit)
        if u and r[2] == u[-1][2] and r[0] - u[-1][0] < 0.05:
            continue
        u.append(r)
    return u
```

### 4.6 The Three Decoded Beacons

Full decode script:

```python
def decode_beacon(ip, name):
    u = uniq(ip, name)
    gaps = [b[0] - a[0] for a, b in zip(u, u[1:])]
    # skip sync (first gap is ~1.5 s)
    cls = []
    for g in gaps[1:]:
        cls.append('s' if g < 0.38 else 'l')
    # Manchester: pairs
    bits = ''
    for a, b in zip(cls[0::2], cls[1::2]):
        bits += '1' if (a, b) == ('s', 'l') else '0'
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
```

| Host | Beacon (hex) |
|------|-------------|
| 10.13.37.5 | `ce0513ae8d021d81fb72b52b827c444d` |
| 10.13.37.6 | `ee2afaf24ddd37989f4a630e0ed20734` |
| 10.13.37.7 | `7640a9d379f2042e2ce88c50b1c25c1b` |

Each is exactly 16 bytes — the `beacon16` value that goes into the vault key derivation.

---

## 5. Stage 3 — Vault Carving & Decryption

### 5.1 Carving VLT1 Records from the Raw Image

The vault format starts with the magic bytes `VLT1`. We scan the entire raw image for this magic:

```python
import re
d = open('evidence.img', 'rb').read()
for m in re.finditer(b'VLT1', d):
    o = m.start()
    # format: VLT1 | salt(16) | len(be32) | ...
    L = int.from_bytes(d[o+20:o+24], 'big')
    print(hex(o), L)
```

Hits:
| Offset | Size (bytes) | Note |
|--------|-------------|------|
| 1,947,663 | — | Inside the `lab_notes.txt` string literal (`'VLT1'` appears in the text) — not a real vault |
| 1,952,697 | 5,008 | Real vault candidate |
| 1,958,510 | 4,112 | Real vault candidate |
| 1,964,150 | 574,944 | Real vault candidate |
| 2,541,171 | 580,400 | Real vault candidate |

The first hit is a false positive — it's the literal text in `lab_notes.txt`. The remaining four are real vault records.

### 5.2 CRC Verification

`lab_notes.txt` says `crc32(salt || ct)` is appended after the ciphertext. We verify each:

```python
import zlib, struct

def verify(o):
    salt = d[o+4:o+20]
    L = int.from_bytes(d[o+20:o+24], 'big')
    ct = d[o+24:o+24+L]
    crc_stored = int.from_bytes(d[o+24+L:o+28+L], 'big')
    crc_calc = zlib.crc32(salt + ct) & 0xffffffff
    return crc_calc == crc_stored
```

| Offset | CRC OK? |
|--------|---------|
| 1,952,697 | ❌ No |
| 1,958,510 | ✅ Yes |
| 1,964,150 | ✅ Yes |
| 2,541,171 | ✅ Yes |

The note in `lab_notes.txt` — **"crc alone proves nothing"** — is a warning that a valid CRC doesn't mean the vault is real (decoys can have valid CRCs too). It just rules out corruption. The corrupted vault at 1,952,697 is almost certainly an intentional decoy with a broken checksum.

### 5.3 AES Decryption — Which Beacon Opens Which Vault?

Key derivation per `lab_notes.txt`:
```
key = sha256(beacon16 || salt)
iv  = salt
cipher = AES-256-CBC
then zlib-decompress the plaintext
```

```python
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def try_decrypt(beacon, salt, ct):
    key = hashlib.sha256(beacon + salt).digest()
    cipher = Cipher(algorithms.AES(key), modes.CBC(salt)).decryptor()
    pt = cipher.update(ct) + cipher.finalize()
    # strip PKCS#7 padding
    pad = pt[-1]
    if 1 <= pad <= 16:
        pt = pt[:-pad]
    try:
        return zlib.decompress(pt)
    except:
        return None
```

I tried every (beacon × vault) combination — 3 beacons × 3 valid-CRC vaults = 9 attempts:

| Vault offset | Beacon (host) | Result |
|---|---|---|
| 1,958,510 | .5 | ❌ |
| 1,958,510 | .6 | ❌ |
| 1,958,510 | .7 | ❌ |
| 1,964,150 | **.5** | ✅ RIFF....WAVEfmt (WAV!) |
| 1,964,150 | .6 | ❌ |
| 1,964,150 | .7 | ❌ |
| 2,541,171 | .5 | ❌ |
| 2,541,171 | .6 | ❌ |
| 2,541,171 | **.7** | ✅ RIFF....WAVEfmt (WAV!) |

The vault at 1,958,510 opened with none of the three beacons. This is likely a red herring vault with a valid CRC but no matching beacon in this capture.

**Result:**
- Host **10.13.37.5**'s beacon decrypts vault at offset **1,964,150** → WAV file (960,044 bytes)
- Host **10.13.37.7**'s beacon decrypts vault at offset **2,541,171** → WAV file (960,044 bytes)
- Host **10.13.37.6**'s beacon opens nothing — it is a decoy host

The hint says **"two of the three vaults open"** — confirmed. Now we have two WAV files.

---

## 6. Stage 4 — Audio Steganography

Both WAV files have identical parameters:
- **Channels:** 2 (stereo)
- **Sample rate:** 22,050 Hz
- **Bit depth:** 16-bit signed PCM
- **Frames:** 240,000 (≈10.88 seconds)

`lab_notes.txt` describes two independent hiding techniques, one per channel.

### 6.1 Left Channel — Spectrogram Picture

> *"left ear = picture (played backwards, my bad)"*

The left channel, when reversed and viewed as a **spectrogram**, reveals text.

```python
import numpy as np
from scipy import signal
from PIL import Image
import wave

for tag, path in [('A', 'vault_host5.wav'), ('B', 'vault_host7.wav')]:
    w = wave.open(path)
    a = np.frombuffer(w.readframes(w.getnframes()), dtype='<i2').reshape(-1, 2)
    left = a[:, 0].astype(float)[::-1]       # ← reversed

    freq, t, Sxx = signal.spectrogram(left, 22050, nperseg=512, noverlap=384)
    Sxx_log = np.log10(Sxx + 1e-3)
    Sxx_norm = (Sxx_log - Sxx_log.min()) / (Sxx_log.max() - Sxx_log.min())
    img = (np.flipud(Sxx_norm) * 255).astype(np.uint8)
    Image.fromarray(img).save(f'spec_{tag}.png')
```

**Results:**
- Vault from host **.5**: spectrogram reads **`prap`**
- Vault from host **.7**: spectrogram reads **`LURE42`**

### 6.2 Failed Attempt — Wrong Channel Order / No Reversal

Before reading `lab_notes.txt` closely, I first tried:

1. **Spectrogram of the left channel without reversal** — the image appears mirrored in time and the text is completely unreadable (shows as a smear).
2. **Right channel spectrogram** — random noise, nothing legible.
3. **Left channel without time-reversal, with different spectrogram parameters** — still unreadable.

The critical fix was the reversal (`[::-1]`). The operator encoded it by playing the audio backwards — the note literally says "played backwards, my bad." Without reversing, every test produced garbage.

4. I also tried checking whether the "picture" might be an actual image file hidden in the raw PCM bytes (e.g., PNG/JPEG header scan) — nothing found. The picture is purely spectral.

### 6.3 Right Channel — LSB Payload Extraction

> *"right ear: header 'FNL!' + be16 len + data, one bit per sample, stride 7 starting at 1000. data ^= the word from the picture, repeating."*

- Extract the **right channel** samples
- Take **1 bit per sample**, using **every 7th sample** starting at **sample index 1000** (i.e., samples 1000, 1007, 1014, …)
- The bit is the **LSB** (least significant bit) of each sample
- Assemble bits into bytes
- The resulting byte stream starts with magic `FNL!` then a big-endian uint16 length, then `length` bytes of data (XOR'd with the picture word)

```python
right = a[:, 1]
bits = (right[1000::7] & 1)    # stride 7, starting at index 1000, LSB only

def unpack_bits(bits):
    n = len(bits) // 8
    return np.packbits(bits[:n*8]).tobytes()

payload_raw = unpack_bits(bits)
assert payload_raw[:4] == b'FNL!'
length = int.from_bytes(payload_raw[4:6], 'big')
data = payload_raw[6:6+length]
```

| Vault (host) | FNL! found? | Length | Raw data (hex) |
|---|---|---|---|
| .5 | ✅ | 45 bytes | `3813021b3326270b1e423e401e413e18434613142f0609432f15094003063e071843120043003e04074302430d` |
| .7 | ✅ | 33 bytes | `0f01143e405a7d260d320041132162756b0178262b1a5f017f250d22040322322f` |

### 6.4 XOR Decryption and the Decoy

Each payload is XOR'd with the picture word (repeating). We try both picture words on both payloads:

```python
def xor_key(data, key):
    key = key.encode()
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))
```

| Payload from | Key word | Result |
|---|---|---|
| Host .5 | `prap` | **`HackCTF{n0_0n3_h34rd_th3_gh0st_wh1sp3r_tw1c3}`** |
| Host .5 | `LURE42` | binary garbage |
| Host .7 | `LURE42` | `CTF{th1s_w4s_t00_34sy_k33p_g01ng}` ← **DECOY** |
| Host .7 | `prap` | binary garbage |

The decoy from host .7 produces a plausible-looking CTF flag but is missing the `HackCTF` prefix and the text itself says `th1s_w4s_t00_34sy_k33p_g01ng` — it's bait.

The hint — **"only one picture tells the truth"** — refers to this: both vaults have valid payloads, but only the `.5` vault contains the real flag.

Host `.7` is the liar. Its beacon is real (it opens a vault), but the vault contains a carefully crafted decoy to mislead.

---

## 7. Summary of the Full Chain

```
evidence_img.gz
     │
     ▼ zcat
evidence.img (ext4, 24 MB)
     │
     ├─ /home/op/lab_notes.txt    ← full protocol spec
     ├─ /home/op/notes_old.txt    ← red herring (abandoned scheme)
     ├─ /home/op/.bash_history    ← confirms rm -f vault.bin
     ├─ /home/op/capture.pcap    ← DNS beacon traffic
     └─ inode 19 (deleted)        ← raw bytes with embedded VLT1 vaults
          │
          ▼ scan for VLT1 magic
          4 vault records (1 corrupted CRC, 1 unreachable, 2 valid)
                │
                ▼ capture.pcap
                3 hosts (10.13.37.5, .6, .7) → beacon domains
                     │ deduplicate by DNS ID
                     │ classify gaps (< 0.38 s = short, ≥ 0.38 s = long)
                     │ skip sync pause (> 1.0 s)
                     │ Manchester decode (pairs: sl=1, ls=0)
                     ▼
                3 × 16-byte beacons
                     │ sha256(beacon || salt) → AES key
                     │ AES-256-CBC(key, iv=salt) + zlib
                     ▼
                2 decrypted WAV files (one per host .5 and .7)
                     │
                     ├─ LEFT channel (reversed) → spectrogram → picture word
                     │       .5: "prap"
                     │       .7: "LURE42"
                     │
                     └─ RIGHT channel → LSB[1000::7] → FNL! payload
                             │ XOR with picture word
                             ▼
                         .5: HackCTF{n0_0n3_h34rd_th3_gh0st_wh1sp3r_tw1c3} ← REAL
                         .7: CTF{th1s_w4s_t00_34sy_k33p_g01ng}              ← DECOY
```

---

## 8. Key Files and Values

| Item | Value |
|------|-------|
| Filesystem UUID | `b2e030e6-9628-4d5e-b8ef-21aed4e6f2db` |
| Volume label | `EVIDENCE` |
| Operator username | `op` |
| Deleted inode | 19 (1,172,415 bytes) |
| Beacon host .5 | `ce0513ae8d021d81fb72b52b827c444d` |
| Beacon host .6 | `ee2afaf24ddd37989f4a630e0ed20734` (opens nothing) |
| Beacon host .7 | `7640a9d379f2042e2ce88c50b1c25c1b` |
| Vault offsets in image | 1,952,697 (bad CRC) / 1,958,510 (no beacon) / **1,964,150** (real) / **2,541,171** (decoy) |
| WAV parameters | 22,050 Hz, 16-bit, stereo, 240,000 frames |
| Picture word (.5) | `prap` |
| Picture word (.7) | `LURE42` |
| FNL! payload length (.5) | 45 bytes |
| FNL! payload length (.7) | 33 bytes |
| **Flag** | **`HackCTF{n0_0n3_h34rd_th3_gh0st_wh1sp3r_tw1c3}`** |

---

*Tools used: `debugfs`, `zlib` (Python stdlib), `hashlib` (Python stdlib), `cryptography` (Python), `numpy`, `scipy.signal`, `wave` (Python stdlib), `Pillow`*
