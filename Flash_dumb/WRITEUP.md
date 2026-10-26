# Flash Dump — HackCTF (100 pts)

**Category:** Forensics / Hardware / Crypto-ish
**Artifact:** `flash.bin` (193 bytes)
**Flag:** `HackCTF{add1t1v3_c1ph3rs_4r3nt_x0r}`

---

## 1. Challenge Statement

> We pulled a raw region out of a field device's flash chip. It's clearly not plain text — looks scrambled — but there's a repeating rhythm to it, and the vendor isn't exactly famous for real cryptography. The on-call "break-glass" note is supposed to be in there. Read it.
>
> Flag format: `HackCTF{...}`

Key hints baked into the prompt:

- **"raw region ... flash chip"** → the file is a firmware/config dump, no container/header.
- **"looks scrambled"** → it is obfuscated, not compressed/encrypted with real crypto.
- **"repeating rhythm"** → the obfuscation uses a **repeating key / periodic pattern**.
- **"vendor isn't exactly famous for real cryptography"** → think XOR / ADD / ROT, not AES.
- **"break-glass note"** → the plaintext will contain a readable note with the flag.

---

## 2. Initial Recon — What the File Actually Looks Like

```bash
$ ls -la
-rw-r--r-- 1 boss boss 193 flash.bin

$ od -A x -t x1z flash.bin
000000 b1 c1 b2 bc bb b3 bc 92 c7 dd d6 d4 8f b2 93 e0  >................<
000010 99 9c 9f a2 93 98 99 94 79 e4 c8 cf d2 d3 dd ac  >.......y.......<
000020 83 dd dc c9 e1 d1 c6 d7 d7 ca d8 d9 6d d7 e0 d2  >............m...<
000030 d4 e4 9d 88 cf cd d4 de c7 95 dd c9 d2 da 6d d6  >..............m.<
000040 d8 d8 d4 ac 83 db cc d6 d0 e6 c6 d0 89 c5 e1 d7  >................<
000050 c4 94 89 d6 de e6 c4 dc ce c8 8f e9 c8 cd d4 d0  >................<
000060 e8 7c d5 cd cc d3 e5 d7 d5 e1 c8 c7 de e0 d7 c9  >.|..............<
000070 cc d8 a9 92 d2 d8 dc 91 d1 e4 cc cc d0 c9 79 d4  >..............y.<
000080 d5 cd ca cf ce d9 cf c9 dc d7 a9 92 ab c9 cc cf  >................<
000090 b2 c6 a9 e3 ca c8 d3 a3 d7 99 df 97 ce d5 94 d8  >................<
0000a0 d1 97 e1 e5 c2 9c db 97 dd e6 c2 e0 99 d6 ec 7c  >...............|<
0000b0 c6 d0 ce c7 da e5 d8 d5 a3 84 de dd 6d ad b7 a8  >............m...<
0000c0 79                                               >y<
```

Immediate observations:

- **193 bytes** — tiny. The whole plaintext is probably the note itself, or the note is a large region of it.
- Values are **mostly high** (`0x80`–`0xEC`), with only three bytes below `0x80`: `0x79`, `0x7c`, `0x6d`.
- Lots of repeated bytes (`0xd7`, `0xd8`, `0xdd`, `0xd4`, `0xc9`, `0xcc`), which is consistent with a low-entropy plaintext (English/ASCII) under a simple cipher.

The very first useful measurement:

```python
>>> data = open('flash.bin','rb').read()
>>> len(data), min(data), max(data)
(193, 0x6d, 0xec)
```

**`0xEC - 0x6D = 0x7F = 127`.** The entire ciphertext lives inside a **128-wide contiguous window**. For 193 essentially random bytes this is astronomically unlikely. This single fact was the most important clue in the whole challenge — it is revisited in Section 8.

---

## 3. First Guess: Single-Byte XOR (Failed)

Because "not famous for real cryptography" screams XOR, the first attempt was a single-byte XOR brute force, looking for the known flag prefix `HackCTF{`.

```python
for k in range(256):
    pt = bytes(b ^ k for b in data)
    if b'HackCTF' in pt or b'hackctf' in pt.lower():
        print(hex(k), pt)
```

No hit.

Next, a printable-ratio sweep of all 256 keys:

```python
for k in range(256):
    pt = bytes(b ^ k for b in data)
    print(k, sum(32 <= c < 127 for c in pt))
```

Best keys produced letter soup, never English. **Single-byte XOR was dead.**

Why it looked plausible but wasn't: a single-byte XOR of ASCII text would keep the high bit constant (all `0x00`–`0x7F` or all `0x80`–`0xFF`). Our data had exactly three sub-`0x80` bytes interspersed among high bytes, and a 128-wide but *not* printable range. That smell was already there; we noted it and moved on.

---

## 4. Second Guess: Repeating-Key XOR + Period Detection

The hint "repeating rhythm" points at a repeating key. So the next job was to find the period.

### 4.1 Byte-level autocorrelation

For a repeating-key XOR with period `L`, we have

```
C[i] ^ C[i+L] = P[i] ^ P[i+L]
```

so at a multiple of the key length the "difference sequence" should look like plaintext-vs-plaintext, i.e. low entropy / many small values. We computed, for each shift `s`, the fraction of `C[i] ^ C[i+s]` bytes below `0x20`:

```python
for s in range(1, 65):
    xs = bytes(data[i] ^ data[i+s] for i in range(len(data)-s))
    print(s, sum(x < 0x20 for x in xs) / len(xs))
```

Result: shift **6** had the strongest signal (`~48%` small values), followed by 12, 18, 24 — all multiples of 6.

### 4.2 Bit-level autocorrelation (more sensitive)

Treating the file as a 1544-bit stream and measuring bit agreement at every bit shift:

```python
bits = [(b >> (7-k)) & 1 for b in data for k in range(8)]
for s in range(1, 400):
    agree = sum(bits[i] == bits[i+s] for i in range(len(bits)-s)) / (len(bits)-s)
```

Top peaks:

| shift (bits) | shift (bytes) | agreement |
|---|---|---|
| **48** | **6** | **0.6263** |
| 376 | 47 | 0.6233 |
| 192 | 24 | 0.6228 |
| 232 | 29 | 0.6204 |
| 256 | 32 | 0.6126 |
| 72 | 9 | 0.6087 |
| 144 | 18 | 0.6071 |

Every high peak is a multiple of 8 bits, and the strongest is **48 bits = 6 bytes**. Conclusion so far: **the periodic structure has period 6 bytes.**

### 4.3 The printability trap

With a 6-byte repeating XOR, each of the 6 columns should be `plaintext ^ constant`. If the plaintext were all printable ASCII, then for each column there must exist a key byte `k` such that every byte in that column decrypts to printable. We tested exactly that:

```python
def pr(b): return 32 <= b < 127
for L in range(1, 25):
    ok = True
    for i in range(L):
        col = data[i::L]
        if not any(all(pr(b ^ k) for b in col) for k in range(256)):
            ok = False
    print(L, ok)
```

**No `L` up to 24 worked.** (We later pushed to 128 — still nothing.)

At the time this was confusing and led us down several wrong paths. The correct interpretation, in hindsight:

1. The cipher is **not XOR**, so the test was checking the wrong transform.
2. Even for the correct transform (ADD), a strict "everything must be printable `0x20–0x7E`" test fails because a real note contains **newlines (`0x0A`)**, which are not in that range.

That over-strict test cost a lot of time. Lesson learned: when testing a hypothesis, also allow `\n`, `\r`, `\t`, and ideally score content instead of hard-filtering.

---

## 5. Dead-End Tour (all the wrong turns)

To be honest about the process, here is everything that was tried and failed, and *why*.

### 5.1 Crib dragging with `HackCTF{`

Assuming the flag appears in the plaintext, then at some offset `i` the keystream is
`K[j] = C[i+j] ^ "HackCTF{"[j]`. For a repeating key of length `L`, that 8-byte keystream must be periodic with period `L`.

A naive checker produced hundreds of "hits" — but almost all were trivial coincidences (any 8-byte sequence is "periodic" with period 8; and 8 bytes with period 6 only constrains two bytes). No consistent key emerged. **Crib dragging was inconclusive because the cipher was not XOR.**

### 5.2 Bigram / quadgram hill-climbing over XOR keys

Built an English bigram/quadgram model from a local text corpus (`/usr/share/doc/pcre2/pcre2.txt`) and hill-climbed the key bytes for `L = 2..16`, with random restarts:

```python
# per-column local search maximising English log-likelihood
for i in range(L):
    for k in range(256):
        key[i] = k
        score = bigram_score(xor_decrypt(data, key))
```

Results were **letter soup** such as:

```
ddot8>0Y <(.0! 4Îhkvksj  deiV]ennjoUÎnYrch>1vmcRd,dieVÎoaxc ...
```

This is the classic failure mode: with only 193 bytes and a key of length `L`, a per-column search has `256^L` degrees of freedom and happily overfits. Long keys always "score better." The model was fine; **the cipher hypothesis was wrong.**

### 5.3 Cumulative / differential XOR and ADD

Tried chained ciphers of the form `C[i] = P[i] ^ P[i-1]` and `C[i] = P[i] + P[i-1]` (decryption = running XOR / running subtraction), brute-forcing all 256 seeds and both directions. Best outputs were still binary garbage. **Dead.**

### 5.4 Bit rotations, bit reversal, nibble swap, NOT

Tried:

- constant `ROL`/`ROR` by 1..7 bits,
- position-dependent rotation patterns (`i mod 8`, `i mod 7`, `(3i) mod 8`, …),
- bit-reversal per byte, nibble swap, bitwise NOT,

each followed by the repeating-XOR printable test. Nothing produced text. A useful negative result: **popcount distribution** of the ciphertext was `{2:2, 3:33, 4:68, 5:61, 6:28, 7:1}` — no bytes with 0 or 1 bits set. Rotation preserves popcount; plain English contains spaces (`0x20`, popcount 1), so a pure rotation of English was implausible. This nudged us away from rotation ciphers.

### 5.5 Common keys / magic constants

Brute-forced a list of "dumb vendor" keys with XOR, ADD and SUB:

```
flash, Flash, FLASH, dumb, DUMB, vendor, break-glass, breakglass,
break_glass, field, device, scada, siemens, moxa, HackCTF, hackctf,
DEADBEEF, CAFEBABE, AA55AA55, A5A5A5A5, 12345678, FFFFFFFF, 6D6D6D6D ...
```

Nothing readable. (Ironically the real key is `orchid` — a vendor-ish word — but it was not on the list. Brute-forcing wordlists only helps if the word is in the list.)

### 5.6 Trying to salvage XOR with "high-bit" reasoning

Since almost every ciphertext byte has the high bit set, we reasoned: *if the plaintext were ASCII (high bit 0) and the cipher were XOR, the key's high bit would have to be 1 almost everywhere.* Testing the high bit per residue for `L = 6`:

| residue mod 6 | high-bit-set count | sub-`0x80` bytes |
|---|---|---|
| 0 | 30 / 33 | `0x79 × 3` |
| 1 | 30 / 32 | `0x7c × 2` |
| 2 | 29 / 32 | `0x6d × 3` |
| 3 | 32 / 32 | — |
| 4 | 32 / 32 | — |
| 5 | 32 / 32 | — |

Within a single residue the high bit **varies**, which is impossible for "ASCII plaintext XOR constant key byte." That formally killed XOR. But it also handed us the actual breakthrough (next section).

---

## 6. The Turning Point — Look at the *Low* Bytes

Instead of filtering them out, we listed every byte `< 0x80` **with its position**:

```python
for i, b in enumerate(data):
    if b < 0x80:
        print(i, i % 6, hex(b))
```

Output:

```
24  0 0x79
44  2 0x6d
62  2 0x6d
97  1 0x7c
126 0 0x79
175 1 0x7c
188 2 0x6d
192 0 0x79
```

This is the "repeating rhythm" made literal:

| residue mod 6 | low byte value | occurrences |
|---|---|---|
| 0 | `0x79` | positions 24, 126, 192 |
| 1 | `0x7c` | positions 97, 175 |
| 2 | `0x6d` | positions 44, 62, 188 |
| 3, 4, 5 | none | — |

At each residue the low byte is **always the same value** and only occurs at residues 0, 1, 2. That is a much stronger regularity than anything we had seen.

### 6.1 Recognizing the cipher

Suppose the cipher is **addition modulo 256** with a 6-byte repeating key:

```
C[i] = (P[i] + K[i mod 6]) mod 256
```

A plaintext **newline `0x0A`** is extremely common in a multi-line note. At a newline position `i`:

```
C[i] = (0x0A + K[i mod 6]) mod 256
```

So the ciphertext at newline positions leaks the key byte directly. And indeed the low bytes are *fixed per residue*, exactly as you'd expect for "same plaintext byte (newline) + same key byte."

Check it:

```
residue 0: 0x79 - 0x0A = 0x6F = 'o'
residue 1: 0x7c - 0x0A = 0x72 = 'r'
residue 2: 0x6d - 0x0A = 0x63 = 'c'
```

**The first three key bytes are `o r c`.**

The remaining residues 3, 4, 5 did not happen to contain a newline, so they weren't directly leaked. But `orc???` with a vendor/plant theme strongly suggests **`orchid`**. (Orchid is also a plausible "field device vendor" name, matching the prompt's tone.)

### 6.2 Verifying the whole hypothesis

Decrypt with `P[i] = (C[i] - K[i mod 6]) mod 256`, `K = b"orchid"`:

```python
data = open('flash.bin','rb').read()
key  = b'orchid'
pt   = bytes((c - key[i % len(key)]) & 0xFF for i, c in enumerate(data))
print(pt.decode())
```

Output:

```
BOOTROM dump @0x08000000
region: user_config
owner: field-tech
note: scratch area, rotated weekly
recovery_contact: ops-bridge
break_glass: HackCTF{add1t1v3_c1ph3rs_4r3nt_x0r}
checksum: ok
END
```

Clean, complete, coherent. Hypothesis confirmed.

---

## 7. Why This Works — The "Narrow Window" Explained

This ties Sections 2, 4, and 6 together.

- Plaintext is 7-bit ASCII, range roughly `0x0A` (newline) to `0x7D` (`}`).
- Key `orchid` bytes are `0x63`–`0x72`.
- Therefore each ciphertext byte is in roughly:

```
min = 0x0A + 0x63 = 0x6D      (newline + 'c')
max = 0x7D + 0x72 = 0xEF      (max possible, if '}' aligned with 'r')
```

Because the maximum possible sum (`0xEF`) is **still below `0x100`**, the addition **never wraps around**. That is why:

1. The ciphertext occupies one contiguous 128-ish-wide window instead of smearing across all 256 values.
2. The mapping is effectively order-preserving: `C = P + K` with no modulo wrap.
3. **Low ciphertext bytes = low plaintext bytes.** Newlines (`0x0A`), being the lowest plaintext values, land lowest in the ciphertext and stand out as the only sub-`0x80` bytes.

This is also why the very first "printable XOR" test was doomed: the cipher was ADD, and the only non-printable plaintext byte was the newline, which the test rejected anyway.

---

## 8. The Key, Derived Cleanly

If you want to reproduce the key without guessing `orchid`, just note that the newline leak gives residues 0–2 directly, and the remaining three follow from the same idea combined with English scoring:

```text
leak:   C = 0x0A + K[r]   =>   K[r] = C - 0x0A
r=0:    0x79 - 0x0A = 0x6F  'o'
r=1:    0x7C - 0x0A = 0x72  'r'
r=2:    0x6D - 0x0A = 0x63  'c'
=> "orc"
```

`orc???` → dictionary / vendor-name guess → `orchid`. Then the full decryption confirms it (all residues, all 193 bytes, fully readable).

A general per-column solver also recovers the same thing automatically, which is what finally printed the answer:

```python
import math, collections

data = open('flash.bin','rb').read()

# crude English letter model
corpus = open('/usr/share/doc/pcre2/pcre2.txt', errors='ignore').read().lower()
corpus = ''.join(c for c in corpus if c in 'abcdefghijklmnopqrstuvwxyz ')
freq = collections.Counter(corpus)
total = sum(freq.values())

def weight(b):
    if b in (0x0A, 0x0D, 0x09):            # newline/tab are legal in a note
        return math.log(0.01)
    if 97 <= b <= 122 or b == 32:          # lowercase + space
        return math.log((freq.get(chr(b), 0) + 1) / total)
    if 65 <= b <= 90:                      # uppercase
        return math.log((freq.get(chr(b + 32), 0) + 1) / total) - 0.5
    if 32 <= b < 127:                      # punctuation/digits
        return math.log(0.005)
    return math.log(0.0005)                # binary

def decrypt_sub(data, key):
    return bytes((c - key[i % len(key)]) & 0xFF for i, c in enumerate(data))

def decrypt_add(data, key):
    return bytes((c + key[i % len(key)]) & 0xFF for i, c in enumerate(data))

for L in (6, 12):
    # per-column best key byte under the SUB model
    key = []
    for i in range(L):
        col = data[i::L]
        best = max(range(256),
                   key=lambda k: sum(weight((b - k) & 0xFF) for b in col))
        key.append(best)
    key = bytes(key)
    print("L =", L, "key =", key)
    print(decrypt_sub(data, key).decode('latin1'))
    print("-" * 60)
```

Output:

```
L = 6 key = b'orchid'
BOOTROM dump @0x08000000
region: user_config
owner: field-tech
note: scratch area, rotated weekly
recovery_contact: ops-bridge
break_glass: HackCTF{add1t1v3_c1ph3rs_4r3nt_x0r}
checksum: ok
END
```

(With the `ADD` model the recovered key prints as its two's complement `91 8e 9d 98 97 9c`, which decrypts to the identical plaintext — a useful sanity check that the two formulations are equivalent: `C = P + K` ⇔ `P = C - K`.)

---

## 9. One-Liner Solve

```bash
python3 -c "d=open('flash.bin','rb').read();k=b'orchid';print(bytes((c-k[i%6])&0xff for i,c in enumerate(d)).decode())"
```

---

## 10. Final Answer

```
BOOTROM dump @0x08000000
region: user_config
owner: field-tech
note: scratch area, rotated weekly
recovery_contact: ops-bridge
break_glass: HackCTF{add1t1v3_c1ph3rs_4r3nt_x0r}
checksum: ok
END
```

**Flag:** `HackCTF{add1t1v3_c1ph3rs_4r3nt_x0r}`

The flag text is itself the lesson: *"additive ciphers aren't XOR."* The whole challenge was designed to bait an XOR solve and reward noticing the additive structure.

---

## 11. Timeline / Approach Changes (TL;DR)

| # | Hypothesis | Method | Result | Why it failed |
|---|---|---|---|---|
| 1 | Single-byte XOR | brute force + printable ratio + `HackCTF{` search | ✗ | wrong transform |
| 2 | Repeating XOR, unknown L | shift autocorrelation (bytes + bits) | **period 6 found** | — (key length correct) |
| 3 | Repeating XOR, L=6 | per-column "all printable" filter | ✗ | cipher is ADD; test also rejected newlines |
| 4 | Repeating XOR, any L | crib dragging with `HackCTF{` | ✗ | wrong transform |
| 5 | Repeating XOR, L≤16 | bigram/quadgram hill-climbing | ✗ (overfit soup) | wrong transform + small sample |
| 6 | Chained/differential XOR/ADD | 256 seeds, both directions | ✗ | wrong transform |
| 7 | Bit rotations / reversal / nibble swap / NOT | transform + XOR test | ✗ | wrong transform |
| 8 | Common vendor keys | wordlist + magic constants | ✗ | key (`orchid`) absent from list |
| 9 | **Addition mod 256, L=6** | **newline leak on sub-`0x80` bytes** | **✓ key `orchid`** | — |
| 10 | Verify | full decrypt, both ADD and SUB forms | ✓ | — |

---

## 12. Lessons / Reusable Checklist

1. **Measure the ciphertext range first.** `max - min + 1` being much less than 256 is a massive hint. Here it was exactly 128, which should have been prioritized earlier.
2. **"Not real crypto" means test a *family*, not just XOR.** Try, in order:
   - `P = C ^ K`
   - `P = (C - K) mod 256` (additive)
   - `P = (C + K) mod 256`
   - `P = ROL/ROR(C, n)`
   - `P = C ^ P_prev` / `P = C - P_prev` (differential)
3. **Never hard-filter on "all printable."** Real notes contain `\n`, `\r`, `\t`, and sometimes a NUL terminator. Allow control characters, or better, score the content.
4. **Low ciphertext bytes are gold.** For additive ciphers without wraparound, the *smallest* ciphertext bytes correspond to the *smallest* plaintext bytes (newlines/spaces). Their positions reveal the key schedule.
5. **A repeated low-byte-at-fixed-residue pattern is a key leak**, not noise. `0x79, 0x7c, 0x6d` at residues `0,1,2 (mod 6)` gave the first three key bytes instantly: `C - 0x0A = "orc"`.
6. **Beware overfitting tiny files with long keys.** With 193 bytes, hill-climbing over a 12–16 byte key will always "improve" the score; distrust it.
7. **Confirm with a second formulation.** Recovering the key under both the `SUB` and `ADD` models yielding the same plaintext is strong proof you have the right structure.
8. **Word intuition matters.** `orc???` → `orchid` is a 5-second guess once the first three bytes are known. A short human guess beat a long automated search here.

---

## 13. Appendix — Useful Snippets Used Along the Way

### A. Byte vs bit autocorrelation (period detection)

```python
d = open('flash.bin','rb').read()

# byte-level: fraction of small XOR-differences per shift
for s in range(1, 65):
    xs = bytes(d[i] ^ d[i+s] for i in range(len(d)-s))
    print("byte shift", s, sum(x < 0x20 for x in xs) / len(xs))

# bit-level: agreement per bit shift
bits = [(b >> (7-k)) & 1 for b in d for k in range(8)]
n = len(bits)
res = []
for s in range(1, 400):
    res.append((sum(bits[i] == bits[i+s] for i in range(n-s)) / (n-s), s))
for a, s in sorted(res, reverse=True)[:10]:
    print("bit shift", s, "=", s/8, "bytes", a)
```

### B. Locate the "anomalously low" bytes and their residues

```python
d = open('flash.bin','rb').read()
for i, b in enumerate(d):
    if b < 0x80:
        print(f"offset={i:#04x}  i%6={i%6}  byte={b:#04x}  (byte-0x0A)={chr((b-0x0A)&0xff)!r}")
```

Expected:

```
offset=0x18  i%6=0  byte=0x79  (byte-0x0A)='o'
offset=0x2c  i%6=2  byte=0x6d  (byte-0x0A)='c'
offset=0x3e  i%6=2  byte=0x6d  (byte-0x0A)='c'
offset=0x61  i%6=1  byte=0x7c  (byte-0x0A)='r'
offset=0x7e  i%6=0  byte=0x79  (byte-0x0A)='o'
offset=0xaf  i%6=1  byte=0x7c  (byte-0x0A)='r'
offset=0xbc  i%6=2  byte=0x6d  (byte-0x0A)='c'
offset=0xc0  i%6=0  byte=0x79  (byte-0x0A)='o'
```

`o r c` at residues `0 1 2` → key `orchid`.

### C. Full decrypt + sanity check (both directions)

```python
d   = open('flash.bin','rb').read()
key = b'orchid'

sub = bytes((c - key[i % 6]) & 0xFF for i, c in enumerate(d))
add = bytes((c + ((256 - key[i % 6]) % 256)) & 0xFF for i, c in enumerate(d))

assert sub == add
print(sub.decode())
```
