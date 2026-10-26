# Vault Cipher — HackCTF Crypto Challenge Write-up

**Target:** `capture.bin` + leaked `cipher.py`
**Category:** Crypto
**Vulnerability:** Homemade stream cipher — raw 64-bit LCG state XORed into plaintext, broken with known plaintext
**Flag:** `HackCTF{r0ll_y0ur_0wn_lcg_r0lls_0v3r}`
**Status:** Solved
**Date:** 2026-10-25

---

## 1. Executive Summary

SecureVault is a password manager whose backup agent encrypts vault exports with a custom stream cipher. The agent source (`cipher.py`) leaked alongside one captured export (`capture.bin`). The seed is secret and random.

The cipher is a 64-bit Linear Congruential Generator (LCG) whose full state word is emitted directly into the keystream. Because every export is prefixed with the constant `MAGIC = b"VAULTv01"`, the first eight keystream bytes are recoverable from the first eight ciphertext bytes. Those eight bytes are exactly the first LCG state, and every subsequent state is a deterministic function of it. The whole keystream therefore falls out without ever touching the seed.

The decrypted export is JSON with four records. The first record is a valid-looking flag but is explicitly labelled `legacy-import` and noted `deprecated, do not use`. The requested **recovery-kit** secret is the fourth record.

```
known MAGIC prefix
        ↓
ciphertext[0:8] XOR "VAULTv01"  →  LCG state s₁
        ↓
sₙ₊₁ = A·sₙ + C (mod 2⁶⁴)  →  entire keystream
        ↓
XOR with capture.bin  →  plaintext JSON
        ↓
read labels, skip the decoy  →  recovery-kit secret
        ↓
HackCTF{r0ll_y0ur_0wn_lcg_r0lls_0v3r}
```

---

## 2. Challenge Brief and Hints

> SecureVault is a password manager that lets you export an encrypted backup. Their backup agent leaked, so we have the exact cipher it uses (`cipher.py`) and one captured export (`capture.bin`). The seed was random and we never saw it. They wrote their own stream cipher. Read it, break it, and pull the recovery-kit secret out of the export.
>
> Note: the export lists several records — the first one that looks like a flag is a retired entry. Read the labels.

Mapping the hints to the attack path:

| Hint | Interpretation |
|---|---|
| "exact cipher" + "one captured export" | White-box cryptanalysis: the algorithm is fully known, only the key/seed is unknown. |
| "The seed was random and we never saw it" | Do not plan on guessing or brute-forcing the seed. Attack the construction, not the key. |
| "They wrote their own stream cipher" | Strong prior for a non-standard, unaudited construction with a structural flaw. |
| "pull the recovery-kit secret out" | The target is a named record, not necessarily the first flag-like string. |
| "the first one that looks like a flag is a retired entry" | There is a decoy. Read the `label` and `note` fields before submitting. |
| Flag format `HackCTF{...}` | Standard HackCTF flag. |

The phrase "we never saw it" is doing real work: it steers the solver away from seed recovery and toward keystream recovery. The note about labels is the second trap.

---

## 3. Environment and Tooling

| Item | Value |
|---|---|
| Target | Local files: `Vault_Cipher/capture.bin` (400 bytes), `Vault_Cipher/cipher.py` |
| Challenge type | Offline crypto (no network service) |
| Cipher | 64-bit LCG stream cipher, raw XOR |
| Known plaintext | Fixed 8-byte `MAGIC = b"VAULTv01"` prefix |
| Tools used | `ls`, `od`, `python3` (stdlib only: `json`, `cipher`) |
| Working directory | `/home/boss/Works/ctf/Zero_trace/Vault_Cipher` |
| Reproducer | `Vault_Cipher/solve.py` |
| Full plaintext | §14.6 |
| Time to solve | ~2 minutes of actual work |

No VPN, proxy, or external tooling was needed. This was a pure source-review and scripting exercise.

---

## 4. Phase 0 — File Enumeration

The first step was simply to see what the challenge shipped:

```bash
$ ls -la /home/boss/Works/ctf/Zero_trace/Vault_Cipher
total 8
drwxr-xr-x 1 boss boss   40 Oct 25 18:45 .
drwxr-xr-x 1 boss boss  248 Oct 25 18:45 ..
-rw-r--r-- 1 boss boss  400 Oct 25 18:44 capture.bin
-rw-r--r-- 1 boss boss 1078 Oct 25 18:45 cipher.py
```

Observations:

1. **Two files only.** No README, no key file, no service. The algorithm must be fully inferable from `cipher.py`.
2. **`capture.bin` is tiny** — 400 bytes. That is small enough to inspect byte-by-byte and to hold entirely in memory.
3. **`cipher.py` is ~1 KB** — small enough to read line by line and reason about completely.

The size asymmetry is a useful signal: 400 bytes of ciphertext and a 1 KB cipher means the intended attack is almost certainly structural, not brute force.

---

## 5. Phase 1 — Source Review

### 5.1 The leaked cipher

```python
#!/usr/bin/env python3
"""SecureVault export cipher  (internal build -- leaked from the backup agent).

This is the exact routine the backup agent uses to encrypt vault exports.
`capture.bin` was produced by encrypt(<export_json>, seed) with a secret
per-run seed. The plaintext always begins with MAGIC.
"""

MAGIC = b"VAULTv01"
A = 6364136223846793005
C = 1442695040888963407
MASK = (1 << 64) - 1


def keystream(seed: int, n: int) -> bytes:
    """Keystream = concatenated 64-bit states of our fast internal PRNG."""
    s = seed & MASK
    out = bytearray()
    while len(out) < n:
        s = (A * s + C) & MASK
        out += s.to_bytes(8, "big")
    return bytes(out[:n])


def encrypt(plaintext: bytes, seed: int) -> bytes:
    data = MAGIC + plaintext
    ks = keystream(seed, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


def decrypt(ciphertext: bytes, seed: int) -> bytes:
    ks = keystream(seed, len(ciphertext))
    data = bytes(a ^ b for a, b in zip(ciphertext, ks))
    assert data[:len(MAGIC)] == MAGIC, "bad seed"
    return data[len(MAGIC):]
```

### 5.2 Line-by-line analysis

| Element | Meaning | Security relevance |
|---|---|---|
| `MAGIC = b"VAULTv01"` | Constant prefix prepended before encryption | **Known plaintext**, 8 bytes, at a known offset |
| `A`, `C` | LCG multiplier and increment | Public; standard Numerical Recipes / PCG-style values |
| `MASK = (1 << 64) - 1` | Arithmetic mod 2⁶⁴ | State space is 2⁶⁴ |
| `s = seed & MASK` | Initial state is the seed | Seed is 64-bit |
| `s = (A * s + C) & MASK` | Advance state, then emit | **First emitted word is `s₁ = A·seed + C`, not `seed`** |
| `out += s.to_bytes(8, "big")` | Emit full 64-bit state, big-endian | **State is exposed verbatim**, no mixing |
| `bytes(a ^ b ...)` | Plain XOR | No authentication, no nonce, no key derivation |
| `assert data[:8] == MAGIC` | Decrypt sanity check | Gives the attacker a free oracle for candidate states |

### 5.3 The critical observation

A stream cipher is only as strong as the unpredictability of its keystream. Here the keystream is not a keyed hash of anything — it is the raw internal state of a deterministic generator, written out 8 bytes at a time.

Two properties combine into an immediate break:

1. **The first plaintext block is known** (`MAGIC`). Therefore keystream bytes 0–7 are known.
2. **The first keystream block is the complete first state**, not a truncated or mixed value. Therefore the full 64-bit generator state is known.

From `s₁`, the LCG is fully determined:

```
s₂ = A·s₁ + C mod 2⁶⁴
s₃ = A·s₂ + C mod 2⁶⁴
...
```

This is a **known-plaintext attack that recovers the generator state directly**, with no search. The seed never has to be known. In fact, the seed is a red herring — it is only one step *before* the thing that is exposed.

---

## 6. Phase 2 — Attack Design (Before Touching the Data)

Before writing any exploit, several possible approaches were considered. Most were rejected on cost or redundancy grounds. This section records that reasoning, because the choice of approach is the actual solution.

### 6.1 Option A — brute-force the 64-bit seed

- **Idea:** iterate `seed` in `[0, 2⁶⁴)`, decrypt, check for the `MAGIC` prefix.
- **Cost:** 2⁶⁴ ≈ 1.8 × 10¹⁹ candidates. At 10⁹ candidates/second that is roughly 580 years.
- **Why it fails:** even with a cheap filter, the search space is far too large. The `MAGIC` check reduces the expected work only by a constant factor of 2⁸, which changes nothing.
- **Decision:** rejected. The prompt's "we never saw it" is a hint not to go here.

### 6.2 Option B — recover the first state from the known prefix

- **Idea:** `ks[0:8] = ct[0:8] XOR MAGIC`; interpret big-endian as `s₁`; regenerate the keystream.
- **Cost:** O(1) for the state, O(n) for the keystream. Negligible.
- **Why it works:** the state is emitted verbatim and the prefix is known.
- **Decision:** **chosen.**

### 6.3 Option C — crib-drag the JSON structure

- **Idea:** guess `{"schema":"securevault/1",...` and derive keystream bytes from known JSON fragments, then extend.
- **Cost:** O(n) but requires accurate guesses throughout the message.
- **Why it is unnecessary:** only 8 bytes of crib are needed to recover the state, after which the rest is generated. Crib-dragging the whole document would work but is strictly more fragile.
- **Decision:** rejected as redundant. (It does, however, serve as an independent sanity check on the schema — see §11.3.)

### 6.4 Option D — algebraic / lattice recovery of the seed

- **Idea:** treat the LCG recurrence as a modular equation and solve for the seed, or apply lattice reduction to truncated outputs.
- **Cost:** implementation complexity, specialized tooling, and it assumes partial output.
- **Why it is unnecessary:** the output is not truncated. The full state is handed over in the first block. Lattice methods are for *truncated* LCG outputs; here there is nothing truncated to solve.
- **Decision:** rejected. Using a lattice attack here would be solving a harder problem than the one posed.

### 6.5 Option E — assume there is authentication or a KDF

- **Idea:** look for an HMAC, nonce, or key schedule before attempting decryption.
- **Result of review:** none exists. `encrypt()` is `MAGIC || plaintext`, XOR keystream, done.
- **Decision:** rejected. There is nothing to forge or verify; it is a raw XOR.

### 6.6 Option F — treat the LCG as an LFSR and use Berlekamp–Massey

- **Idea:** recover a linear recurrence from the keystream bits.
- **Why it is the wrong model:** Berlekamp–Massey applies to linear feedback shift registers over GF(2). An LCG is affine over ℤ/2⁶⁴, not linear over GF(2). The bit-level sequence of an LCG has high linear complexity.
- **Decision:** rejected as a category error.

### 6.7 Decision table

| Option | Approach | Cost | Verdict |
|---|---|---|---|
| A | Brute-force seed | 2⁶⁴ | Rejected — infeasible and hinted against |
| B | Recover state from known prefix | O(n) | **Chosen** |
| C | Crib-drag JSON | O(n), fragile | Rejected — redundant |
| D | Lattice/algebraic seed recovery | High complexity | Rejected — full state already exposed |
| E | Look for AEAD/KDF | N/A | Rejected — none present |
| F | Berlekamp–Massey | N/A | Rejected — wrong algebraic model |

The meta-lesson: the cheapest attack is the one the construction hands you. Option B requires no search, no guessing beyond the documented constant, and no specialized math.

---

## 7. Phase 3 — Ciphertext Inspection (and the First Live Failure)

### 7.1 Failure F1 — `xxd` is not installed

The natural first command for a binary blob is a hex dump:

```bash
$ cd /home/boss/Works/ctf/Zero_trace/Vault_Cipher && xxd capture.bin | head -30
/usr/bin/bash: line 1: xxd: command not found
```

**Diagnosis:** the host does not ship `xxd` (part of `vim-common` on many distros). This is a tooling dead end, not a challenge obstacle.

**Change of approach:** fall back to `od`, which is part of coreutils and universally present.

```bash
$ od -A d -t x1z capture.bin
```

This produced a clean decimal-offset hex dump with an ASCII gutter:

```text
0000000 97 65 e9 62 c5 f0 dd 44 5f 16 de 1b 05 60 24 81  >.e.b...D_....`$.<
0000016 fd 39 18 51 25 38 e8 dd f4 4a bc 22 19 e3 25 23  >.9.Q%8...J."..%#<
0000032 bb 02 de 21 bd 1d 5b 0b ff ea b6 b0 2d 77 e3 ae  >...!..[.....-w..<
0000048 fe c2 a2 b9 a1 5e 84 7e b5 cd 5c 9b 53 87 8c c4  >.....^.~..\.S...<
0000064 48 03 6a b4 7a 50 90 9f a0 b6 fd 8d 27 cb 6e b2  >H.j.zP......'.n.<
...
0000400
```

Takeaway: `od -A d -t x1z` is a fine substitute for `xxd` when it is missing. `-A d` gives byte offsets, `-t x1z` gives one-byte hex plus the ASCII gutter.

### 7.2 Length analysis

`capture.bin` is exactly 400 bytes. The cipher prepends 8 bytes of `MAGIC`, so:

```
400 ciphertext bytes - 8 MAGIC bytes = 392 bytes of JSON plaintext
```

That is consistent with a small JSON document containing four short records. No padding, no block structure, no length field — another sign of a pure stream cipher.

### 7.3 Deriving the first state by hand

The first eight ciphertext bytes are:

```
ct[0:8] = 97 65 e9 62 c5 f0 dd 44
MAGIC   = 56 41 55 4c 54 76 30 31   ("VAULTv01")
```

XOR byte by byte:

```
97^56=c1  65^41=24  e9^55=bc  62^4c=2e
c5^54=91  f0^76=86  dd^30=ed  44^31=75
```

So the first keystream block — and therefore the first LCG state — is:

```
s₁ = 0xc124bc2e9186ed75
```

This is the entire break. Everything after it is arithmetic.

---

## 8. Phase 4 — First Decryption Attempt and the Off-by-One Trap

### 8.1 Failure F2 (live) — passing `s₁` straight to `decrypt()`

The first instinct after recovering `s₁` is to call the provided decryptor:

```python
import cipher
ct = open("capture.bin", "rb").read()
s1 = int.from_bytes(bytes(a ^ b for a, b in zip(ct[:8], cipher.MAGIC)), "big")
cipher.decrypt(ct, s1)
```

Result:

```text
AssertionError: bad seed
```

**Diagnosis.** `keystream()` does not emit the seed; it advances first:

```python
s = seed & MASK
while ...:
    s = (A * s + C) & MASK   # advance
    out += s.to_bytes(8, "big")  # then emit
```

So `keystream(seed)` begins with `A·seed + C`, i.e. state #1. The value recovered from the first ciphertext block is **already state #1**, not a seed. Passing it back in advances it again to state #2 and everything is shifted by one block. The `MAGIC` check then fails.

This is a subtle and very common off-by-one when attacking PRNG-based ciphers: **the recovered first output is not the initial state, it is the first transition of the initial state.** The seed and the first output differ by one LCG step.

**Change of approach.** Stop trying to use `decrypt()` with a state. Either:

1. roll the recovered state *backwards* one step to recover the true seed (`seed = (s₁ - C)·A⁻¹ mod 2⁶⁴`, §11.1), then call `decrypt()` normally; or
2. reimplement the keystream so the first emitted word **is** `s₁`, then XOR directly.

Option 2 was chosen for the solver because it avoids depending on the seed at all.

### 8.2 Failure modes verified during validation

After the solve succeeded, the surrounding failure modes were reproduced deliberately to confirm the diagnosis. These were **not** live dead ends during the solve; they are recorded here because they are exactly the traps a different solver would hit.

**Variant B — wrong byte order.** Serializing the state little-endian instead of big-endian:

```python
ks += s.to_bytes(8, "little")   # wrong
```

Every emitted block is byte-reversed relative to the stream that produced the ciphertext, so the plaintext is garbage from byte 0 — not just after `MAGIC`:

```text
b'\xe2\x88o\xf3\xebL\xf9\x85\xbf_\xdbv}\xcd\x10\xa5...'
```

This also fails the `MAGIC` check, because the first block is reversed too.

**Variant C — advancing before the first emit.** Emitting `s₂` first and shifting the whole stream one block:

```text
b'\xb3QD\x1a\xa8\xf5\x94\xa4\x80\x15\xe49E;\xb9....'
```

Also garbage, and also fails the `MAGIC` check.

**Variant D — correct.** Emit `s₁` first, then advance:

```text
b'VAULTv01{"schema":"securevault/1","exported_by":'
```

The `MAGIC` prefix appears immediately and the JSON begins cleanly.

**Variant E — correct first block, wrong recurrence.** Recover `s₁` correctly, emit the first block correctly, then advance with wrong constants (or the wrong order of operations). The prefix check passes while everything after byte 8 is noise:

```text
MAGIC passes: True
b'VAULTv01{"schema\xdaU\x8dB?^\xd9\xac\xd2\xff\xd1<\xcc\x95\x813e\x10\x83\x81\xfd\xfe\xcbJ'
```

This is the most deceptive case: the built-in assert validates only the 8-byte prefix, not the recurrence. Decryption must be validated by parsing the full JSON.

### 8.3 Variant summary

Variant A was the live failure described in §8.1; variants B–E were reproduced deliberately during validation (§8.2).

| Variant | Code shape | Result | Root cause |
|---|---|---|---|
| A | `cipher.decrypt(ct, s1)` | `AssertionError: bad seed` | `s₁` is a state, not a seed; decrypt advances one step |
| B | `s.to_bytes(8, "little")` | ASCII garbage from block 0 | Wrong endianness |
| C | advance, then emit | ASCII garbage from block 0 | Off-by-one block shift |
| D | emit, then advance | Valid JSON | Correct |
| E | correct block 0, wrong recurrence | `MAGIC` passes, bytes 8+ garbage | Trusting the assert instead of the JSON |

This is the whole cryptanalytic surface of the challenge in one table. The attack is one XOR plus a loop; the only place to go wrong is state/seed/endianness bookkeeping.

---

## 9. Phase 5 — Full Decryption

The working solver logic:

```python
MAGIC = b"VAULTv01"
A = 6364136223846793005
C = 1442695040888963407
MASK = (1 << 64) - 1

ct = open("capture.bin", "rb").read()

# 1. first keystream block = first LCG state
s = int.from_bytes(bytes(a ^ b for a, b in zip(ct[:8], MAGIC)), "big")

# 2. regenerate the keystream, emitting s first
ks = bytearray()
while len(ks) < len(ct):
    ks += s.to_bytes(8, "big")
    s = (A * s + C) & MASK

# 3. XOR and strip MAGIC
pt = bytes(a ^ b for a, b in zip(ct, ks))
assert pt[:8] == MAGIC
print(pt[8:].decode())
```

Output:

```json
{
  "schema": "securevault/1",
  "exported_by": "backup-agent",
  "records": [
    {"id": 1, "label": "legacy-import", "note": "deprecated, do not use",
     "secret": "HackCTF{f1rst_match_1s_a_d3coy_r3c0rd}"},
    {"id": 2, "label": "wifi", "secret": "hunter2"},
    {"id": 3, "label": "smtp", "secret": "relay-pass-8812"},
    {"id": 4, "label": "recovery-kit", "note": "break-glass; on-call only",
     "secret": "HackCTF{r0ll_y0ur_0wn_lcg_r0lls_0v3r}"}
  ]
}
```

The decryption is self-validating: the JSON parses, contains the documented `securevault/1` schema, and all four records have coherent shapes. Random garbage would not produce this.

---

## 10. Phase 6 — Record Triage and the Decoy

### 10.1 The first-match temptation

The first record's secret is a syntactically valid flag:

```
HackCTF{f1rst_match_1s_a_d3coy_r3c0rd}
```

A regex like `HackCTF\{[^}]+\}` run over the decrypted blob returns this immediately. That is the trap. The challenge note says:

> the first one that looks like a flag is a retired entry. Read the labels.

And the record itself is labelled:

```json
{"id": 1, "label": "legacy-import", "note": "deprecated, do not use", ...}
```

The label and note are the disambiguator, and the flag text itself (`f1rst_match_1s_a_d3coy_r3c0rd`) confirms it is intentionally fake.

### 10.2 Picking the right record

The brief asks specifically for the **recovery-kit** secret. That is record 4:

```json
{"id": 4, "label": "recovery-kit", "note": "break-glass; on-call only",
 "secret": "HackCTF{r0ll_y0ur_0wn_lcg_r0lls_0v3r}"}
```

The selection was made **by label**, not by regex order, not by record order, and not by which flag "looks better". A solver that greps for the first match submits the decoy.

### 10.3 Why this is a realistic trap

Real backups contain old and deprecated credentials. A correct recovery workflow must select by key/label, not by scanning values. The challenge encodes that operational lesson directly: the export is a key-value store, and the requested key is `recovery-kit`.

---

## 11. Phase 7 — Verification

Four independent checks were performed.

### 11.1 Recovering the original seed

Because `A` is odd, it is invertible modulo 2⁶⁴, and the LCG can be run backwards:

```python
A_inv = pow(A, -1, 1 << 64)          # 0xc097ef87329e28a5
seed  = ((s1 - C) * A_inv) & MASK    # 0x96aee5d16a9aa47e
```

Forward check:

```text
(A * 0x96aee5d16a9aa47e + C) mod 2^64 = 0xc124bc2e9186ed75 = s1  ✓
```

This does not help the attack (it is the long way round), but it proves that `s₁` is a genuine LCG state reachable from a real seed, and not an artifact of a lucky byte pattern.

### 11.2 Decrypting with the unmodified challenge code

With the recovered seed, the original `cipher.decrypt()` — not a reimplementation — succeeds:

```python
import cipher
seed = 0x96aee5d16a9aa47e
cipher.decrypt(open("capture.bin", "rb").read(), seed)
```

```text
b'{"schema":"securevault/1","exported_by":"backup-agent","records":[{"id":1,"label'
```

This is the strongest check: the leaked implementation, unmodified, accepts the seed and returns the same plaintext that the independent keystream reconstruction produced.

### 11.3 Structural validation

- Plaintext is 392 bytes, ciphertext is 400 bytes — exactly the 8-byte `MAGIC` difference.
- Plaintext is valid UTF-8 and `json.loads` parses it.
- The `schema` field is the documented `securevault/1`.
- All four records have `id`, `label`, `secret`; the two flagged records also have `note`.
- The expected schema/`exported_by` text independently matches the crib-drag approach from §6.3, confirming the keystream is correct over the whole message, not just the first block.

### 11.4 Self-consistency of the keystream

XORing `MAGIC || plaintext` with the reconstructed keystream reproduces `capture.bin` byte-for-byte. This is guaranteed by construction, but it means there is no residual "maybe a few bytes were wrong" doubt: any error would show up immediately as invalid JSON or a broken prefix.

---

## 12. Consolidated Failure Log and Approach Changes

### 12.1 Note on honesty

This solve was effectively one-shot at the cryptographic level: the design analysis in §6 identified the correct attack before execution, and the first correct implementation worked. The only **live** dead ends were a missing tool and an initially wrong API call. The remaining entries are failure modes that were reasoned about up front or reproduced deliberately during validation. They are labelled as such below. Nothing is presented as a live attempt when it was not.

### 12.2 Live failures during the solve

#### F1 — `xxd` missing

- **Attempt:** `xxd capture.bin`.
- **Result:** `xxd: command not found`.
- **Diagnosis:** tool not installed on the host.
- **Change:** used `od -A d -t x1z`, a coreutils equivalent.
- **Cost:** seconds.

#### F2 — `cipher.decrypt(ct, s₁)` raised `bad seed`

- **Attempt:** treat the recovered first keystream block as the seed and call the provided decryptor.
- **Result:** `AssertionError: bad seed`.
- **Diagnosis:** `keystream()` advances before emitting, so `s₁` is the first *output*, one LCG step after the seed.
- **Change:** regenerate the keystream starting from `s₁` (emit first, then advance). Alternatively, invert the LCG to recover the seed and use `decrypt()` unchanged.
- **Lesson:** with PRNG stream ciphers, distinguish *seed* from *first output state*.

#### F3 — almost taking the decoy

- **Attempt (instinct):** the first `HackCTF{...}` in the decrypted output is `HackCTF{f1rst_match_1s_a_d3coy_r3c0rd}`.
- **Result:** rejected before submission by reading the record's `label` (`legacy-import`) and `note` (`deprecated, do not use`), and by re-reading the challenge note.
- **Diagnosis:** regex-first triage ignores metadata by design.
- **Change:** select the record whose `label` equals `recovery-kit`, per the brief.
- **Lesson:** in key-value data, select by key, not by value shape.

### 12.3 Failure modes designed around (then reproduced)

#### R1 — Brute-forcing the seed

- **Considered:** iterate all 2⁶⁴ seeds.
- **Rejected:** ~10¹⁹ candidates; the `MAGIC` filter saves at most a factor of 256.
- **Reproduced?** No. The cost argument is decisive; running it would only burn CPU.
- **Alternative chosen:** direct state recovery.

#### R2 — Lattice / truncated-LCG attacks

- **Considered:** solve the recurrence algebraically or with lattice reduction.
- **Rejected:** those techniques target *truncated* outputs. Here the full 64-bit state is emitted.
- **Reproduced?** No.
- **Alternative chosen:** read the state straight from the first block.

#### R3 — Crib-dragging the JSON

- **Considered:** guess `{"schema":"securevault/1"...` and extend keystream from known bytes.
- **Rejected:** requires only 8 known bytes for the state; doing more is unnecessary and fragile.
- **Reproduced?** Partially — the expected schema text was used as an independent sanity check in §11.3.
- **Alternative chosen:** 8-byte prefix XOR.

#### R4 — Searching for a nonce/AEAD/key schedule

- **Considered:** maybe `encrypt()` hides a KDF or MAC.
- **Rejected:** source review shows raw `MAGIC || plaintext` XOR keystream; nothing else exists.
- **Reproduced?** No.
- **Alternative chosen:** none needed.

#### R5 — Endianness mistake

- **Considered:** `to_bytes(8, "big")` vs `"little"`.
- **Resolved:** the cipher writes big-endian, and the manual XOR in §7.3 confirms it. Deliberately switching to little-endian produces garbage from block 0 (§8.2, Variant B).
- **Lesson:** match the writer's byte order exactly; here the `MAGIC` check happens to catch the mistake, but that is luck, not design.

#### R6 — Off-by-one block (`s₂` first)

- **Considered:** whether to advance before or after emitting.
- **Resolved:** emit `s₁` first to match `encrypt()`, whose stream starts at `A·seed + C`.
- **Deliberately reproduced:** shifting one step produces garbage from byte 0 (§8.2, Variant C).
- **Lesson:** model the generator as a sequence of transitions, not as "seed then outputs".

#### R7 — Trusting the `MAGIC` assert as full validation

- **Considered:** the `assert data[:8] == MAGIC` looks like a correctness guarantee.
- **Resolved:** it only validates the first block. A correct `s₁` with a wrong recurrence passes the assert and corrupts bytes 8+ (§8.2, Variant E).
- **Deliberately reproduced:** `assert` passed; `json.loads` on the result failed.
- **Lesson:** validate the whole plaintext structurally, not just the known prefix.

### 12.4 Approach-change summary

| # | Trigger | Old approach | New approach | Outcome |
|---|---|---|---|---|
| F1 | `xxd` missing | `xxd` | `od -A d -t x1z` | Hex dump obtained |
| F2 | `bad seed` assertion | Pass `s₁` as seed | Regenerate from `s₁` / invert to seed | Decryption succeeded |
| F3 | Decoy flag visible | First regex match | Select by `label == "recovery-kit"` | Correct flag |
| R1 | 2⁶⁴ cost | Seed brute force | State recovery | O(n) |
| R2 | Complexity | Lattice attack | Read emitted state | Trivial |
| R3 | Fragility | Full-document crib | 8-byte prefix XOR | Robust |
| R4 | Source review | Assume AEAD/KDF | Raw XOR | Correct model |
| R5 | Garbage from block 0 | Little-endian | Big-endian | Valid JSON |
| R6 | Garbage at start | Shifted stream | Emit `s₁` first | Valid prefix |
| R7 | Prefix-only check | Trust `MAGIC` assert | Parse full JSON | Full validation |

---

## 13. Attack Chain Diagram

```
┌──────────────────────────────┐
│ cipher.py (leaked)           │
│  MAGIC, A, C, keystream()    │
└──────────────┬───────────────┘
               │ read
               ▼
┌──────────────────────────────┐
│ Known plaintext: "VAULTv01"  │
│ at offset 0 of every export  │
└──────────────┬───────────────┘
               │ XOR with ct[0:8]
               ▼
┌──────────────────────────────┐
│ s₁ = 0xc124bc2e9186ed75      │  ← full 64-bit LCG state exposed
└──────────────┬───────────────┘
               │ sₙ₊₁ = A·sₙ + C mod 2⁶⁴
               ▼
┌──────────────────────────────┐
│ Full keystream (400 bytes)   │
└──────────────┬───────────────┘
               │ XOR with capture.bin
               ▼
┌──────────────────────────────┐
│ JSON export, 4 records       │
│ 1 legacy-import  (decoy)     │
│ 2 wifi                       │
│ 3 smtp                       │
│ 4 recovery-kit   ← target    │
└──────────────┬───────────────┘
               │ select by label
               ▼
   HackCTF{r0ll_y0ur_0wn_lcg_r0lls_0v3r}
```

---

## 14. Evidence Appendix

### 14.1 File listing

```text
-rw-r--r-- 1 boss boss  400 Oct 25 18:44 capture.bin
-rw-r--r-- 1 boss boss 1078 Oct 25 18:45 cipher.py
```

### 14.2 First 64 bytes of ciphertext

```text
0000000 97 65 e9 62 c5 f0 dd 44 5f 16 de 1b 05 60 24 81  >.e.b...D_....`$.<
0000016 fd 39 18 51 25 38 e8 dd f4 4a bc 22 19 e3 25 23  >.9.Q%8...J."..%#<
0000032 bb 02 de 21 bd 1d 5b 0b ff ea b6 b0 2d 77 e3 ae  >...!..[.....-w..<
0000048 fe c2 a2 b9 a1 5e 84 7e b5 cd 5c 9b 53 87 8c c4  >.....^.~..\.S...<
```

### 14.3 First-block XOR

```text
ct[0:8]  = 97 65 e9 62 c5 f0 dd 44
MAGIC    = 56 41 55 4c 54 76 30 31
keystream= c1 24 bc 2e 91 86 ed 75
s1       = 0xc124bc2e9186ed75
```

### 14.4 Recovered generator values

```text
A        = 6364136223846793005
C        = 1442695040888963407
A_inv    = 0xc097ef87329e28a5   (mod 2^64)
s1       = 0xc124bc2e9186ed75
s2       = 0x2434ad786d0549e0
s3       = 0xdf033a22405b9daf
s4       = 0x913cdd5775970a12
seed     = 0x96aee5d16a9aa47e
check    = (A*seed + C) mod 2^64 == s1   ✓
```

### 14.5 Decryption with the original implementation

```python
import cipher
ct = open("capture.bin", "rb").read()
cipher.decrypt(ct, 0x96aee5d16a9aa47e)
```

```text
b'{"schema":"securevault/1","exported_by":"backup-agent","records":[{"id":1,"label'
```

### 14.6 Full plaintext

```json
{"schema":"securevault/1","exported_by":"backup-agent","records":[{"id":1,"label":"legacy-import","note":"deprecated, do not use","secret":"HackCTF{f1rst_match_1s_a_d3coy_r3c0rd}"},{"id":2,"label":"wifi","secret":"hunter2"},{"id":3,"label":"smtp","secret":"relay-pass-8812"},{"id":4,"label":"recovery-kit","note":"break-glass; on-call only","secret":"HackCTF{r0ll_y0ur_0wn_lcg_r0lls_0v3r}"}]}
```

Length: 392 bytes of plaintext; 400 bytes of ciphertext.

### 14.7 Record table

| ID | Label | Note | Secret |
|---|---|---|---|
| 1 | `legacy-import` | `deprecated, do not use` | `HackCTF{f1rst_match_1s_a_d3coy_r3c0rd}` — **decoy** |
| 2 | `wifi` | — | `hunter2` |
| 3 | `smtp` | — | `relay-pass-8812` |
| 4 | `recovery-kit` | `break-glass; on-call only` | `HackCTF{r0ll_y0ur_0wn_lcg_r0lls_0v3r}` — **flag** |

### 14.8 Variant outputs (validation)

```text
A: cipher.decrypt(ct, s1)          -> AssertionError: bad seed
B: little-endian states            -> b'\xe2\x88o\xf3\xebL\xf9\x85\xbf_...'   (garbage)
C: advance-before-emit             -> b'\xb3QD\x1a\xa8\xf5\x94\xa4\x80...'    (garbage)
D: emit-then-advance               -> b'VAULTv01{"schema":"securevault/1",...' (valid)
E: correct s1, wrong recurrence    -> MAGIC passes, b'...{"schema\xdaU\x8dB?...' (garbage)
```

---

## 15. Root Cause

1. **A general-purpose PRNG was used as a stream cipher.** LCGs are fast and statistically passable for simulations, but their output is a deterministic affine function of a single word of state. They are not cryptographically secure.
2. **The full state is emitted verbatim.** No truncation, no whitening, no hash. One output word equals the entire internal state, so one known plaintext block breaks the generator forever.
3. **A fixed known prefix provides the known plaintext.** `MAGIC` is not just a format marker; it is 8 bytes of free keystream disclosure.
4. **No nonce, no key derivation, no authentication.** The "key" is a per-run seed with no mixing, and there is no integrity check beyond an `assert` on decryption.
5. **The design assumes the seed is the secret.** The actual secret required to predict the stream is the *state*, and the state is published in the ciphertext.

In one sentence: the construction confuses a pseudorandom *number generator* with a *stream cipher*, and leaks the generator's state into the ciphertext.

---

## 16. Remediation

1. **Use a standard AEAD.** AES-256-GCM, XChaCha20-Poly1305, or libsodium `crypto_secretbox`. Never hand-roll a stream cipher.
2. **If a stream cipher is unavoidable, never XOR raw PRNG output.** Use a CSPRNG or derive keystream with a keyed hash/KDF (e.g. HKDF or ChaCha20) so that observing output does not reveal state.
3. **Use a random nonce per export** and store it alongside the ciphertext. The same key must never produce the same keystream twice.
4. **Derive the encryption key properly.** For password-protected exports, use Argon2id or scrypt to derive a key, then AEAD-encrypt with a random nonce.
5. **Authenticate the ciphertext.** AEAD tags make tampering and wrong-key decryption explicit failures rather than an `assert` on a magic prefix.
6. **Do not rely on a magic prefix for validation.** A known constant at a known offset is a known-plaintext gift.
7. **Rotate the leaked key material.** The per-run seed here is compromised by construction; any real deployment must treat every export as decryptable by anyone with the file.

Example safe outline:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = derive_key(password)            # Argon2id / scrypt
nonce = os.urandom(12)                # random per export
ct = AESGCM(key).encrypt(nonce, plaintext, associated_data=schema_version)
export = {"v": 1, "nonce": nonce.hex(), "ct": ct.hex()}
```

---

## 17. Detection Opportunities (Blue Team)

Although this is an offline challenge, the same flaw is detectable in real code review:

- **Grep for LCG constants** such as `6364136223846793005` and `1442695040888963407`.
- **Flag any `encrypt`/`decrypt` that XORs generator output directly** into plaintext.
- **Reject custom ciphers in review.** Require an approved AEAD library.
- **Look for fixed magic prefixes** used as the only integrity check.
- **Look for `assert`-based decryption validation** — it indicates no authenticated encryption.
- **Check for missing nonces** in any deterministic encryption routine.

---

## 18. Lessons Learned

1. **Unknown key does not imply unknown keystream.** If the cipher exposes state or has known plaintext at a known offset, the keystream can be recovered without the key.
2. **Attack the construction, not the key.** The prompt's "we never saw it" was a hint that brute force is the wrong axis.
3. **Distinguish seed, state, and output.** `s₁ = A·seed + C`; passing `s₁` back as a seed shifts the stream and fails. This is the single most likely implementation mistake in this class of challenge.
4. **Validate beyond the prefix.** A correct first block does not prove the rest of the stream is correct; endianness and off-by-one errors both pass a naive `MAGIC` check in some variants.
5. **Read the labels.** Data triage by regex order is a real-world failure mode; select by key or label.
6. **Small artifacts are a design signal.** 400 bytes and a 1 KB cipher means the intended path is structural, not brute force.
7. **Have fallback tooling.** `xxd` missing cost seconds; knowing `od` avoided a detour.

---

## 19. Timeline

| Time (approx.) | Activity | Result |
|---|---|---|
| 18:45 | List challenge directory | `capture.bin`, `cipher.py` identified |
| 18:45 | Read `cipher.py` | LCG stream cipher, known `MAGIC` prefix identified |
| 18:45 | Design attack options | Seed brute force/lattice/crib-drag rejected; state recovery chosen |
| 18:46 | `xxd capture.bin` | Failed — not installed |
| 18:46 | `od -A d -t x1z capture.bin` | Hex dump obtained |
| 18:46 | Manual first-block XOR | `s₁ = 0xc124bc2e9186ed75` |
| 18:46 | `cipher.decrypt(ct, s₁)` | `AssertionError: bad seed` |
| 18:46 | Reimplement keystream from `s₁` | Valid JSON plaintext |
| 18:46 | Record triage | Decoy rejected by label; recovery-kit selected |
| 18:46 | Seed inversion and unmodified `decrypt()` | Verified |
| 18:47 | `solve.py` + write-up | Reproducer and documentation |

---

## 20. Appendix — `solve.py`

```python
#!/usr/bin/env python3
"""Recover the SecureVault export by breaking its LCG stream cipher.

The cipher is a plain 64-bit LCG whose state is XORed directly into the
plaintext. Because the first 8 plaintext bytes are the known MAGIC value,
the first 8 keystream bytes -- and therefore the first LCG state -- are
recoverable directly from the ciphertext. Every later state follows from
that one, so the whole keystream is known without ever knowing the seed.
"""

import json

MAGIC = b"VAULTv01"
A = 6364136223846793005
C = 1442695040888963407
MASK = (1 << 64) - 1


def recover_keystream(ciphertext: bytes) -> bytes:
    # keystream[0:8] = ciphertext[0:8] XOR MAGIC -> LCG state #1
    state = int.from_bytes(
        bytes(a ^ b for a, b in zip(ciphertext[: len(MAGIC)], MAGIC)), "big"
    )
    out = bytearray()
    while len(out) < len(ciphertext):
        out += state.to_bytes(8, "big")
        state = (A * state + C) & MASK
    return bytes(out[: len(ciphertext)])


def main() -> None:
    with open("capture.bin", "rb") as fh:
        ciphertext = fh.read()

    plaintext = bytes(a ^ b for a, b in zip(ciphertext, recover_keystream(ciphertext)))
    assert plaintext[: len(MAGIC)] == MAGIC, "keystream recovery failed"

    export = json.loads(plaintext[len(MAGIC) :])

    for record in export["records"]:
        print(f"[{record['id']}] {record['label']:<14} {record['secret']}")

    recovery = next(r for r in export["records"] if r["label"] == "recovery-kit")
    print("\nFLAG:", recovery["secret"])


if __name__ == "__main__":
    main()
```

Run:

```bash
$ cd Vault_Cipher && python3 solve.py
[1] legacy-import  HackCTF{f1rst_match_1s_a_d3coy_r3c0rd}
[2] wifi           hunter2
[3] smtp           relay-pass-8812
[4] recovery-kit   HackCTF{r0ll_y0ur_0wn_lcg_r0lls_0v3r}

FLAG: HackCTF{r0ll_y0ur_0wn_lcg_r0lls_0v3r}
```

---

## 21. Final Result

```
HackCTF{r0ll_y0ur_0wn_lcg_r0lls_0v3r}
```

Recovered from the `recovery-kit` record of the decrypted SecureVault export, after rejecting the `legacy-import` decoy by its label and note.
