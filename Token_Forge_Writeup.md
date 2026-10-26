# Token Forge — HackCTF Crypto Challenge Write-up

**Target:** `request_ids.log` + `tokengen.py` + `admin_reset.sealed`
**Category:** Crypto
**Vulnerability:** Truncated-LCG state recovery — only the low 32 bits are hidden, so the full 64-bit state (and therefore the seal key) is predictable
**Flag:** `HackCTF{trunc4t3d_lcg_st1ll_l34ks_th3_st4t3}`
**Status:** Solved
**Date:** 2026-10-25

---

## 1. Executive Summary

An edge gateway uses a 64-bit Linear Congruential Generator (LCG) as its internal
"sequence generator". The same generator hands out two very different things:

1. **Public request-ids**, which are the generator's state with the low
   `LOW_BITS = 32` bits chopped off (`token(s) = s >> 32`).
2. **The admin password-reset token**, which is sealed with a key derived from
   the *next full 64-bit state* (`SHA256(b"reqid-seal-" + str(next_state))`).

The challenge ships ten consecutive request-ids, the generator source, and the
sealed reset blob. Because the recurrence constants are known and the outputs are
consecutive, the only unknown is the low 32 bits of the first state. Brute-forcing
those 2³² possibilities against the next nine ids leaves **exactly one candidate**,
which yields the full state chain and the next state:

```
state0 = 0x32a38bf3a9e9bae3
  ...
state10 = 0xb7bb30593513439e      (last logged id = 0xb7bb3059)
state11 = 0x426a53911d4bc615      ← the state used to seal the reset token
        = 4785729436761441813
```

Unsealing with that state produces honest JSON containing two flag-shaped
strings. The first (`preview_token`) is the documented decoy; the real
`admin_reset_token` is the second.

```
top 32 bits of 10 consecutive states (known)
        ↓
brute-force low 32 bits of s₁  (2³², ~2 s in C)
        ↓
verify s₂…s₁₀ against the log  →  unique state0
        ↓
advance to s₁₁ = next state
        ↓
key = SHA256(b"reqid-seal-" + str(s₁₁))
        ↓
ks  = SHA256(key + counter_be32), XOR ciphertext
        ↓
read admin_reset_token, skip preview_token
        ↓
HackCTF{trunc4t3d_lcg_st1ll_l34ks_th3_st4t3}
```

---

## 2. Challenge Brief and Hints

> An edge gateway mints request-ids from an internal sequence generator, and —
> unwisely — mints the admin password-reset token from the very same generator.
> We dumped some consecutive request-ids (`request_ids.log`), grabbed the
> generator's code from a core dump (`tokengen.py`), and captured the sealed
> reset token (`admin_reset.sealed`), which is sealed with the NEXT value the
> generator will produce. Predict that next value and forge your way in.
>
> Note: the sealed payload is honest JSON, but the first `HackCTF{...}` in it is
> NOT the admin reset token.

| Hint | Interpretation |
|---|---|
| "mints request-ids from an internal sequence generator" | The ids are raw generator output, not hashed or keyed. |
| "mints the admin password-reset token from the very same generator" | Predicting the id stream predicts the security token. There is no domain separation. |
| "some consecutive request-ids" | Consecutive is the key word: adjacency lets us verify a candidate against every following id. |
| "grabbed the generator's code from a core dump" | White-box attack: `A`, `C`, `MASK`, `LOW_BITS` are all known. |
| "sealed with the NEXT value the generator will produce" | We must predict `s₁₁`, one step after the last logged state. |
| "honest JSON, but the first `HackCTF{...}` is NOT the admin reset token" | There is a decoy field; select by field name, not by regex order. |
| `HackCTF{...}` | Standard HackCTF flag format. |

The brief is unusually generous. It tells you the attack class (predict the next
generator value), the data you need (consecutive outputs), and the trap (decoy
flag). The work is mostly careful bookkeeping.

---

## 3. Environment and Tooling

| Item | Value |
|---|---|
| Target | Local files in `Token_Forge/` (no network service) |
| Generator | 64-bit LCG, PCG-64 constants |
| Known output | Top 32 bits of 10 consecutive states |
| Secret | Low 32 bits of the first state |
| Seal | `SHA256(b"reqid-seal-" + str(next_state))` then a SHA-256 counter-mode keystream |
| Tools used | `ls`, `read`, `gcc -O2`, `python3` (stdlib: `hashlib`, `re`, `json`) |
| Search cost | 2³² candidates, ~2 s in optimized C, ~9 min in pure Python |
| Reproducer | `Token_Forge/solve.c` + `Token_Forge/solve.py` |
| Full plaintext | §14.7 |
| Time to solve | ~5 minutes of work, ~2 s of compute |

GCC is the only non-stdlib dependency. If it is unavailable, `solve.py --python`
runs the same search in pure Python.

---

## 4. Phase 0 — File Enumeration

```bash
$ ls -la /home/boss/Works/ctf/Zero_trace/Token_Forge
total 12
drwxr-xr-x 1 boss boss  88 Oct 25 18:48 .
drwxr-xr-x 1 boss boss 334 Oct 25 18:47 ..
-rw-r--r-- 1 boss boss 576 Oct 25 18:47 admin_reset.sealed
-rw-r--r-- 1 boss boss 301 Oct 25 18:48 request_ids.log
-rw-r--r-- 1 boss boss 634 Oct 25 18:48 tokengen.py
```

Observations:

1. **Three small files.** The whole challenge fits in memory and can be read
   completely, line by line.
2. **`tokengen.py` is ~634 bytes.** The generator is simple enough to verify by
   hand.
3. **`request_ids.log` is 301 bytes.** Ten 13-character lines plus comments —
   ten outputs.
4. **`admin_reset.sealed` is 576 bytes,** mostly a single hex ciphertext line.

No README and no key file. Everything needed must be derivable from these three
artifacts.

---

## 5. Phase 1 — Source Review

### 5.1 The leaked generator

```python
#!/usr/bin/env python3
"""edge-gateway internal sequence generator  (leaked from a core dump).

The gateway mints request-ids and the admin password-reset token from the
same sequence generator. `request_ids.log` holds consecutive ids (the
HIGH bits of successive states). `admin_reset.sealed` was sealed with the
NEXT state after the last logged id.
"""

A = 6364136223846793005
C = 1442695040888963407
MASK = (1 << 64) - 1
LOW_BITS = 32


def next_state(s: int) -> int:
    return (A * s + C) & MASK


def token(s: int) -> int:
    """Public id = top (64-LOW_BITS) bits of the state; low bits discarded."""
    return s >> LOW_BITS
```

### 5.2 Line-by-line analysis

| Element | Meaning | Security relevance |
|---|---|---|
| `A = 6364136223846793005` | LCG multiplier, `0x5851f42d4c957f2d` | Known; standard PCG-64 value |
| `C = 1442695040888963407` | LCG increment, `0x14057b7ef767814f` | Known; standard PCG-64 value |
| `MASK = (1 << 64) - 1` | Arithmetic modulo 2⁶⁴ | State space is 2⁶⁴ |
| `LOW_BITS = 32` | How many low bits are discarded | **Only 32 bits of state are hidden** |
| `next_state(s)` | `(A·s + C) mod 2⁶⁴` | Fully deterministic, no secret input |
| `token(s)` | `s >> 32` | Emits the **top 32 bits** of the state |
| Docstring | "sealed with the NEXT state after the last logged id" | Fixes the off-by-one target explicitly |

The two constants are the well-known PCG-64 LCG constants, which is a tell: this
is a general-purpose PRNG, not a cryptographic one. But even a "good" LCG would
fail here, because the construction leaks state.

### 5.3 The critical observation

A truncated LCG with a **known recurrence** is not safe just because part of the
state is hidden. Writing the state as

```
sᵢ = (tᵢ << 32) | lᵢ        where tᵢ = token(sᵢ),  lᵢ ∈ [0, 2³²)
```

the recurrence splits cleanly:

```
lᵢ₊₁ = (A·lᵢ + C) mod 2³²                                  (low half, independent)
tᵢ₊₁ = (A·tᵢ + carry(lᵢ)) mod 2³²                          (high half, depends on lᵢ)
```

So **one** unknown 32-bit value, `l₁`, determines the entire chain. Each
additional logged id is an independent 32-bit check on that value. With nine
checks, false positives are astronomically unlikely: the expected number of
survivors after nine filters is `2³² / (2³²)⁹`, i.e. one in 2²⁵⁶ — in practice
either exactly one solution or none.

This is the whole challenge. Everything else is implementation.

### 5.4 The request-id log

```text
# edge-gateway request-id log  (newest requests get a fresh id)
# ids are emitted by the service's internal sequence generator
# one id per line, oldest first:

req-032a38bf3
req-0b67f750a
req-0b658d79a
req-00c1f3bf4
req-0d4b95a26
req-0a4bd019e
req-0f0759990
req-0fd8be8bf
req-0e3b17eea
req-0b7bb3059
```

Ten ids, oldest first, consecutive. The ordering matters only for the initial
brute-force state; the chain check works in either direction once you know it.

### 5.5 The sealed blob

```text
# admin password-reset payload, sealed with the NEXT request-id's FULL state
# key  = SHA256(b'reqid-seal-' + str(next_state).encode())
# ks   = SHA256(key + counter_be32), counter from 0; payload = ct XOR ks
ciphertext_hex: 1d4f9c59...5774b9aec
```

The seal is a hand-rolled SHA-256 counter-mode stream cipher. It is not the hard
part. The key is `SHA256("reqid-seal-" + str(next_state))`, and the format is
explicit: decimal `str()` of an integer, big-endian 32-bit counter starting at 0.
Two details that will bite later:

- `str(next_state)` is **decimal**, not hex.
- The counter is **big-endian** (`counter_be32`).

---

## 6. Phase 2 — Attack Design

Before touching the data, several approaches were considered. Recording the
rejected ones is useful because the correct path is cheap only if you avoid the
expensive ones.

### 6.1 Option A — brute-force the 64-bit seed

- **Idea:** try every seed in `[0, 2⁶⁴)`, generate ids, compare.
- **Cost:** 2⁶⁴ ≈ 1.8 × 10¹⁹ candidates. Even at 10⁹/s that is ~580 years.
- **Why it fails:** the seed is not even given, and a 64-bit search is infeasible.
- **Decision:** rejected.

### 6.2 Option B — brute-force the low 32 bits of the first state

- **Idea:** `s₁ = (t₁ << 32) | l₁`. Try all `l₁`, advance the LCG, and require
  the next nine top-32-bit outputs to match the log.
- **Cost:** 2³² candidates; a single multiply-and-compare per candidate with
  early exit. Seconds in C.
- **Why it works:** the recurrence is known, so the low 32 bits are the only
  missing information.
- **Decision:** **chosen.**

### 6.3 Option C — lattice attack on truncated LCG outputs

- **Idea:** the Frieze–Hastad–Kannan–Lagarias style lattice reduction recovers a
  truncated LCG state from partial outputs when the multiplier is unknown.
- **Cost:** nontrivial lattice setup (LLL/BKZ), extra libraries, careful scaling.
- **Why it is unnecessary:** the multiplier and increment are *known*, and only
  32 bits are missing. A 2³² search is far simpler and faster than building a
  lattice and hoping the parameters are favorable.
- **Decision:** rejected as overkill.

### 6.4 Option D — recover the state from a single id

- **Idea:** invert `token()` or use algebra on one output.
- **Why it fails:** `token()` is lossy. Each id leaves 2³² possible full states.
  One output is never enough.
- **Decision:** rejected.

### 6.5 Option E — find the seed in the files

- **Idea:** maybe the core dump leaked the seed.
- **Result of review:** no seed, no config, no key file. Only A, C, mask, and
  the truncation width.
- **Decision:** rejected.

### 6.6 Option F — attack the SHA-256 seal directly

- **Idea:** treat the seal as a stream cipher and recover the keystream from
  known JSON.
- **Why it fails:** the key is `SHA256("reqid-seal-" + str(state))`. Even knowing
  the full keystream does not reveal `state` (preimage resistance). The seal is
  not the weak link; the *state prediction* is.
- **Decision:** rejected. The attack must go through the LCG.

### 6.7 Option G — assume the ids encode the state in a different way

- **Idea:** maybe `token()` uses the low bits, or a mixed output.
- **Result of review:** the code is unambiguous: `s >> LOW_BITS`. Top bits only.
- **Decision:** rejected.

### 6.8 Decision table

| Option | Approach | Cost | Verdict |
|---|---|---|---|
| A | Brute-force 64-bit seed | 2⁶⁴ | Rejected — infeasible |
| B | Brute-force low 32 bits of `s₁` | 2³², seconds | **Chosen** |
| C | Lattice reduction on truncated outputs | High complexity | Rejected — unnecessary with known A, C |
| D | Invert a single id | 2³² ambiguity | Rejected — insufficient data |
| E | Find the seed on disk | N/A | Rejected — not present |
| F | Attack SHA-256 seal directly | 2²⁵⁶ | Rejected — wrong layer |
| G | Reinterpret `token()` | N/A | Rejected — code is clear |

The meta-lesson: when the recurrence and the truncation width are known, the
attack surface is exactly the truncated bits. Do not solve a harder problem.

---

## 7. Phase 3 — First Friction, Format Doubts, and the Off-by-One Trap

This section records the points where the solve could have gone wrong, and the
checks that kept it on track. Some were live moments of doubt; others were
failure modes deliberately reproduced afterwards to confirm they matter. They
are labelled honestly.

### 7.1 F1 — The request-id format looks like 36 bits, not 32

The first thing that stands out is the width of the ids:

```text
req-032a38bf3      ← 9 hex characters
req-0b67f750a
req-0b658d79a
...
```

`token(s) = s >> 32` returns a value `< 2³²`, which is at most 8 hex digits.
Yet every id has **9** hex characters. At first glance `0x032a38bf3` is a
36-bit-looking number, which contradicts the source.

**Resolution:** the leading `0` is numerically a no-op. `int("032a38bf3", 16)`
is exactly `0x32a38bf3`. The ids are 8-hex-digit 32-bit values printed with
zero-padding to 9 characters (consistent with a `%09x`-style format, or a fixed
`"0"` prefix). Confirming with bit lengths:

```text
parsed:     0x32a38bf3 0xb67f750a 0xb658d79a 0x0c1f3bf4 ...
bit lengths:    30         32         32         28      ...
```

All values are `≤ 32` bits. The format is a cosmetic zero-pad, not extra
entropy. **No change to the attack was needed**, but this was the first place a
solver could have mis-parsed the log (e.g., by treating the ids as 36-bit
numbers and shifting by the wrong amount). The check was: every parsed value
must fit in 32 bits, or the model is wrong.

> **Lesson:** when a printed value is wider than the field it should represent,
> check whether the extra character is padding before changing your bit
> arithmetic.

### 7.2 F2 — Pure Python is workable but ~270× slower than C

The natural first implementation is Python. A micro-benchmark of the inner loop:

```text
python: 4,194,304 steps in 0.525 s = 7,989,298 steps/s
extrapolated 2^32 full scan: 0.15 hours (~9 minutes), single core
```

So Python *would* finish, but ~9 minutes is long for a search that has a known,
trivial C implementation. The approach was changed to C with `-O2`:

```text
$ gcc -O2 -o solve solve.c && time ./solve
MATCH lo=2850667235 state0=0x32a38bf3a9e9bae3 next=0x426a53911d4bc615
total matches: 1
real  0m2.0s
```

**Change:** move the 2³² loop to C. Keep Python for parsing and decryption,
where performance is irrelevant. This is a real approach change, not a
theoretical one: the first instinct (script it in Python) was measured and
replaced.

> **Lesson:** measure before committing to a language for a hot loop. A 2³²
> search is borderline in Python and trivial in C.

### 7.3 F3 — Naive verification multiplies the cost by 9

The obvious candidate loop checks **all nine** following ids for every low-bit
guess:

```python
for lo in range(2**32):
    s = (t[0] << 32) | lo
    for i in range(1, 10):
        s = nx(s)
        if (s >> 32) != t[i]:
            fail
```

Worst case that is `2³² × 9 ≈ 3.9 × 10¹⁰` state advances. The fix is standard
**early exit**: check the very next state first and break on mismatch. Under a
random model, only ~1 candidate in 2³² survives the first check, so the
amortized cost collapses to ~`2³²` single-step checks plus a negligible tail.

```c
for (uint64_t lo = 0; lo < (1ULL << 32); lo++) {
    uint64_t cur = ((uint64_t)t[0] << 32) | lo;
    int ok = 1;
    for (int i = 1; i < 10; i++) {
        cur = nx(cur);
        if ((uint32_t)(cur >> 32) != t[i]) { ok = 0; break; }   // early exit
    }
    ...
}
```

**Change:** order the checks so the cheapest discriminator runs first and break
immediately. This is why the run is ~2 s and not ~20 s.

> **Lesson:** in a brute-force search, the first filter should reject almost
> everything. Never compute the full verification for every candidate.

### 7.4 F4 — The off-by-one: `s₁₁`, not `s₁₀`

The brief says the token is sealed with "the NEXT value the generator will
produce" and the source says "sealed with the NEXT state after the last logged
id". The last logged id is the **top 32 bits of `s₁₀`**. The state used for the
seal is therefore `s₁₁ = next_state(s₁₀)`, **not** `s₁₀`.

This is the highest-risk mistake in the challenge, because `s₁₀` is a perfectly
valid-looking 64-bit value and its top 32 bits match the last log line. Using it
silently produces garbage instead of valid JSON.

Reproduced deliberately afterwards:

| Key state used | Value | Output valid JSON? |
|---|---|---|
| `s₁₀` (last logged state) | `13239228689286382494` | no — mojibake |
| seed (2 steps early) | `1013305268337261668` | no — mojibake |
| `s₁₁` (correct next state) | `4785729436761441813` | **yes** |
| `s₁₂` (1 step too far) | `8941487093624258048` | no — mojibake |

**Change:** define the target explicitly as `next_state(s₁₀)` and verify by
walking *backwards* `len(ids)` times from the candidate, which must land exactly
on `s₁`. That back-walk check catches off-by-one errors mechanically.

> **Lesson:** "next" is relative. Anchor it to a concrete element (the last
> logged state) and verify the index with a forward/backward consistency check.

### 7.5 F5 — Counter endianness is load-bearing

The comment says `counter_be32`. Big-endian. Using little-endian produces a
plaintext that starts correctly and then degrades into garbage, because the
first 32 bytes use counter `0` (identical in both endiannesses — all zero bytes)
and only later blocks diverge. Reproduced:

```text
--- CORRECT (big-endian): {"issued_by":"edge-gateway","kind":"password-reset",...  (175/175 printable)
--- WRONG (little-endian): {"issued_by":"edge-gateway","kin<garbage>...             (147/167 printable)
```

This is a classic "first block looks fine" trap. If you only check the first few
bytes, you might believe a wrong key is right.

**Change:** take the endianness from the comment literally and validate the
**entire** plaintext (`json.loads` on the whole thing), not a prefix.

> **Lesson:** counter-mode keystreams with a zero initial counter can mask an
> endianness bug for the first block. Always validate the full output.

---

## 8. Phase 4 — State Recovery

### 8.1 The search

The C solver is in `solve.c`. The core:

```c
static const uint64_t A = 6364136223846793005ULL;
static const uint64_t C = 1442695040888963407ULL;
static inline uint64_t nx(uint64_t s){ return A*s + C; }

uint32_t t[10] = {
    0x32a38bf3u, 0xb67f750au, 0xb658d79au, 0x0c1f3bf4u, 0xd4b95a26u,
    0xa4bd019eu, 0xf0759990u, 0xfd8be8bfu, 0xe3b17eeau, 0xb7bb3059u
};

for (uint64_t lo = 0; lo < (1ULL << 32); lo++) {
    uint64_t cur = ((uint64_t)t[0] << 32) | lo;
    int ok = 1;
    for (int i = 1; i < 10; i++) {
        cur = nx(cur);
        if ((uint32_t)(cur >> 32) != t[i]) { ok = 0; break; }
    }
    if (ok) { /* report state0 and next = nx(cur) */ }
}
```

Note `nx` relies on unsigned `uint64_t` wraparound, which is exactly the
`& MASK` in Python. `(uint32_t)(cur >> 32)` extracts the top 32 bits.

### 8.2 The result

```text
$ gcc -O2 -o solve solve.c && time ./solve
MATCH lo=2850667235 state0=0x32a38bf3a9e9bae3 next=0x426a53911d4bc615 next_dec=4785729436761441813
total matches: 1

real    0m1.995s
user    0m1.988s
sys     0m0.000s
```

- Recovered low half: `2850667235 = 0xa9e9bae3`.
- Recovered first state: `0x32a38bf3a9e9bae3`.
- **Next state: `0x426a53911d4bc615` = `4785729436761441813`.**
- **Exactly one candidate** survives all nine checks.

### 8.3 The full state chain

Every logged id is reproduced exactly by the recovered chain:

| # | State (hex) | Top 32 bits | Logged id | Match |
|---|---|---|---|---|
| 1 | `32a38bf3a9e9bae3` | `32a38bf3` | `req-032a38bf3` | ✓ |
| 2 | `b67f750af352f836` | `b67f750a` | `req-0b67f750a` | ✓ |
| 3 | `b658d79a658deccd` | `b658d79a` | `req-0b658d79a` | ✓ |
| 4 | `0c1f3bf4e924d458` | `0c1f3bf4` | `req-00c1f3bf4` | ✓ |
| 5 | `d4b95a26ef707cc7` | `d4b95a26` | `req-0d4b95a26` | ✓ |
| 6 | `a4bd019e8fe7294a` | `a4bd019e` | `req-0a4bd019e` | ✓ |
| 7 | `f0759990f0977951` | `f0759990` | `req-0f0759990` | ✓ |
| 8 | `fd8be8bf0f5c038c` | `fd8be8bf` | `req-0fd8be8bf` | ✓ |
| 9 | `e3b17eeaf0d294eb` | `e3b17eea` | `req-0e3b17eea` | ✓ |
| 10 | `b7bb30593513439e` | `b7bb3059` | `req-0b7bb3059` | ✓ |
| **11** | **`426a53911d4bc615`** | `426a5391` | *not logged* | **target** |

The next state is the first one with no corresponding log line, which is exactly
the value the seal used.

---

## 9. Phase 5 — Unsealing the Payload

### 9.1 Deriving the key

Per the header comment:

```
key = SHA256(b"reqid-seal-" + str(4785729436761441813))
```

The `str()` is Python decimal formatting — not hex, not bytes. Computing it:

```text
key = afbfbed5c3c10f05462ce2a84bb344eb5e02ec9b5bf437b6b13fa5035f738ca4
```

### 9.2 Generating the keystream

The ciphertext is **175 bytes**. Each `SHA256` output is 32 bytes, so six
counter blocks are needed:

```
block 0: SHA256(key || 00000000)
block 1: SHA256(key || 00000001)
...
block 5: SHA256(key || 00000005)   (truncated at byte 175)
```

XOR the concatenated keystream with the ciphertext:

```python
key = hashlib.sha256(b"reqid-seal-" + str(next_state).encode()).digest()
out = bytearray()
for counter in range((len(ct) + 31) // 32):
    ks = hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
    chunk = ct[counter*32:(counter+1)*32]
    out += bytes(a ^ b for a, b in zip(chunk, ks))
```

### 9.3 The plaintext

```json
{"issued_by":"edge-gateway","kind":"password-reset","preview_token":"HackCTF{just_th3_t0k3n_n0t_th3_st4t3}","admin_reset_token":"HackCTF{trunc4t3d_lcg_st1ll_l34ks_th3_st4t3}"}
```

It is 175 bytes, valid UTF-8, and `json.loads` parses it. That is the proof the
key was right: a wrong state produces non-JSON garbage (§7.4).

---

## 10. Phase 6 — Decoy Triage

### 10.1 The first-match temptation

A naive solver greps the decrypted blob:

```bash
grep -o 'HackCTF{[^}]*}' plaintext.json | head -1
```

That returns:

```
HackCTF{just_th3_t0k3n_n0t_th3_st4t3}
```

This is the `preview_token` field. The vulnerable name is practically a taunt —
`just_th3_t0k3n_n0t_th3_st4t3` ("just the token, not the state"). The challenge
note warned about exactly this:

> the first `HackCTF{...}` in it is NOT the admin reset token.

Because JSON preserves insertion order and `preview_token` appears before
`admin_reset_token`, a first-match regex reliably hits the decoy.

### 10.2 Selecting the right field

The brief asks for the **admin password-reset token**. The JSON field is
literally `admin_reset_token`:

```json
"admin_reset_token": "HackCTF{trunc4t3d_lcg_st1ll_l34ks_th3_st4t3}"
```

Selection is by **field name**, not by regex order, not by "which looks more
real". The correct extraction in the solver:

```python
flag = re.search(r'"admin_reset_token"\s*:\s*"(HackCTF\{[^}]+\})"', pt.decode()).group(1)
```

### 10.3 Why this is a realistic trap

Incident-response and backup tooling routinely carries stale or preview
credentials alongside live ones. A correct recovery workflow keys off the
identifier, never off "the first secret-looking string". The challenge encodes
that operational discipline directly.

---

## 11. Phase 7 — Verification

Five independent checks were performed.

### 11.1 Chain check

Starting from the recovered `state0`, all ten logged top-32-bit values match
(§8.3). This is the primary check: a wrong low half fails within the first one
or two successors.

### 11.2 Candidate uniqueness

The solver reports `total matches: 1`. There is no ambiguity to resolve. If the
search had returned zero, the parsing/model would have been wrong (e.g., wrong
byte order in the id string); if it had returned more than one, more log lines
would disambiguate.

### 11.3 Backward walk to the seed

`A` is odd, so it is invertible modulo 2⁶⁴. The state two steps before `state0`
(the original seed) is recoverable:

```python
A_inv = pow(A, -1, 1 << 64)               # 0xc097ef87329e28a5
seed  = ((state0 - C) * A_inv) & MASK     # 0x0e0ffbc5d8463c64
```

Forward check:

```text
(A * 0x0e0ffbc5d8463c64 + C) mod 2^64 = 0x32a38bf3a9e9bae3 = state0   ✓
```

This is not needed for the attack, but it proves `state0` is a genuine LCG state
reachable from a real seed, not an artifact of a lucky collision. The solver also
uses the inverse walk backwards `len(ids)` times from the candidate to confirm it
lands on `state0` — a mechanical off-by-one guard.

### 11.4 Wrong-key negative controls

Deliberately using the wrong state produces non-JSON garbage (§7.4). The correct
state produces 175/175 printable bytes and parses as JSON. This rules out the
"any key looks close enough" failure mode.

### 11.5 End-to-end reproducer

`solve.py` re-derives everything from the three shipped files:

```text
[*] loaded 10 consecutive request-ids
[*] C search (2^32 low-bit candidates)…
[+] next state = 4785729436761441813 (0x426a53911d4bc615)
[+] plaintext:
{"issued_by":"edge-gateway","kind":"password-reset","preview_token":"HackCTF{just_th3_t0k3n_n0t_th3_st4t3}","admin_reset_token":"HackCTF{trunc4t3d_lcg_st1ll_l34ks_th3_st4t3}"}

[+] FLAG: HackCTF{trunc4t3d_lcg_st1ll_l34ks_th3_st4t3}
```

---

## 12. Consolidated Failure Log and Approach Changes

### 12.1 Note on honesty

This solve was close to one-shot at the cryptographic level. The design in §6
identified the correct attack before execution, and the first correct C
implementation worked. The entries below are a mix of **live** adjustments
(F1, F2, F3, and the off-by-one/endianness checks in F4/F5) and **failure modes
reasoned about up front, then reproduced deliberately** to confirm they actually
break the solve. Each is labelled. Nothing is invented as a live dead end when
it was not.

### 12.2 Failure log

| ID | Type | Attempt | Result | Diagnosis | Change / guard | Lesson |
|---|---|---|---|---|---|---|
| F1 | Live doubt | Treat 9-hex-char ids as 36-bit values | Contradicts `token() = s >> 32` | Leading `0` is zero-padding; values are ≤32 bits | Parse `int(id, 16)`; assert every value `< 2³²` | Check for padding before changing bit math |
| F2 | Live | Python brute force over 2³² | ~8M steps/s → ~9 min | Python int loop is slow for a hot 2³² search | Reimplemented the loop in C (`-O2`) → ~2 s | Measure the hot loop; use the right tool |
| F3 | Design | Verify all 9 successors per candidate | ~3.9 × 10¹⁰ operations | 9× wasted work | Early exit on the first mismatching successor | First filter must reject almost everything |
| F4 | Live risk | Use `s₁₀` (last logged state) as the seal key | Mojibake, invalid JSON | Seal uses the **next** state `s₁₁` | Define target as `next_state(s₁₀)`; back-walk `len(ids)` steps to `s₁` | "Next" is relative — anchor and verify the index |
| F5 | Live risk | Little-endian counter in the SHA-256 stream | First block correct, later blocks garbage | Header says `counter_be32`; counter 0 is endian-agnostic | Use big-endian; validate **entire** plaintext with `json.loads` | Zero initial counters mask endianness bugs |
| F6 | Design | First regex `HackCTF{...}` match | Returns `preview_token` | Decoy precedes the real field | Select by `admin_reset_token` field name | Never select secrets by regex order |

### 12.3 Approach-change summary

1. **From "try everything" to "only the truncated bits matter."** Once `A`, `C`,
   and `LOW_BITS` are known, the unknown is exactly 32 bits. Lattice attacks,
   seed brute force, and seal preimage attacks were all rejected in favor of a
   targeted 2³² search.
2. **From Python to C for the hot loop.** Measured, not assumed: Python would
   take ~9 minutes; C takes ~2 seconds.
3. **From full verification to early-exit filtering.** Reduces the search from
   `9 × 2³²` to ~`2³²` operations.
4. **From "last id" to "next state."** The seal target is `s₁₁`, not `s₁₀`;
   enforced by a backward-walk consistency check.
5. **From prefix validation to full-plaintext validation.** Catches the
   endianness trap that the first keystream block hides.
6. **From first-regex-match to field-name selection.** Avoids the decoy flag.

---

## 13. Attack Chain Diagram

```text
┌─────────────────────────────────────────────────────────────────────┐
│  Public artifacts                                                    │
│    request_ids.log : 10 consecutive top-32-bit states                │
│    tokengen.py     : A, C, MASK=2^64-1, LOW_BITS=32                  │
│    admin_reset.sealed : ciphertext + key/keystream recipe            │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
        sᵢ = (tᵢ << 32) | lᵢ ; only l₁ unknown (32 bits)
                              │
                              ▼
        for l₁ in [0, 2³²):  s₂…s₁₀ top bits == log?
                              │  early exit on first mismatch
                              ▼
        unique  state0 = 0x32a38bf3a9e9bae3
                              │
                              ▼
        advance 10 times → state10 = 0xb7bb30593513439e
        advance once more → state11 = 0x426a53911d4bc615  (target)
                              │
                              ▼
        key = SHA256("reqid-seal-" + str(state11))
        ks  = SHA256(key || be32(counter)) , counter = 0,1,2,…
                              │
                              ▼
        plaintext = ct XOR ks  →  valid JSON
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
   preview_token (DECOY)          admin_reset_token (REAL)
   HackCTF{just_th3_t0k3n…}       HackCTF{trunc4t3d_lcg_st1ll_l34ks_th3_st4t3}
```

---

## 14. Evidence Appendix

### 14.1 File listing

```text
$ ls -la /home/boss/Works/ctf/Zero_trace/Token_Forge
-rw-r--r-- 1 boss boss  576 Oct 25 18:47 admin_reset.sealed
-rw-r--r-- 1 boss boss  301 Oct 25 18:48 request_ids.log
-rw-r--r-- 1 boss boss  634 Oct 25 18:48 tokengen.py
```

### 14.2 Parsed request-ids

```text
ids:  032a38bf3 0b67f750a 0b658d79a 00c1f3bf4 0d4b95a26
      0a4bd019e 0f0759990 0fd8be8bf 0e3b17eea 0b7bb3059
hex:  0x32a38bf3 0xb67f750a 0xb658d79a 0x0c1f3bf4 0xd4b95a26
      0xa4bd019e 0xf0759990 0xfd8be8bf 0xe3b17eea 0xb7bb3059
bits: 30 32 32 28 32 32 32 32 32 32      (all ≤ 32 → leading 0 is padding)
```

### 14.3 Brute-force output

```text
MATCH lo=2850667235 state0=0x32a38bf3a9e9bae3 next=0x426a53911d4bc615 next_dec=4785729436761441813
total matches: 1

real    0m1.995s
user    0m1.988s
sys     0m0.000s
```

### 14.4 Backward seed recovery

```text
A_inv       = 0xc097ef87329e28a5
seed        = 0x0e0ffbc5d8463c64  (1013305268337261668)
forward     = 0x32a38bf3a9e9bae3  = state0   ✓
```

### 14.5 Seal key

```text
next_state  = 4785729436761441813
key         = afbfbed5c3c10f05462ce2a84bb344eb5e02ec9b5bf437b6b13fa5035f738ca4
ct length   = 175 bytes  →  6 keystream blocks (192 bytes, truncated)
```

### 14.6 Wrong-state negative controls

| Key state | Decimal value | Valid JSON? | Printable ratio |
|---|---|---|---|
| `s₁₀` last logged | `13239228689286382494` | no | 141/168 |
| seed (2 early) | `1013305268337261668` | no | 144/166 |
| **`s₁₁` correct** | **`4785729436761441813`** | **yes** | **175/175** |
| `s₁₂` (1 late) | `8941487093624258048` | no | 141/163 |
| `s₁₁`, LE counter | `4785729436761441813` | no | 147/167 |

(The ratios are approximate because invalid UTF-8 is replaced during decoding;
the decisive column is "valid JSON?".)

### 14.7 Full plaintext

```json
{"issued_by":"edge-gateway","kind":"password-reset","preview_token":"HackCTF{just_th3_t0k3n_n0t_th3_st4t3}","admin_reset_token":"HackCTF{trunc4t3d_lcg_st1ll_l34ks_th3_st4t3}"}
```

### 14.8 Field table

| Field | Value | Role |
|---|---|---|
| `issued_by` | `edge-gateway` | Provenance |
| `kind` | `password-reset` | Payload type |
| `preview_token` | `HackCTF{just_th3_t0k3n_n0t_th3_st4t3}` | **Decoy** |
| `admin_reset_token` | `HackCTF{trunc4t3d_lcg_st1ll_l34ks_th3_st4t3}` | **Real flag** |

---

## 15. Root Cause

The failure is architectural, not a small coding bug.

1. **Truncation is not hiding.** Discarding the low 32 bits leaves a 64-bit
   state with only 32 bits of uncertainty. With a known recurrence and
   consecutive outputs, 32 bits is trivially searchable. The security margin is
   `2³²`, not `2⁶⁴`.
2. **Secret and public values share a generator.** Request-ids are public by
   design; the reset token is a credential. Deriving one from the other — even
   indirectly, through a shared state stream — destroys the credential's secrecy.
3. **The seal key is a deterministic function of predictable state.** Once the
   state is known, the key is recomputable. There is no independent secret.
4. **No cryptographic PRNG.** The PCG-64 LCG is a statistical PRNG, not a CSPRNG.
   It is predictable by construction; predictability is a feature for
   reproducibility and a fatal flaw for secrets.
5. **State is exposed directly.** `token()` emits raw top bits of the internal
   state rather than a keyed, one-way transformation.

Any one of these is serious; together they make the token forgeable in seconds.

---

## 16. Remediation

### 16.1 For the token

- Generate reset tokens with a **CSPRNG**: `secrets.token_urlsafe(32)`,
  `os.urandom(32)`, or the platform's `getrandom`. Never a general-purpose LCG.
- Store only a **hash** of the token server-side (`SHA-256` or an HMAC with a
  server key), and compare in constant time.
- Bind the token to the user, purpose, and a short expiry; make it single-use.
- Rotate/invalidate the leaked admin reset token immediately.

### 16.2 For request-ids

- If ids must be opaque, generate them independently with a CSPRNG (e.g.,
  128-bit random), not from a counter/PRNG that also feeds secrets.
- If ids must be sequential, keep them as a **separate** counter that no secret
  derivation touches, and never expose generator state.

### 16.3 For the architecture

- **Domain separation:** credentials and public identifiers must never share a
  state stream, key, or seed.
- **Keyed derivation:** if a value must be derived from a sequence, derive it
  with a secret key, e.g., `HMAC-SHA256(server_key, counter)`, so observing the
  public output does not reveal the credential.
- **AEAD:** replace the hand-rolled XOR seal with AES-GCM or
  ChaCha20-Poly1305, with a random nonce and authentication tag.
- **Threat model:** assume an attacker sees all public outputs. If a secret can
  be predicted from public outputs, the design is broken.

### 16.4 Minimum patch for this codebase

```python
import os, hashlib, hmac

# tokens: independent CSPRNG, stored hashed
reset_token = os.urandom(32)
stored = hashlib.sha256(reset_token).digest()

# request ids: random, 128-bit
request_id = os.urandom(16).hex()

# if a sequence must drive a secret, key it:
# secret = hmac.new(server_key, counter.to_bytes(8, "big"), hashlib.sha256).digest()
```

---

## 17. Detection Opportunities (Blue Team)

- **Entropy monitoring on identifiers:** request-ids that are sequential or
  low-entropy should be flagged. Here the ids are truncated LCG states and will
  fail basic randomness/entropy tests over time.
- **Reset-token anomaly detection:** alert on resets that occur without a
  corresponding user request, or on tokens that validate for the wrong account.
- **Rate/pattern detection:** mass token validation attempts, or tokens
  generated in bursts consistent with prediction.
- **Code review signal:** any security token whose key derivation references a
  non-cryptographic PRNG, a counter, or a public identifier is a finding.
- **Log correlation:** a spike in request-ids followed by an admin reset within
  the same generator window is suspicious.

---

## 18. Lessons Learned

1. **"Truncated output" ≠ "hidden state."** For a known LCG, hiding 32 of 64
   bits leaves a 2³² search — trivial. The effective security is the hidden
   entropy, not the state size.
2. **Never share a state stream between public and secret values.** This is the
   root of the whole challenge.
3. **Consecutive outputs are the enabler.** A single truncated output is
   ambiguous by 2³²; ten consecutive ones pin the state uniquely.
4. **Brute force is the right tool when the unknown is 32 bits.** Do not reach
   for lattices when a two-second search suffices.
5. **Measure the hot loop.** Python ~9 min vs C ~2 s; know before you commit.
6. **Early-exit filters matter.** Checking the cheapest discriminator first cut
   the work by ~9×.
7. **Anchor "next" concretely.** The seal used `s₁₁`, not `s₁₀`; a backward walk
   makes the index provable.
8. **Validate the whole plaintext.** A zero initial counter hides endianness
   bugs in the first block.
9. **Select secrets by name, not by regex order.** The decoy is designed to be
   the first match.
10. **Read the comments literally.** `str(next_state)`, `counter_be32`, and
    "NEXT state" were all accurate and all load-bearing.

---

## 19. Timeline

| Step | Action | Outcome |
|---|---|---|
| 1 | Enumerated `Token_Forge/` | Three files: generator, log, sealed blob |
| 2 | Read `tokengen.py` | 64-bit LCG, top-32-bit output, known A/C |
| 3 | Read `request_ids.log` | 10 consecutive ids, 9 hex chars each |
| 4 | Resolved 9-char format doubt | Leading `0` is padding; values ≤32 bits |
| 5 | Designed attack options | Rejected seed brute force, lattice, seal preimage |
| 6 | Chose low-32-bit search | 2³² candidates, known recurrence |
| 7 | Benchmarked Python | ~9 min; switched hot loop to C |
| 8 | Added early-exit filtering | ~`2³²` effective operations |
| 9 | Compiled and ran C solver | Unique match in ~2 s |
| 10 | Recovered `s₁₁` | `4785729436761441813` |
| 11 | Derived seal key | `SHA256("reqid-seal-" + str(s₁₁))` |
| 12 | Unsealed ciphertext | 175-byte valid JSON |
| 13 | Triaged fields | `preview_token` decoy; `admin_reset_token` real |
| 14 | Verified | Chain, uniqueness, backward seed, negative controls |
| 15 | Wrote solver | `solve.c` + `solve.py` reproduce result |

---

## 20. Appendix — Solver Code

### 20.1 `solve.c` — the 2³² search

```c
#include <stdio.h>
#include <stdint.h>

static const uint64_t A = 6364136223846793005ULL;
static const uint64_t C = 1442695040888963407ULL;

static inline uint64_t nx(uint64_t s){ return A*s + C; }

int main(void){
    /* top 32 bits observed, oldest first */
    uint32_t t[10] = {
        0x32a38bf3u, 0xb67f750au, 0xb658d79au, 0x0c1f3bf4u, 0xd4b95a26u,
        0xa4bd019eu, 0xf0759990u, 0xfd8be8bfu, 0xe3b17eeau, 0xb7bb3059u
    };
    uint64_t found = 0;
    for(uint64_t lo=0; lo<(1ULL<<32); lo++){
        uint64_t s = ((uint64_t)t[0]<<32) | lo;
        uint64_t cur = s;
        int ok = 1;
        for(int i=1;i<10;i++){
            cur = nx(cur);
            if((uint32_t)(cur>>32) != t[i]){ ok=0; break; }
        }
        if(ok){
            found++;
            printf("MATCH lo=%llu state0=0x%016llx next=0x%016llx next_dec=%llu\n",
                   (unsigned long long)lo,
                   (unsigned long long)s,
                   (unsigned long long)nx(cur),
                   (unsigned long long)nx(cur));
        }
    }
    printf("total matches: %llu\n",(unsigned long long)found);
    return 0;
}
```

### 20.2 `solve.py` — parse, recover, unseal, verify

```python
#!/usr/bin/env python3
"""Token Forge — reference solver.

Stage 1 (state recovery) is brute force over the 32 unknown low bits of the
first logged state.  The C helper `solve.c` does the 2^32 search in ~2 seconds;
this script compiles and runs it automatically.  A pure-Python search is
available with --python (about 9 minutes on this host).
"""

import hashlib, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
A = 6364136223846793005
C = 1442695040888963407
MASK = (1 << 64) - 1
LOW_BITS = 32


def nx(s: int) -> int:
    return (A * s + C) & MASK


def load_ids(path=os.path.join(HERE, "request_ids.log")):
    out = []
    for line in open(path):
        m = re.match(r"req-([0-9a-fA-F]+)", line.strip())
        if m:
            out.append(int(m.group(1), 16))
    return out


def recover_c(targets):
    src = os.path.join(HERE, "solve.c")
    bin_ = os.path.join(HERE, ".solve_bin")
    subprocess.run(["gcc", "-O2", "-o", bin_, src], check=True)
    out = subprocess.run([bin_], capture_output=True, text=True, check=True).stdout
    m = re.search(r"next_dec=(\d+)", out)
    return int(m.group(1)) if m else None


def recover_python(targets):
    t0 = targets[0]
    for lo in range(1 << 32):
        s = (t0 << LOW_BITS) | lo
        cur = s
        for t in targets[1:]:
            cur = nx(cur)
            if (cur >> LOW_BITS) != t:
                break
        else:
            return nx(cur)
    return None


def unseal(next_state, path=os.path.join(HERE, "admin_reset.sealed")):
    text = open(path).read()
    ct = bytes.fromhex(re.search(r"ciphertext_hex:\s*([0-9a-fA-F]+)", text).group(1))
    key = hashlib.sha256(b"reqid-seal-" + str(next_state).encode()).digest()
    out = bytearray()
    counter = 0
    while len(out) < len(ct):
        ks = hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
        out += bytes(a ^ b for a, b in zip(ct[len(out):len(out) + 32], ks))
        counter += 1
    return bytes(out)


def main():
    targets = load_ids()
    print(f"[*] loaded {len(targets)} consecutive request-ids")

    if "--python" in sys.argv:
        print("[*] pure-Python search (slow)…")
        nxt = recover_python(targets)
    else:
        print("[*] C search (2^32 low-bit candidates)…")
        nxt = recover_c(targets)
    if nxt is None:
        sys.exit("no candidate matched the log")

    # verify the recovered state is exactly one step after the 10 logged ids:
    # walking back len(targets) steps must land on the first logged state.
    s = nxt
    a_inv = pow(A, -1, 1 << 64)
    for _ in range(len(targets)):
        s = ((s - C) * a_inv) & MASK
    assert (s >> LOW_BITS) == targets[0], "back-walk did not reach first id"
    print(f"[+] next state = {nxt} (0x{nxt:016x})")

    pt = unseal(nxt)
    print("[+] plaintext:")
    print(pt.decode())
    flag = re.search(r'"admin_reset_token"\s*:\s*"(HackCTF\{[^}]+\})"', pt.decode()).group(1)
    print(f"\n[+] FLAG: {flag}")


if __name__ == "__main__":
    main()
```

### 20.3 Run

```bash
$ cd /home/boss/Works/ctf/Zero_trace/Token_Forge
$ python3 solve.py
[*] loaded 10 consecutive request-ids
[*] C search (2^32 low-bit candidates)…
[+] next state = 4785729436761441813 (0x426a53911d4bc615)
[+] plaintext:
{"issued_by":"edge-gateway","kind":"password-reset","preview_token":"HackCTF{just_th3_t0k3n_n0t_th3_st4t3}","admin_reset_token":"HackCTF{trunc4t3d_lcg_st1ll_l34ks_th3_st4t3}"}

[+] FLAG: HackCTF{trunc4t3d_lcg_st1ll_l34ks_th3_st4t3}
```

---

## 21. Final Result

```
HackCTF{trunc4t3d_lcg_st1ll_l34ks_th3_st4t3}
```

The next generator state was `0x426a53911d4bc615` (`4785729436761441813`).
Its decimal string, fed into `SHA256("reqid-seal-" + str(state))`, unsealed the
payload. The first flag-shaped string in the JSON was the `preview_token` decoy;
the real value is the `admin_reset_token`.

The challenge is a clean demonstration that **truncating a non-cryptographic
generator's output does not hide its state**, and that **sharing a state stream
between public identifiers and secret credentials is a critical design flaw**.
