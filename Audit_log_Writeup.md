# Audit Log — HackCTF Writeup

**Challenge:** Audit Log  
**Category:** Crypto / ECDSA  
**Points:** 400  
**Flag:** `HackCTF{match_th3_k3y_n0t_just_th3_r}`

---

## 1. TL;DR

Three services (`fw-prod`, `telemetry`, `ota-cdn`) sign JSON events with ECDSA over `secp256k1`. Two `fw-prod` signatures reused the same nonce `k`, exposing the same `r`. From the two signatures:

```
k = (z1 - z2) / (s1 - s2) mod n
d = (s1 * k - z1) / r mod n
```

The recovered `d` reproduces the published `fw-prod` public key, confirming it is correct. The sealed blob is then decrypted with:

```
key = SHA256(b"fw-prod-seal-" + str(d).encode())
ks  = SHA256(key + counter_be32)   # counter = 0, 1, 2, ...
pt  = ct XOR ks
```

Recovered private key:

```
15770836630998876809320045031180303963064800215727080558172892102528819779650
```

Final flag:

```
HackCTF{match_th3_k3y_n0t_just_th3_r}
```

---

## 2. Challenge Artifacts

Two files were provided:

```
Audit_log/
├── audit.log.jsonl     # 11 signed JSONL events, ~4 KB
└── release.sealed      # sealed release blob + encryption format notes
```

### 2.1 `release.sealed`

```text
# sealed by fw-prod signing service
# key  = SHA256(b'fw-prod-seal-' + str(d).encode()), d = fw-prod ECDSA private key
# ks   = SHA256(key + counter_be32), counter from 0; flag = ct XOR ks
ciphertext_hex: 7b0df4b443574678cf2c851bd67e284d1f584a88ee0f0c8dfb26c0ea70ae252063aa717786
```

The file is not a standard sealed-box format. It is a custom XOR stream:

1. Derive a 32-byte symmetric `key` from the **decimal string representation** of the ECDSA private key `d`.
2. Build a keystream by hashing `key || counter` where the counter is a 32-bit **big-endian** integer starting at 0.
3. XOR the ciphertext with the keystream.

So the whole challenge reduces to one thing: recover `d`.

### 2.2 `audit.log.jsonl`

Each line is a JSON object:

```json
{
  "ts": 1726000000,
  "signer": "fw-prod",
  "pubkey": "0489ee2a...5478b0",
  "msg": "{\"action\":\"sign\",\"artifact\":\"fw-2.4.1.img\"}",
  "sig": "t+gm85Gd...xQOI0A==",
  "alg": "ecdsa-secp256k1-sha256"
}
```

Notes:

- `pubkey` is an uncompressed secp256k1 point: `0x04 || X(32) || Y(32)`.
- `msg` is a JSON **string**, and the string itself is what gets hashed.
- `sig` is `base64(r || s)`, with both `r` and `s` encoded as 32-byte big-endian integers.
- `z = SHA256(msg) mod n`.

The log contains 11 events from three signers:

| Signer | Events |
|---|---|
| `fw-prod` | 4 |
| `telemetry` | 4 |
| `ota-cdn` | 3 |

---

## 3. ECDSA Background

For secp256k1:

```
n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
```

A signature `(r, s)` over message hash `z` with private key `d` and nonce `k`:

```
R = k * G
r = R.x mod n
s = k^-1 * (z + r*d) mod n
```

Equivalently:

```
s * k = z + r*d  (mod n)
```

The critical property: if the same `k` is used for two different messages, `r` is identical in both signatures. That leaks the nonce and therefore the private key.

---

## 4. Step 1 — Parsing and Decoding the Log

First, load every JSONL line and decode each signature into `r` and `s`:

```python
import json, base64

rows = [json.loads(line) for line in open("audit.log.jsonl")]
for row in rows:
    raw = base64.b64decode(row["sig"])
    row["r"] = int.from_bytes(raw[:32], "big")
    row["s"] = int.from_bytes(raw[32:], "big")
```

Then compute the message hash:

```python
import hashlib

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
for row in rows:
    row["z"] = int.from_bytes(
        hashlib.sha256(row["msg"].encode()).digest(), "big"
    ) % n
```

Important: use `row["msg"]` **directly**, not `json.dumps(row["msg"])`. The quoted/escaped form would hash differently.

---

## 5. Step 2 — Hunting the Nonce Reuse

Grouping signatures by `r` immediately shows the RNG failure.

### 5.1 Reused `r` inside `fw-prod`

The `fw-2.4.2.img` and `fw-2.5.0.img` signatures share the exact same `r`:

```
ts = 1726000058  msg = {"action":"sign","artifact":"fw-2.4.2.img"}
r  = 0xe0e519fe1b2f148efd7f942db8087a07e65d9b1a98889e873ca987ed19b051b0
s  = 0x7d2782d75609889ef5d7af2ac95e024a96943cfdee98a4d65e7fb8ea38d27802
z  = 0x572dc11a6d539994b22026a38b17508ca666e71bab3315f20b56291ff6d0f5d9

ts = 1726000295  msg = {"action":"sign","artifact":"fw-2.5.0.img"}
r  = 0xe0e519fe1b2f148efd7f942db8087a07e65d9b1a98889e873ca987ed19b051b0
s  = 0xf70da42c61bda4c039f230cfad1074b1605bdca20b21f99c08555c94cd78fea4
z  = 0xeabe84fea1da8c7058d7a487dc5fe528fc430a5339de29162e3d9d8afb000a87
```

This is the direct path to `fw-prod`'s private key.

### 5.2 A second reused `r` across services (red herring)

There is another repeated `r` between `telemetry` and `ota-cdn`:

```
reused r = 0x6ad667fb3c200ba103e37d...
  telemetry ts = 1726000114
  ota-cdn   ts = 1726000119
```

This confirms the RNG was broken globally, not just for one process. However, these two signatures belong to **different public keys**, so the situation is:

```
s1 * k = z1 + r * d1
s2 * k = z2 + r * d2
```

That is two equations with three unknowns (`k`, `d1`, `d2`), so it is underdetermined and does **not** yield either private key by itself. It was noted but not pursued, because the `fw-prod` pair already provides a complete solution.

---

## 6. Step 3 — First Attempt (Failure)

### 6.1 The mistaken formula

Knowing that reused nonces leak keys, the first attempt used the textbook subtraction:

```
s1*k = z1 + r*d
s2*k = z2 + r*d
```

Subtracting:

```
k*(s1 - s2) = z1 - z2
k = (z1 - z2) / (s1 - s2)
```

The bug was the next line. The script did:

```python
d = (z1 - z2) * pow(s1 - s2, -1, n) % n
```

and then tried to verify `d` by recomputing the public key.

That expression returns **`k`**, not `d`. It is a classic sign of moving too fast: the subtraction was done correctly, but the result was assigned to the wrong variable. In the first script the verification was:

```python
w = pow(s, -1, n)
R = (z*w + r*d*w) % n
assert R == r
```

Every `fw-prod` signature failed this check:

```
verify 1726000000 False
verify 1726000058 False
verify 1726000188 False
verify 1726000295 False
```

The same wrong formula was then applied to the sign-flip brute force, and that also failed:

```
pair 1726000058 1726000295 r eq True
# no candidate d matched the published pubkey
```

### 6.2 Why the first failure was useful

The failed verification was actually a strong signal:

1. The signatures themselves were valid, because all 11 verified against their own public keys with `z = SHA256(msg)`.
2. The message encoding was therefore correct.
3. The only broken part was the private-key formula.

This prevented the wrong path of chasing encoding issues.

---

## 7. Step 4 — Debugging and Changing Approach

### 7.1 Control test: confirm the message hashing

Before changing the algebra, all signatures were verified against their own `pubkey` using several candidate message encodings:

| Encoding | Signatures verified |
|---|---|
| `row["msg"]` | **11 / 11** |
| `row["msg"] + "\n"` | 0 / 11 |
| `json.dumps(row["msg"])` | 0 / 11 |
| full JSON without `sig` | 0 / 11 |
| `str(ts) + msg` | 0 / 11 |

This established with certainty:

```
z = SHA256(row["msg"].encode()) mod n
```

No encoding ambiguity remained.

### 7.2 Re-deriving the correct relation

Starting from:

```
s1*k1 = z1 + r*d
s2*k2 = z2 + r*d
```

With the same nonce, `k1 = k2 = k`, so:

```
k = (z1 - z2) / (s1 - s2) mod n
```

Then substitute `k` back into either signature to solve for `d`:

```
s1*k = z1 + r*d
=> r*d = s1*k - z1
=> d = (s1*k - z1) / r mod n
```

That is the step the first attempt missed: `k` and `d` are different values.

### 7.3 Considering low-S / negated nonces

For robustness, the script also tried all four sign combinations of `s1` and `s2` (normal and `n - s`). This handles the case where a signer normalizes `s` to the low half of the curve order, which corresponds to using `-k`.

The general situation for two signatures with the same `r` is:

- **Case A: `k2 = k1`**
  ```
  k1 = (z1 - z2) / (s1 - s2)
  d  = (s1*k1 - z1) / r
  ```

- **Case B: `k2 = -k1`**
  ```
  -s2*k1 = z2 + r*d
  s1*k1  = z1 + r*d
  => k1 = (z1 - z2) / (s1 + s2)
  => d  = (s1*k1 - z1) / r
  ```

Brute-forcing the signs covers both cases.

For this challenge, the correct result came from the unmodified signatures (`k2 = k1`). The all-negated variant also produced the same `d`, because negating both `s` values is a global sign flip and leaves the recovered key unchanged.

---

## 8. Step 5 — Correct Key Recovery

Using the `fw-prod` pair directly:

```python
a = signature for fw-2.4.2.img
b = signature for fw-2.5.0.img

k = (a["z"] - b["z"]) * pow(a["s"] - b["s"], -1, n) % n
d = (a["s"] * k - a["z"]) * pow(a["r"], -1, n) % n
```

Intermediate values:

```
k = 0xef4e9449242370dc994dd5a86d77dada239f67351959d5cb31fc43ab1f9003bd

d = 0x22ddfa2a54f5c6bbbe73b6311a007b622412f98c19821421cc21f23a9d77d842

d (decimal) =
15770836630998876809320045031180303963064800215727080558172892102528819779650
```

### Verification

The recovered `d` was checked by recomputing the public key:

```python
Q = d * G
assert Q == published_fw_prod_pubkey
```

This succeeded. That is the definitive proof the key is correct — unlike the first attempt, where the pubkey check failed immediately.

---

## 9. Step 6 — Unsealing the Release

With `d` known, follow the note in `release.sealed` exactly.

### 9.1 Derive the seal key

```python
key = hashlib.sha256(
    b"fw-prod-seal-" + str(d).encode()
).digest()
```

Important detail: `str(d)` is the **decimal** representation, with no spaces, prefixes, or newline.

Result:

```
key = b251c218daa8f94c03425ae6e1aa71f9048121be9a8cf00a22103ec8974315dd
```

### 9.2 Build the keystream

The ciphertext is 42 bytes, so two SHA-256 blocks are needed:

```python
ct = bytes.fromhex(
    "7b0df4b443574678cf2c851bd67e284d1f584a88ee0f0c8dfb26c0ea70ae2520"
    "63aa717786"
)

ks = b"".join(
    hashlib.sha256(key + i.to_bytes(4, "big")).digest()
    for i in range((len(ct) + 31) // 32)
)
```

Keystream:

```
336c97df00030003a24df178be215c252c0721bb975062bd8f79aa9f03da7a54
0b992e05fbec46cb2285371f60a0cb26b480ba392a1ec74c566969ef8f3bd91b
```

### 9.3 XOR and recover the flag

```python
pt = bytes(c ^ k for c, k in zip(ct, ks))
print(pt)
```

Output:

```
b'HackCTF{match_th3_k3y_n0t_just_th3_r}'
```

---

## 10. Final Flag

```
HackCTF{match_th3_k3y_n0t_just_th3_r}
```

---

## 11. What Went Wrong and How the Approach Changed

| Stage | Attempt | Result | Why it failed | Fix |
|---|---|---|---|---|
| 1 | Assume reused nonce from repeated `r` | Correct hypothesis | — | Keep going |
| 2 | Use `d = (z1 - z2) / (s1 - s2)` | Pubkey verification false for all `fw-prod` signatures | The expression is `k`, not `d` | Re-derive algebra |
| 3 | Try sign flips of `s1`, `s2` with the same wrong formula | Still no matching pubkey | Same `d`/`k` mix-up; also needed the correct sign-case equation | Derive both `k2 = k1` and `k2 = -k1` cases |
| 4 | Control-test message encodings | `row["msg"]` verified 11/11 | Proved the signatures and hashing were fine | Stop suspecting encoding |
| 5 | Correctly compute `k`, then `d` | `d*G` matched the published pubkey | — | Success |
| 6 | Unseal with `SHA256(b"fw-prod-seal-" + str(d))` | Flag recovered | — | Success |

### Key lessons

1. **A repeated `r` means a repeated nonce `k`, not a repeated private key formula.** The first equation gives `k`; `d` requires a second substitution.
2. **Always verify a recovered key against the published public key.** The failed check caught the algebra bug early.
3. **Use a control test before chasing encoding issues.** Verifying all 11 signatures against their own public keys ruled out message-format problems.
4. **A reused `r` across different signers is interesting but not automatically useful.** With different private keys, the shared nonce gives two equations with three unknowns.
5. **Low-S normalization matters.** Checking `s` and `n - s` variants makes nonce-reuse tooling robust against signers that normalize signatures.

---

## Appendix A — Full Solver

```python
#!/usr/bin/env python3
"""Recover fw-prod ECDSA key from repeated nonce, then unseal release.sealed."""
import json, base64, hashlib

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: return None
    if P == Q:
        l = (3 * x1 * x1) * pow(2 * y1, -1, p) % p
    else:
        l = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (l * l - x1 - x2) % p
    return x3, (l * (x1 - x3) - y1) % p


def mul(k, P=(Gx, Gy)):
    R = None
    while k:
        if k & 1:
            R = add(R, P)
        P = add(P, P)
        k >>= 1
    return R


rows = [json.loads(line) for line in open("audit.log.jsonl")]
fw = [row for row in rows if row["signer"] == "fw-prod"]

for row in fw:
    raw = base64.b64decode(row["sig"])
    row["r"] = int.from_bytes(raw[:32], "big")
    row["s"] = int.from_bytes(raw[32:], "big")
    row["z"] = int.from_bytes(
        hashlib.sha256(row["msg"].encode()).digest(), "big"
    ) % n

pk = bytes.fromhex(fw[0]["pubkey"])
Q = (int.from_bytes(pk[1:33], "big"), int.from_bytes(pk[33:], "big"))

# fw-2.4.2 and fw-2.5.0 share the same nonce k => same r
a, b = [row for row in fw if row["r"] == fw[1]["r"]][:2]

k = (a["z"] - b["z"]) * pow(a["s"] - b["s"], -1, n) % n
d = (a["s"] * k - a["z"]) * pow(a["r"], -1, n) % n

assert mul(d) == Q, "recovered key does not match published pubkey"
print("private key:", d)

key = hashlib.sha256(b"fw-prod-seal-" + str(d).encode()).digest()
ct = bytes.fromhex(
    open("release.sealed").read().split("ciphertext_hex:")[1].strip()
)
ks = b"".join(
    hashlib.sha256(key + i.to_bytes(4, "big")).digest()
    for i in range((len(ct) + 31) // 32)
)
print("flag:", bytes(c ^ k for c, k in zip(ct, ks)).decode())
```

Run:

```bash
cd Audit_log
python3 solve.py
```

Output:

```
private key: 15770836630998876809320045031180303963064800215727080558172892102528819779650
flag: HackCTF{match_th3_k3y_n0t_just_th3_r}
```

---

## Appendix B — Compact Reproduction

Everything needed, without the ECDSA point arithmetic:

```python
import json, base64, hashlib

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
rows = [json.loads(l) for l in open("audit.log.jsonl")]
fw = [r for r in rows if r["signer"] == "fw-prod"]

for r in fw:
    raw = base64.b64decode(r["sig"])
    r["r"] = int.from_bytes(raw[:32], "big")
    r["s"] = int.from_bytes(raw[32:], "big")
    r["z"] = int.from_bytes(hashlib.sha256(r["msg"].encode()).digest(), "big") % n

a, b = [r for r in fw if r["r"] == fw[1]["r"]][:2]
k = (a["z"] - b["z"]) * pow(a["s"] - b["s"], -1, n) % n
d = (a["s"] * k - a["z"]) * pow(a["r"], -1, n) % n

key = hashlib.sha256(b"fw-prod-seal-" + str(d).encode()).digest()
ct = bytes.fromhex(open("release.sealed").read().split("ciphertext_hex:")[1].strip())
ks = b"".join(hashlib.sha256(key + i.to_bytes(4, "big")).digest()
              for i in range((len(ct) + 31) // 32))
print(bytes(c ^ x for c, x in zip(ct, ks)).decode())
```

Output:

```
HackCTF{match_th3_k3y_n0t_just_th3_r}
```
