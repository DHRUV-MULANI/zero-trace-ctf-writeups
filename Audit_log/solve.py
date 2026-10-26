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
    l = (3 * x1 * x1) * pow(2 * y1, -1, p) % p if P == Q else (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (l * l - x1 - x2) % p
    return x3, (l * (x1 - x3) - y1) % p


def mul(k, P=(Gx, Gy)):
    R = None
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R


rows = [json.loads(l) for l in open("audit.log.jsonl")]
fw = [x for x in rows if x["signer"] == "fw-prod"]
for x in fw:
    raw = base64.b64decode(x["sig"])
    x["r"] = int.from_bytes(raw[:32], "big")
    x["s"] = int.from_bytes(raw[32:], "big")
    x["z"] = int.from_bytes(hashlib.sha256(x["msg"].encode()).digest(), "big") % n

pk = bytes.fromhex(fw[0]["pubkey"])
Q = (int.from_bytes(pk[1:33], "big"), int.from_bytes(pk[33:], "big"))

# fw-2.4.2 and fw-2.5.0 share the same nonce k => same r
a, b = [x for x in fw if x["r"] == fw[1]["r"]][:2]
k = (a["z"] - b["z"]) * pow(a["s"] - b["s"], -1, n) % n
d = (a["s"] * k - a["z"]) * pow(a["r"], -1, n) % n
assert mul(d) == Q, "recovered key does not match published pubkey"
print("private key:", d)

key = hashlib.sha256(b"fw-prod-seal-" + str(d).encode()).digest()
ct = bytes.fromhex(open("release.sealed").read().split("ciphertext_hex:")[1].strip())
ks = b"".join(hashlib.sha256(key + i.to_bytes(4, "big")).digest()
              for i in range((len(ct) + 31) // 32))
print("flag:", bytes(c ^ k for c, k in zip(ct, ks)).decode())
