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
