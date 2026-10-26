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
