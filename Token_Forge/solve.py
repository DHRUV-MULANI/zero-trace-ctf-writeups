#!/usr/bin/env python3
"""Token Forge — reference solver.

Stage 1 (state recovery) is brute force over the 32 unknown low bits of the
first logged state.  The C helper `solve.c` does the 2^32 search in ~2 seconds;
this script will compile and run it automatically.  A pure-Python search is
available with --python (about 9 minutes on this host).

Stage 2 unseals admin_reset.sealed with the NEXT state and prints the token.
"""

import hashlib
import os
import re
import subprocess
import sys

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
    """Compile and run solve.c; return the recovered next state or None."""
    src = os.path.join(HERE, "solve.c")
    bin_ = os.path.join(HERE, ".solve_bin")
    subprocess.run(["gcc", "-O2", "-o", bin_, src], check=True)
    out = subprocess.run([bin_], capture_output=True, text=True, check=True).stdout
    m = re.search(r"next_dec=(\d+)", out)
    return int(m.group(1)) if m else None


def recover_python(targets):
    """Pure-Python fallback: same search, much slower."""
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
