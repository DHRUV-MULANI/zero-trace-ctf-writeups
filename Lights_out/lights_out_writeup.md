# HackCTF — Lights Out (200 pts) — Full Writeup

| Field | Value |
|---|---|
| Category | Forensics / Steganography |
| Points | 200 |
| File | `static.gif` (460,652 bytes) |
| Flag format | `HackCTF{...}` |
| **Flag** | **`HackCTF{bl4ck_1s_n0t_3mpty_9c21}`** |

**Challenge text:** *Our surveillance feed went dark at 3 AM. The tape shows nothing but black, flickering for a few seconds, then loops forever. The technician swears the camera was still recording something. We also found that the file is heavier than it should be.*

**Hint:** *Black isn't always empty.*

---

## 1. Solution Overview

```
static.gif
 ├── 40 frames of near-black binary noise (palette idx 0 = #000000, idx 1 = #010101)
 │     └── frames 9 and 31 are secretly related
 │           └── XOR(frame9, frame31) = QR code (v2, 25x25, 8px modules, finder patterns erased)
 │                 └── repair finders -> decode -> "ph4nt0m-sign4l-7731"
 └── 64 bytes appended after the GIF trailer (0x3B)
       └── "Salted__" OpenSSL blob
             └── AES-256-CBC + PBKDF2, password = QR text
                   └── HackCTF{bl4ck_1s_n0t_3mpty_9c21}
```

---

## 2. Step 1 — Initial Triage

Goal: learn what the file is, how it is structured, and whether anything is obviously hidden.

```bash
ls -l static.gif
file static.gif
strings -n 6 static.gif | head
```

Findings:

- `GIF image data, version 89a, 264 x 264`
- A `NETSCAPE2.0` application extension (infinite looping, explains "loops forever")
- A **GIF comment**: `nothing to see here` (suspicious; later shown to be a decoy)
- Roughly 460 KB for 40 frames, which is large for an all-black animation

### Frame inspection with Pillow

```python
from PIL import Image, ImageSequence
import numpy as np

im = Image.open('static.gif')
print(im.size, im.mode, im.n_frames, im.info)

for i, f in enumerate(ImageSequence.Iterator(im)):
    a = np.array(f.convert('RGB'))
    print(i, f.info['duration'], a.min(), a.max(), len(np.unique(a.reshape(-1,3), axis=0)))
```

Result:

- 40 frames, each with only **2 unique colors**, pixel values `0` and `1`
- Frame durations vary between 40, 50 and 60 ms

So the image is not empty: each frame is a binary pattern with colors `(0,0,0)` and `(1,1,1)`. They are visually indistinguishable from pure black. This is the meaning of **"Black isn't always empty."**

Amplifying a frame (`pixel * 255`) shows what looks like pure random noise.

---

## 3. Step 2 — Parse the GIF Structure Manually

Pillow hides low-level details, so I parsed the blocks by hand to look for trailing data, extra extensions and odd palettes.

```python
import struct
d = open('static.gif','rb').read()
p = 6
w,h,flags,bg,asp = struct.unpack('<HHBBB', d[p:p+7]); p += 7
if flags & 0x80:
    n = 3 * (2 ** ((flags & 7) + 1)); p += n         # global color table
while p < len(d):
    b = d[p]
    if b == 0x3B:
        print('trailer at', p, 'remaining bytes:', len(d) - p - 1); break
    ...   # walk extension (0x21) and image (0x2C) blocks
```

Findings:

| Item | Result |
|---|---|
| Global color table | 256 entries, only entry 1 is non-zero (`01 01 01`), everything else black |
| Comment extension | `nothing to see here` |
| Frames | 40, each 264x264, LZW min code size 8, each with a local color table identical to the global one |
| **Data after trailer** | **64 bytes after `0x3B`** |

This is the *"file is heavier than it should be"* clue. A GIF decoder stops at the `0x3B` trailer, so anything after it is invisible to viewers.

### Dumping the trailing bytes

```python
tail = d[460588:]
print(tail[:8])   # b'Salted__'
```

```
53616c7465645f5f 29bea422e923c037 ...
S a l t e d _ _   <8-byte salt>   <48 bytes ciphertext>
```

`Salted__` is the magic header of `openssl enc` output. The layout is:

- 8 bytes: magic `Salted__`
- 8 bytes: salt
- 48 bytes: ciphertext (3 AES blocks, so the plaintext is 33 to 47 bytes, which fits a flag)

I saved it:

```python
open('blob.bin','wb').write(d[460588:])
```

**Conclusion so far:** the flag is encrypted and a password is needed. The password must be hidden somewhere else in the GIF.

---

## 4. Step 3 — Password Guessing (Dead End)

I first tried the obvious candidates against several OpenSSL configurations:

- Passwords: `nothing to see here`, `lights out`, `black`, `static`, `HackCTF`, `3AM`, `surveillance`, etc.
- Ciphers: `aes-128/192/256-cbc`, `aes-256-ecb`, `aes-256-ctr`
- KDFs: legacy MD5, SHA-256, `-pbkdf2` with several iteration counts

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in blob.bin -pass pass:"nothing to see here"
```

No candidate worked. The comment was therefore a decoy, and the password had to be recovered from the image data.

---

## 5. Step 4 — Frame Durations (Dead End)

The durations take exactly three values (40, 50, 60 ms) over 40 frames, which looks designed. I converted them to ternary:

```
0122000112000222012112201202200200220100
```

I tried:

- Groups of 5 trits turned into 8 bytes
- Groups of 3 trits mapped to letters (`a-z`)
- All 6 permutations of the 40/50/60 to 0/1/2 mapping, forward and reversed, with offsets 0-4
- Morse (40 = dot, 60 = dash, 50 = separator)
- Binary (40 = 0, 60 = 1, ignoring 50)

None produced readable output (e.g. `fsesitwypygid`, `E7/?T/G?I`). The durations are just random jitter that makes the loop look like real flicker.

---

## 6. Step 5 — Is the Noise Really Random? (Dead End, With a Useful Lesson)

### 6.1 Visual and statistical checks

- Temporal mean per pixel, blurred and contrast stretched: shows no image. The standard deviation matches the binomial expectation for 40 samples.
- Per-frame fraction of ones is around 0.50 for every frame.
- Horizontal, vertical and temporal correlations are all about 0 (within the expected 0.0006 sigma).
- Stream autocorrelation and Berlekamp-Massey linear complexity (1000 for 2000 bits) both look random.

### 6.2 Bit extraction in many orders (Dead End)

I packed the pixel bits into bytes using many orderings and searched for printable ASCII or keywords (`Hack`, `flag`, `pass`, `key`, `CTF`, `{`):

- frame-major row-major, frame-major column-major
- pixel-major (time as the fastest axis), both orderings
- reversed frame order
- inverted bits, MSB-first and LSB-first packing, bit offsets 0-7

Only chance matches appeared (hundreds of orderings over about 280 KB of random data guarantee a few). No signal.

### 6.3 Raw palette indices (Dead End)

Because palette entries 2-255 are all black, I suspected pixels with index above 1 might hide data after an RGB conversion. Pillow returned inconsistent frame modes, so I wrote my own GIF LZW decoder to read raw indices:

```python
def lzw_decode(data, mcs, npix):
    clear = 1 << mcs; eoi = clear + 1
    codesize = mcs + 1; out = bytearray(); prev = None
    bitbuf = bits = pos = 0
    table = [bytes([i]) for i in range(clear)] + [b'', b'']
    while len(out) < npix:
        while bits < codesize and pos < len(data):
            bitbuf |= data[pos] << bits; bits += 8; pos += 1
        if bits < codesize: break
        code = bitbuf & ((1 << codesize) - 1)
        bitbuf >>= codesize; bits -= codesize
        if code == clear:
            table = [bytes([i]) for i in range(clear)] + [b'', b'']
            codesize = mcs + 1; prev = None; continue
        if code == eoi: break
        if prev is None:
            entry = table[code]; out += entry; prev = entry; continue
        entry = table[code] if code < len(table) else prev + prev[:1]
        out += entry
        table.append(prev + entry[:1])
        if len(table) == (1 << codesize) and codesize < 12: codesize += 1
        prev = entry
    return bytes(out[:npix])
```

Result: only indices `0` and `1` exist (about 1,394,315 zeros and 1,393,525 ones). There is no hidden palette data, so the secret is in the arrangement of the bits.

---

## 7. Step 6 — The Breakthrough: Duplicate Rows

Truly random 264-bit rows essentially never repeat. I checked for repeated rows across all 40 x 264 = 10,560 rows:

```python
import collections
d = collections.defaultdict(list)
for t in range(40):
    for r in range(264):
        d[I[t, r].tobytes()].append((t, r))
groups = [v for v in d.values() if len(v) > 1]
print(len(groups))   # 64
```

**64 duplicate rows**, all between **frame 9 and frame 31**.

A pairwise comparison of every frame pair confirmed it:

```
(0.782, frame 9, frame 31)     <- outlier
(0.507, frame 6, frame 12)     <- baseline noise is ~0.50
...
```

Frames 9 and 31 agree on about **78%** of their pixels. All other pairs agree on about 50%. That is only possible if one is derived from the other.

---

## 8. Step 7 — XOR of the Two Frames Reveals a QR Code

```python
diff = (I[9] != I[31]).astype(np.uint8)    # XOR of the two frames
```

Row sums of the XOR mask came out in multiples of 8 (`40, 40, ... 32, 32 ... 24 ...`), which means the pattern is made of **8x8 pixel blocks**. I checked that every 8x8 block is uniform:

```python
blk = diff.reshape(33, 8, 33, 8)
print((blk.min(axis=(1,3)) == blk.max(axis=(1,3))).all())   # True
```

So the image is a **33 x 33 module grid**. Since 33 = 25 + 2 x 4, this is a **version 2 QR code (25x25 modules) with a 4-module quiet zone**.

Printing the module grid:

```python
g = diff[4::8, 4::8]
for r in g: print(''.join('█' if x else '·' for x in r))
```

The data modules, timing pattern (alternating modules along row 6 / column 6 of the QR) and alignment pattern are there. But the **three 7x7 finder patterns in the corners are missing**. This makes the QR code undetectable to scanners, which is why it did not look like a QR code at first glance.

### How the QR was hidden

Frame 31 is frame 9 with every pixel in each *dark* QR module flipped. XORing the two frames cancels the random noise and leaves only the QR pattern. The finder patterns were deliberately left out of the XOR so that scanners cannot find it.

---

## 9. Step 8 — Repair the QR Code

Crop the 25x25 region (modules 4..28) and redraw the three finder patterns:

```python
q = g[4:29, 4:29].copy()

def finder(r, c):
    for i in range(7):
        for j in range(7):
            ring = max(abs(i - 3), abs(j - 3))
            q[r + i, c + j] = 1 if ring in (3, 1, 0) else 0

finder(0, 0)      # top-left
finder(0, 18)     # top-right
finder(18, 0)     # bottom-left
```

A finder pattern is: 7x7 dark outer ring, 5x5 light ring, 3x3 dark center. The separators (the light modules around each finder) were already empty.

Render with a quiet zone, inverted so that dark modules become black on white:

```python
from PIL import Image
img = np.pad(1 - q, 4, constant_values=1)
Image.fromarray((img * 255).astype('uint8')).resize((33*16, 33*16), Image.NEAREST).save('qr_fixed.png')
```

---

## 10. Step 9 — Decode the QR Code

```python
import cv2
img = cv2.imread('qr_fixed.png', 0)
print(cv2.QRCodeDetector().detectAndDecode(img)[0])
```

Output:

```
ph4nt0m-sign4l-7731
```

The Aruco-based detector and several border sizes all agree on the same string, so the repair is correct.

---

## 11. Step 10 — Decrypt the Appended Blob

```bash
tail -c 64 static.gif | openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:ph4nt0m-sign4l-7731
```

Output:

```
HackCTF{bl4ck_1s_n0t_3mpty_9c21}
```

Both `-pbkdf2` and `-pbkdf2 -md sha256` work (they are the same since SHA-256 is the OpenSSL 3.x default). The legacy MD5 KDF and other ciphers fail, which confirms the parameters.

---

## 12. Final Answer

```
HackCTF{bl4ck_1s_n0t_3mpty_9c21}
```

---

## 13. Map of Clues to Techniques

| Clue | Meaning | Technique |
|---|---|---|
| "Nothing but black" | Palette is `#000000` and `#010101` | Inspect palette and raw pixel values |
| "Flickering" | Per-frame binary noise | Treat frames as bit arrays |
| "File is heavier than it should be" | Data after GIF trailer `0x3B` | Parse blocks manually, dump trailing bytes |
| "Black isn't always empty" | Near-black pixels carry information | Amplify, XOR, look for structure |
| "Loops forever" | `NETSCAPE2.0` loop extension | Only explains looping, no hidden data |
| Comment `nothing to see here` | Decoy | Password guess fails |

## 14. Dead Ends (and Why They Matter)

| Attempt | Outcome |
|---|---|
| GIF comment as password | Wrong |
| Frame durations as ternary, binary or Morse | Random jitter |
| Raw palette indices above 1 | Do not exist |
| Bit extraction in many orders | Only chance matches |
| Blurred temporal mean | Pure noise |
| Randomness statistics | Noise is random *except* for the 9/31 pair |

## 15. Tools Used

- `file`, `strings`, `openssl`
- Python: `Pillow`, `NumPy`, `SciPy`, `OpenCV`
- A small custom GIF parser and LZW decoder

## 16. Lessons and Takeaways

1. **Do not convert GIFs to RGB blindly.** Look at raw palette indices, and parse the container for trailing data.
2. **Check for structure in "noise."** Duplicate rows, pairwise frame similarity and XOR between frames are quick tests that expose engineered relationships.
3. **Modules on an 8x8 grid** in a difference image usually means a QR code, and the module count tells you the version (33 = 25 + 2 x 4 means version 2).
4. **A QR code that does not scan may just lack finder patterns.** Redraw them and try again.
5. **`Salted__` means OpenSSL `enc`.** Try `-pbkdf2` first on modern challenges.
6. Hints are literal. "Black isn't always empty" meant near-black pixels, and "heavier than it should be" meant appended data.

## 17. Reproduction Script

```python
#!/usr/bin/env python3
"""Full solve for HackCTF 'Lights Out' (static.gif)."""
import struct, subprocess, numpy as np, cv2
from PIL import Image

PATH = 'static.gif'
d = open(PATH, 'rb').read()

# --- 1. trailing OpenSSL blob ------------------------------------------------
trailer = d.rfind(b'\x3b', 0, len(d) - 64)
blob = d[-64:]
assert blob.startswith(b'Salted__')

# --- 2. raw frame indices ----------------------------------------------------
def lzw_decode(data, mcs, npix):
    clear = 1 << mcs; eoi = clear + 1
    codesize = mcs + 1; out = bytearray(); prev = None
    bitbuf = bits = pos = 0
    table = [bytes([i]) for i in range(clear)] + [b'', b'']
    while len(out) < npix:
        while bits < codesize and pos < len(data):
            bitbuf |= data[pos] << bits; bits += 8; pos += 1
        if bits < codesize: break
        code = bitbuf & ((1 << codesize) - 1)
        bitbuf >>= codesize; bits -= codesize
        if code == clear:
            table = [bytes([i]) for i in range(clear)] + [b'', b'']
            codesize = mcs + 1; prev = None; continue
        if code == eoi: break
        if prev is None:
            entry = table[code]; out += entry; prev = entry; continue
        entry = table[code] if code < len(table) else prev + prev[:1]
        out += entry
        table.append(prev + entry[:1])
        if len(table) == (1 << codesize) and codesize < 12: codesize += 1
        prev = entry
    return bytes(out[:npix])

def read_frames(d):
    p = 6
    w, h, fl, bg, asp = struct.unpack('<HHBBB', d[p:p+7]); p += 7
    if fl & 0x80: p += 3 * (2 ** ((fl & 7) + 1))
    frames = []
    while d[p] != 0x3B:
        if d[p] == 0x21:
            q = p + 2
            while d[q] != 0: q += 1 + d[q]
            p = q + 1
        elif d[p] == 0x2C:
            x, y, iw, ih, lf = struct.unpack('<HHHHB', d[p+1:p+10]); p += 10
            if lf & 0x80: p += 3 * (2 ** ((lf & 7) + 1))
            mcs = d[p]; p += 1
            buf = bytearray()
            while d[p] != 0:
                buf += d[p+1:p+1+d[p]]; p += 1 + d[p]
            p += 1
            frames.append(np.frombuffer(lzw_decode(bytes(buf), mcs, iw*ih),
                                        dtype=np.uint8).reshape(ih, iw))
    return np.array(frames)

I = read_frames(d)

# --- 3. find the related frame pair -----------------------------------------
best = max(((I[a] == I[b]).mean(), a, b)
           for a in range(len(I)) for b in range(a+1, len(I)))
_, a, b = best
print('related frames:', a, b)

# --- 4. XOR -> 33x33 module grid -> 25x25 QR ---------------------------------
diff = (I[a] != I[b]).astype(np.uint8)
q = diff[4::8, 4::8][4:29, 4:29].copy()

def finder(r, c):
    for i in range(7):
        for j in range(7):
            q[r+i, c+j] = 1 if max(abs(i-3), abs(j-3)) in (3, 1, 0) else 0
finder(0, 0); finder(0, 18); finder(18, 0)

img = np.pad(1 - q, 4, constant_values=1)
img = (img * 255).astype('uint8')
img = np.kron(img, np.ones((16, 16), dtype='uint8'))
cv2.imwrite('qr_fixed.png', img)

password = cv2.QRCodeDetector().detectAndDecode(img)[0]
print('password:', password)

# --- 5. decrypt --------------------------------------------------------------
open('blob.bin', 'wb').write(blob)
print(subprocess.run(
    ['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2',
     '-in', 'blob.bin', '-pass', f'pass:{password}'],
    capture_output=True, text=True).stdout)
```

**Flag:** `HackCTF{bl4ck_1s_n0t_3mpty_9c21}`
