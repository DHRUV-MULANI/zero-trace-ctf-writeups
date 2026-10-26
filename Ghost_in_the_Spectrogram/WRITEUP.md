# Ghost in the Spectrogram — Full Writeup

| Field | Value |
|---|---|
| Challenge | Ghost in the Spectrogram |
| Category | Forensics / Stego |
| Points | 100 |
| Flag | `HackCTF{sp3ctr0gr4m_gh0sts_n3v3r_d13}` |
| Evidence | `evidence.img.gz` |

---

## 0. TL;DR (the whole chain in 8 lines)

1. `evidence.img.gz` decompresses to an **ext4** image (volume `EVIDENCE`).
2. `debugfs lsdel` shows **one** deleted inode (15) — a deleted stereo WAV (`voice.wav`).
3. The WAV's **right channel** is pure LSB stego; the left channel is decoy audio.
4. Right-channel `sample & 1` yields: `GHST` + `uint32 BE = 0x40` + a 64-byte OpenSSL blob (`Salted__`).
5. The **left-channel spectrogram** (11–21 s, 4.4–6.7 kHz) contains drawn text that is **rotated 180°**.
6. Segmenting the glyphs and OCR'ing the 180°-rotated image reads: **`ECHO-7-LANTERN`**.
7. `0x40 = 64` is the **exact length of the OpenSSL blob** — the other ~57 KB after it is decoy.
8. `openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 -pass pass:ECHO-7-LANTERN` → flag.

---

## 1. Environment & tooling

Everything was done on Linux with a mix of shell and Python.

```text
Available: file, gzip, debugfs (e2fsprogs), binwalk, 7z,
           python3 + numpy / matplotlib / PIL / wave,
           ffmpeg, tesseract, faster-whisper, vosk, openssl
NOT available: scipy, opencv (cv2), sox
```

That constraint mattered later: all signal processing was hand-rolled with `numpy + numpy.fft`, and all images were rendered with `matplotlib` / `PIL`.

Working directory:

```text
/home/boss/Works/ctf/Zero_trace/Ghost_in_the_Spectrogram
```

---

## 2. Phase 1 — Initial triage

### 2.1 The artifact

```bash
ls -l
# evidence.img.gz
```

It was a gzip, so decompress it (keeping the original):

```bash
gunzip -k evidence.img.gz
# -> evidence.img (8,388,608 bytes = exactly 8 MiB)
```

### 2.2 Identify the image

```bash
file evidence.img
```

```text
evidence.img: Linux rev 1.0 ext4 filesystem data,
UUID=4ce854e7-3ce8-4b85-8544-d2f4cb4ac0cf, volume name "EVIDENCE"
(extents) (64bit) (large files) (huge files)
```

So it is not a disk image with partitions — it is a **bare ext4 filesystem** that can be mounted or read directly with `debugfs`.

Key filesystem parameters:

```text
Volume name: EVIDENCE
Block size:  1024
Block count: 8192   (8 MiB)
Inode count: 2048
```

### 2.3 Why not just mount?

Mounting requires root and risks the journal replaying / metadata being touched. `debugfs` in read-only mode is safer for forensics, so everything was done through `debugfs`.

---

## 3. Phase 2 — Filesystem forensics

### 3.1 Root directory contents

```bash
debugfs -R "ls -l /" evidence.img
```

This revealed the normal run-of-the-mill files (including a couple of obvious decoys, see §3.6) and, importantly, no obvious "flag" file.

### 3.2 The only deleted inode

```bash
debugfs -R "lsdel" evidence.img
```

```text
 Inode  Owner  Mode    Size      Blocks   Time deleted
    15   1000 100644 1850844   1808/  1808 Tue Oct 20 09:24:59 2026
1 deleted inodes found.
```

There is exactly **one** deleted file. That is the whole point of the challenge: the "ghost" is the deleted recording.

### 3.3 Inode metadata

```bash
debugfs -R "stat <15>" evidence.img
```

```text
Inode: 15   Type: regular    Mode:  0644
Size: 1850844
Blockcount: 3616
EXTENTS:
(0-1807):1652-3459
```

The extents were still intact — the blocks had not been reused — so a raw `dump` would recover the full file.

### 3.4 Recover the deleted file

```bash
debugfs -R "dump <15> deleted_file" evidence.img
```

The original name was recovered separately from the directory entry / string search as `voice.wav`.

### 3.5 Identify the recovered file

```bash
file deleted_file
```

```text
RIFF (little-endian) data, WAVE audio, Microsoft PCM,
16 bit, stereo 22050 Hz
```

Python confirms the geometry:

```python
import wave
w = wave.open('deleted_file','rb')
print(w.getnframes(), w.getframerate(), w.getnchannels(), w.getsampwidth())
# 462700 22050 2 2
print(w.getnframes()/w.getframerate())   # 20.984 s
```

So: **462,700 frames, stereo, 22,050 Hz, 16-bit PCM, ~20.98 s.**

> Note: `462700` frames is `462700 bits = 57,837.5 bytes` if you extract 1 LSB per frame — this odd number becomes important in §5 and §6.

### 3.6 Decoy files (recorded for completeness)

Two files were plainly decoys:

* `notes.txt` → `Meeting moved. Nothing to see here.`
* `.old_backup` → base64:

```bash
echo 'Q1RGe24xYzNfdHJ5X3RoMXNfMXNfNF9kM2MweX0K' | base64 -d
# CTF{n1c3_try_th1s_1s_4_d3c0y}
```

`CTF{...}` (not `HackCTF{...}`) — deliberately the wrong flag format. Classic lure. Ignore it.

---

## 4. Phase 3 — First look at the audio

### 4.1 Split the channels

The WAV is stereo, so the two channels were exported separately for inspection:

```bash
ffmpeg -i deleted_file -map_channel 0.0.0 left.wav  -ar 16000 left16k.wav
ffmpeg -i deleted_file -map_channel 0.0.1 right.wav -ar 16000 right16k.wav
```

(Equivalently, `numpy.frombuffer(...).reshape(-1,2)` and take `[:,0]` / `[:,1]`.)

### 4.2 Channel asymmetry — the first real clue

Histogramming each channel's sample values:

```text
LEFT  channel: broad distribution, looks like real audio + noise (large waveform values)
RIGHT channel: values confined to only {-2, -1, 0, 1, 2, 3}
```

A channel that only ever takes a handful of tiny values is **not audio** — it is a data carrier. That immediately said: the right channel is LSB steganography.

### 4.3 What the left channel is (and is not)

The left channel's spectrum is a flat-ish noise floor from ~1.5 kHz up to ~9 kHz, with an **elevated band around 4.5–6 kHz starting only after ~11.5 s**.

* Attempted speech recognition on the left channel with `faster-whisper` (tiny / base / small) → **nothing**. It is not speech.
* This was the first dead end: *"maybe the password is spoken."* It is not. The left channel is a **spectrogram drawing**, not audio content.

---

## 5. Phase 4 — Right-channel LSB extraction

### 5.1 The hypothesis

If the right channel is an LSB carrier, the low bit of each 16-bit sample is one bit of a hidden byte stream. Try both bit orders and both channels; the one that produces an ASCII magic is the winner.

### 5.2 Extraction

```python
import wave, numpy as np

w = wave.open('deleted_file','rb')
n, ch = w.getnframes(), w.getnchannels()
raw = np.frombuffer(w.readframes(n), dtype=np.int16).reshape(-1, ch)
right = raw[:, 1]

bits = (right & 1).astype(np.uint8)          # 462700 bits
bits = bits[:len(bits)//8*8]                  # 462696 bits -> 57837 bytes
payload = np.packbits(bits).tobytes()        # MSB-first within each byte

open('extracted.bin','wb').write(payload)
```

### 5.3 Result — a clean container

The first bytes are unmistakable:

```text
0000  47 48 53 54 00 00 00 40 53 61 6c 74 65 64 5f 5f   GHST...@Salted__
0010  82 15 15 05 4a 14 d1 17 cd ee 50 27 49 6a e8 82   ....J.....P'Ij..
```

Decode the structure:

| Offset | Bytes | Meaning |
|---|---|---|
| `0x00` | `47 48 53 54` | magic **`GHST`** |
| `0x04` | `00 00 00 40` | big-endian `uint32` = **64** |
| `0x08` | `53 61 6c 74 65 64 5f 5f` | **`Salted__`** (OpenSSL) |
| `0x10` | `82 15 15 05 4a 14 d1 17` | 8-byte OpenSSL **salt** |
| `0x18` | … | ciphertext |
| end | | total payload = **57837 bytes** |

So the file is a **mini container**: `GHST` magic, a 4-byte length, then an OpenSSL `enc` salted blob.

### 5.4 The wrong assumption that cost time

The first instinct was: *"`GHST` + length is just a wrapper, the OpenSSL blob is the rest of the file."* That assumption is **false**, and it is the single biggest reason decryption appeared impossible later (§6). The `0x40` is **not** metadata — it is the literal byte length of the OpenSSL blob that follows.

We'll come back to this.

---

## 6. Phase 5 — Reading the spectrogram (the hard part)

The passphrase had to come from the left channel. This phase had the most failures, so it is documented in detail.

### 6.1 Failure #1 — treating the left channel as audio

* Ran Whisper on the left channel at multiple model sizes → empty transcripts.
* Ran it on the reversed waveform → empty.
* Conclusion: not speech. **Change of approach:** stop listening, start looking.

### 6.2 Failure #2 — whole-file spectrogram

`matplotlib.specgram` of the entire 21 s file, full 0–11 kHz band, default settings:

* The interesting band was a thin strip that looked like "noise".
* Default FFT/hop made the strip only a few pixels tall → nothing readable.

**Change of approach:** crop to the suspicious band and window in time.

### 6.3 Failure #3 — wrong aspect ratio / resolution

Tried many STFT configurations, printing ASCII and saving PNGs:

* `nfft ∈ {512, 1024, 2048}`, various hops
* band windows like `4200–6900`, `4400–6700`, `4000–7000`
* time windows like `10.5–22.5 s`, `11–21 s`
* grids of 48×360, 60×720, 90×720, …

ASCII renders at low row counts produced *glyph-shaped blobs* but they read like gibberish because the text was being squeezed/stretched. Fragments that OCR/eyeballing produced across attempts included nonsense like:

```text
MASITUA     OHD3     WS A N ORIED     COJIERHED N LIS
```

**Change of approach:** stop trying to force a "nice" aspect; instead **binarize** the image and let the *structure* of the text guide the geometry.

### 6.4 Failure #4 — blind OCR of the raw spectrogram

Ran `tesseract` directly on spectrogram crops (`--psm 7`, `--psm 8`), with a character whitelist, on the original and on 90°/180°/270° rotations. Results were garbage because:

* the spectrogram is continuous-tone, not a crisp glyph image;
* the text is inverted/mirrored;
* there is a bright consistent band at the bottom of every glyph confusing the segmenter.

**Change of approach:** build a proper **binary mask**, then segment into characters *first*, then OCR.

### 6.5 The systematic fix — binary mask + column-gap segmentation

This is the step that broke it open.

**(a) Compute a normalized dB spectrogram** of the left channel, cropped to the message band:

```python
import numpy as np, wave
from PIL import Image

w = wave.open('deleted_file','rb')
n, sr, ch = w.getnframes(), w.getframerate(), w.getnchannels()
raw = np.frombuffer(w.readframes(n), dtype=np.int16).reshape(-1, ch)
left = raw[:,0].astype(np.float64)

start, end = 10.5, 22.5
lo, hi = 4200, 6900          # the message band
nfft, hop = 1024, 128

x = left[int(start*sr):int(end*sr)].copy()
x -= x.mean()

win = np.hanning(nfft)
frames = [np.abs(np.fft.rfft(x[i:i+nfft]*win))
          for i in range(0, len(x)-nfft, hop)]
S = 20*np.log10(np.array(frames).T + 1e-9)

freqs = np.fft.rfftfreq(nfft, 1/sr)
idx = np.where((freqs>=lo) & (freqs<=hi))[0]
S = S[idx, :]

# resample to a fixed grid
W, H = 720, 90
G = np.array(Image.fromarray(S.astype(np.float32), mode='F').resize((W,H), Image.BILINEAR))

# remove per-frequency baseline, rescale
G = G - np.median(G, axis=1, keepdims=True)
lo_p, hi_p = np.percentile(G, 5), np.percentile(G, 99.5)
N = np.clip((G - lo_p)/(hi_p - lo_p + 1e-9), 0, 1)

mask = (G > 8).astype(np.uint8)     # threshold on baseline-subtracted dB
np.save('mask.npy', mask)
```

**(b) Find the text rows.** Summing the mask per frequency row showed a clean rectangular text block occupying **rows 14–73** of the 90-row grid, with rows 0–13 and 74–89 empty. That is a strong "this is a rectangle of glyphs" signal.

**(c) Segment into characters by zero-column runs.** Sum the mask over rows 14–73, then look for columns that are completely empty across the text height. Those are inter-character gaps:

```text
zero-column runs (start,end,len):
(0,90,91)  (127,129,3)  (168,176,9)  (210,216,7)  (254,260,7)
(297,299,3) (339,344,6) (378,392,15) (416,431,16) (465,476,12)
(501,513,13) (551,556,6) (592,600,9) (634,642,9)  (675,719,45)
```

That produces exactly **14 glyph groups**, with a mix of narrow gaps (3–9 cols, letter spacing) and wide gaps (12–16 cols, spaces/wide letters). Fourteen characters is a great fit for a password-like phrase.

### 6.6 Failure #5 — wrong orientation (mirror vs 180°)

Printing each of the 14 glyphs as ASCII revealed the shapes were **not** in normal orientation. Two candidate transforms were tried:

* **Horizontal mirror only** (what you'd get from “the audio was reversed”): this produced a plausible-looking **`E C H O - …`** at the start, which was seductive — but two glyphs refused to resolve into letters (`Γ` and a bare `\`).
* **180° rotation** (mirror + upside-down): this turned the stubborn `Γ`-shaped glyph into a clean **`L`**, and the bare diagonal into a **`7`** (top bar + descending diagonal).

The deciding evidence was the two *narrow* glyphs: they are 23–24 columns wide and consist of a single horizontal bar in the middle — i.e. **hyphens**. Their positions bracket the 7, giving the pattern `… O - 7 - L …`.

So the correct transform is **180° rotation**, and the character sequence is:

```text
E C H O - 7 - L A N T E R N
```

Glyph-by-glyph sanity check (rows top→bottom after 180° rotation):

| # | Glyph | Shape seen | Letter |
|---|---|---|---|
| 0 | orig `g13` | three bars + left stem | **E** |
| 1 | orig `g12` | top/bottom curves + left stem, open right | **C** |
| 2 | orig `g11` | two verticals + middle bar | **H** |
| 3 | orig `g10` | closed ring with hole | **O** |
| 4 | orig `g9`  | single mid bar (narrow) | **-** |
| 5 | orig `g8`  | top bar + descending diagonal | **7** |
| 6 | orig `g7`  | single mid bar (narrow) | **-** |
| 7 | orig `g6`  | vertical + bottom bar | **L** |
| 8 | orig `g5`  | apex + two legs + crossbar | **A** |
| 9 | orig `g4`  | two verticals + diagonal | **N** |
| 10 | orig `g3` | top bar + centre stem | **T** |
| 11 | orig `g2` | three bars + left stem | **E** |
| 12 | orig `g1` | vertical + top + middle + leg | **R** |
| 13 | orig `g0` | two verticals + diagonal | **N** |

### 6.7 OCR confirmation

To remove human bias, the binary mask was exported as a padded, 6× upscaled PNG, rotated **180°**, and sent to Tesseract:

```python
img = Image.fromarray((mask[13:75, 85:680]*255).astype('uint8'))
img = img.resize((img.width*6, img.height*6), Image.NEAREST)
# pad with white, then rotate 180
```

```bash
tesseract ocr_180_0.png stdout --psm 7 \
  -c tessedit_char_whitelist='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_{}'
```

```text
ECHO-7-LANTERN
```

Cross-checks in other orientations produced garbage (`NadINY1-7-0HD`, `ECHO-A-TYUILEEW`, …), confirming the 180° orientation is the intended one.

**Passphrase: `ECHO-7-LANTERN`.**

---

## 7. Phase 6 — Decryption (and why it kept failing)

### 7.1 Naïve attempt — fails

```bash
python3 - <<'PY'
d = open('extracted.bin','rb').read()
open('openssl.bin','wb').write(d[8:])   # skip GHST + length
PY

openssl enc -d -aes-256-cbc -in openssl.bin -pass pass:'ECHO-7-LANTERN'
# bad decrypt ... wrong final block length
```

### 7.2 Root cause #1 — ciphertext length is not block-aligned

Count the bytes:

```text
total payload            = 57837
minus GHST + length (8)  = 57829   (openssl.bin)
minus Salted__ + salt(16)= 57813   (ciphertext)
57813 mod 16             = 5       <-- NOT a multiple of 16
```

AES-CBC ciphertext must be a multiple of the 16-byte block. `57813 % 16 == 5` means **the whole 57 KB tail is not the OpenSSL message at all**. Any decryptor will either drop 5 bytes and then fail the final-block/padding check, or refuse outright.

This is exactly what happened: every CBC attempt decrypted a bunch of blocks and then died on the padding.

### 7.3 Failure #2 — brute-forcing ciphers and digests

Assuming the passphrase was slightly wrong, a broad sweep was run over:

* ciphers: `aes-{128,192,256}-{cbc,ecb,cfb,ofb,ctr}`, `des*`, `bf-cbc`, `cast5-cbc`, `camellia-*`, `seed-cbc`, `aria-*`, `rc2-cbc`, `rc4`, `chacha20`
* digests: `sha256`, `md5`, `sha1`
* passphrase variants: upper/lower, dashes removed/replaced, `ECHO7LANTERN`, `LANTERN`, `ECHO-7`, `ghost`, `SPECTROGRAM`, wrapped in `HackCTF{...}`, etc.

Result: **no valid CBC padding anywhere.** The only “successes” were stream modes (CTR/OFB/CFB/ChaCha20), which *always* return data and are therefore meaningless for a passphrase check.

> Lesson: never use “openssl returned 0” as proof for stream modes. Use a plaintext check.

### 7.4 Failure #3 — truncation brute force

If the 5 extra bytes were just channel padding, truncating the tail should eventually produce a valid padding block. Tried every tail cut from 0 to 80 bytes, plus offsets 0–40, across CBC ciphers/digests. **No valid padding.** So the problem was not "a few junk bytes at the end"; the structure itself was being mis-parsed.

### 7.5 The pivot — check the *first block* instead of the padding

Because CBC decrypts block-by-block, the **first plaintext block is correct iff the key/IV are correct**, regardless of padding errors later. So the sweep was re-run and scored on the *printability of the first 48 bytes* across ciphers **and KDF settings** (`legacy`, `-pbkdf2`, `-pbkdf2 -iter 10000/100000/1000000`).

One candidate lit up instantly:

```text
cipher = aes-256-cbc
kdf    = -pbkdf2  (default 10000 iterations)
md     = sha256
pass   = ECHO-7-LANTERN
first 48 bytes:
  b'HackCTF{sp3ctr0gr4m_gh0sts_n3v3r_d13}\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
```

Two revelations:

1. The passphrase and crypto parameters were **right all along**: **AES-256-CBC + PBKDF2 + SHA-256**. The legacy `EVP_BytesToKey` KDF (openssl's default without `-pbkdf2`) was the wrong KDF — another reason the first attempts failed.
2. The plaintext ends after 48 bytes: **37-character flag + 11 bytes of `0x0b` PKCS#7 padding = 48 bytes**. So the ciphertext is **48 bytes**, i.e. the OpenSSL blob is `8 (Salted__) + 8 (salt) + 48 (ciphertext) = 64 bytes`.

### 7.6 The insight — `0x40` is the blob length

Go back to the header:

```text
47 48 53 54 | 00 00 00 40 | ...
  G  H  S  T |   length=64 |
```

`0x40 = 64` is **exactly** the OpenSSL blob size. The container is:

```text
[ "GHST" ][ uint32 BE = 64 ][ 64-byte OpenSSL blob ][ 57,765 bytes of decoy ]
```

Everything after offset `8 + 64 = 72` is filler. That filler is what broke every naive decrypt: it is random-looking and made the “ciphertext” look 57 KB long and misaligned.

### 7.7 Final decryption — clean

```python
d = open('extracted.bin','rb').read()
assert d[:4] == b'GHST'
length = int.from_bytes(d[4:8], 'big')     # 64
blob = d[8:8+length]
open('blob64.bin','wb').write(blob)
```

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 \
  -in blob64.bin -pass pass:'ECHO-7-LANTERN' -out flag.txt
# exit code 0  (valid PKCS#7 padding)
```

```text
$ cat flag.txt
HackCTF{sp3ctr0gr4m_gh0sts_n3v3r_d13}
```

Byte-verified (37 bytes, correct padding stripped):

```text
H a c k C T F { s p 3 c t r 0 g r 4 m _ g h 0 s t s _ n 3 v 3 r _ d 1 3 }
```

---

## 8. Verification

Independent checks that the result is not a fluke:

* `blob64.bin` is exactly 64 bytes and starts with `Salted__`.
* Decrypt returns **exit 0** (PKCS#7 validates) — not just “looks printable”.
* The plaintext is exactly 37 bytes, matching the flag length, and the final 11 bytes are `0x0b`.
* The phrase `sp3ctr0gr4m_gh0sts_n3v3r_d13` is thematically consistent with the challenge name.

---

## 9. Every dead end, in one table

| # | Attempt | Why it failed | What changed |
|---|---|---|---|
| 1 | Listen to / transcribe left channel with Whisper | Not speech; it's a spectrogram drawing | Look, don't listen |
| 2 | Whole-file spectrogram | Message band too thin/compressed | Crop to 4.2–6.9 kHz, 10.5–22.5 s |
| 3 | Eyeball ASCII at arbitrary aspect ratios | Glyphs recognizable but unreadable | Binarize and segment structurally |
| 4 | Direct Tesseract on spectrogram crops | Continuous tone + mirroring + bright baseline | Build clean binary mask first |
| 5 | OCR at 0°/90°/270° | Text is rotated 180° | Rotate 180° |
| 6 | Horizontal mirror only | Gave plausible `ECHO-…` but `Γ`/`\` never resolved | Switch to 180° rotation (`Γ→L`, `\→7`) |
| 7 | `openssl enc -d -aes-256-cbc` (legacy KDF) | Wrong KDF + ciphertext length not block-aligned | Try `-pbkdf2`, inspect structure |
| 8 | Cipher/digest/passphrase brute force | All failures because of structural misparse | Check first plaintext block instead of padding |
| 9 | Tail truncation 0–80 bytes | Extra data isn't at the tail of the blob — it's *after* the blob | Read the length field |
| 10 | Assume `GHST`+length is just a wrapper | 57 KB of decoy made ciphertext look misaligned | `0x40` is the blob length; take exactly 64 bytes |

---

## 10. Lessons worth keeping

1. **A length field is data, not decoration.** If a format gives you a size, use it before you feed a parser the whole buffer.
2. **Validate with the *first* block, not the padding.** CBC padding tells you “key maybe right”; the first block tells you “key definitely right”.
3. **Stream modes always “succeed”.** Never accept exit-code 0 as proof when the cipher has no padding.
4. **Spectrogram text is often transformed.** Check 0°/90°/180°/270° and mirroring; a single stubborn glyph (here `Γ→L`) disambiguates mirror from 180°.
5. **Structural segmentation beats eyeballing.** Zero-column/zero-row projections cleanly found 14 glyphs and the exact text rectangle.
6. **Beware wrong-format decoys.** `CTF{...}` decoy was intentionally not `HackCTF{...}`.
7. **Channel asymmetry is a tell.** A 16-bit audio channel taking only values −2..3 is a data channel, not audio.

---

## 11. Appendix — one-shot reproduction

```bash
# 1) evidence
gunzip -k evidence.img.gz
file evidence.img                          # ext4, volume EVIDENCE
debugfs -R "lsdel" evidence.img            # inode 15, 1850844 bytes
debugfs -R "dump <15> voice.wav" evidence.img

# 2) right-channel LSB
python3 - <<'PY'
import wave, numpy as np
w = wave.open('voice.wav','rb'); n, ch = w.getnframes(), w.getnchannels()
raw = np.frombuffer(w.readframes(n), np.int16).reshape(-1, ch)
bits = (raw[:,1] & 1).astype(np.uint8)
open('extracted.bin','wb').write(np.packbits(bits[:len(bits)//8*8]).tobytes())
PY
# extracted.bin = "GHST" + uint32BE(64) + OpenSSL blob + decoy

# 3) spectrogram passphrase (see §6 for the full segmentation)
#    -> ECHO-7-LANTERN

# 4) decrypt the 64-byte blob
python3 - <<'PY'
d = open('extracted.bin','rb').read()
assert d[:4]==b'GHST'
L = int.from_bytes(d[4:8],'big')
open('blob64.bin','wb').write(d[8:8+L])
PY
openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 \
  -in blob64.bin -pass pass:'ECHO-7-LANTERN'
# HackCTF{sp3ctr0gr4m_gh0sts_n3v3r_d13}
```

---

## 12. Flag

```text
HackCTF{sp3ctr0gr4m_gh0sts_n3v3r_d13}
```
