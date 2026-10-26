# Matryoshka Protocol — Full Challenge Writeup

**Challenge Name:** Matryoshka Protocol  
**Category:** Digital Forensics / Steganography / Signal Processing / Cryptography  
**Points:** 250  
**Flag Format:** `HackCTF{...}`  
**Provided Files:** `relic.png` (5,442,824 bytes, 512x512 RGB PNG)  
**Hint:** "Rows lie. Columns don’t"  
**Flag:** `HackCTF{m4tryoshka_pr0t0c0l_n0_sh0rtcut_5d8e}`  

---

## 1. Executive Summary

"Matryoshka Protocol" is an intricate, multi-layered digital forensics and steganography challenge. Mirroring the traditional Russian nesting doll concept, each successfully unlocked artifact provides the exact credential or carrier signal necessary to access the next deeper layer:

1. **Outer Shell (Image & Steganography):**  
   `relic.png` contains an appended password-protected ZIP archive (`archive.zip`) hidden after the PNG `IEND` chunk. The archive password and instructions are concealed inside the image pixel array. Standard row-by-row steganographic scanners fail because the bits are stored in column-major order ("Rows lie. Columns don't"). Reading bit 1 of the Red channel down columns yields the zip passphrase `relic-9Q4x-cipher` and the instruction `tape key: lowercase of what you hear.`

2. **Second Doll (Audio Archive):**  
   Extracting `archive.zip` yields `tape.wav` (5.5 MB, 30.0-second stereo PCM at 48,000 Hz), representing an analog cassette tape carrying two distinct signals on separate stereo tracks.

3. **Third Doll (The Locked Signal - Left Channel):**  
   Channel 0 (Left) contains a 6.0-second Frequency Shift Keying (FSK) transmission from 2.0s to 8.0s operating at 100 baud using 1800 Hz (space/0) and 2600 Hz (mark/1). Demodulating this stream reveals an HDLC-style frame with a 32-bit preamble, sync byte `0x7E`, a 16-bit big-endian length prefix (`0x0040` = 64 bytes), a 64-byte OpenSSL encrypted blob (`Salted__...`), and a 32-bit big-endian CRC32 checksum (`0x2DFAF280`).

4. **Fourth Doll (The Key to the Signal - Right Channel):**  
   Channel 1 (Right) contains an on-off keyed 650 Hz Morse code carrier tone between 14.65s and 25.0s on a 90 ms (4320-sample) unit grid. Direct forward decoding produces an unreadable string (`1ROTÄESFFDA`). Analyzing the transmission timing and testing for temporal inversion reveals that the audio was recorded backwards. Inverting the timeline decodes cleanly to `NULLSECTOR9`. Converting to lowercase per the instructions produces `nullsector9`.

5. **Inner Core (Cryptographic Recovery):**  
   Decrypting the 64-byte payload using OpenSSL AES-256-CBC with PBKDF2 SHA-256 and passphrase `nullsector9` recovers the plaintext flag:
   `HackCTF{m4tryoshka_pr0t0c0l_n0_sh0rtcut_5d8e}`

---

## 2. Attack Surface & Initial Reconnaissance

### Initial File Analysis

Inspecting the provided file `relic.png`:

```bash
$ ls -lh relic.png
-rw-r--r-- 1 boss boss 5.2M Oct 25 20:44 relic.png

$ file relic.png
relic.png: PNG image data, 512 x 512, 8-bit/color RGB, non-interlaced

$ binwalk relic.png
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, total size: 320541 bytes
320541        0x4E41D         ZIP archive, file count: 1, total size: 5122283 bytes
```

`relic.png` is composed of:
- Bytes `0` to `320540`: Valid PNG image stream (320,541 bytes).
- Bytes `320541` to `5442823`: Appended ZIP archive (5,122,283 bytes).

Inspecting the appended ZIP file with `7z`:

```bash
$ 7z l -slt archive.zip
Path = archive.zip
Type = zip
Physical Size = 5122283
----------
Path = tape.wav
Size = 5760044
Packed Size = 5122101
Encrypted = +
Method = ZipCrypto Deflate:Maximum
```

The archive is password-protected using ZipCrypto and contains a single file, `tape.wav`.

### Inspecting PNG Metadata

Running `exiftool`:

```text
ExifTool Version Number         : 13.55
File Name                       : relic.png
File Size                       : 5.4 MB
Image Width                     : 512
Image Height                    : 512
Bit Depth                       : 8
Color Type                      : RGB
Comment                         : Q1RGe24xY2VfdHJ5X2J1dF9uMH0=
Software                        : relic-encoder 0.9
Warning                         : [minor] Trailer data after PNG IEND chunk
```

Decoding the base64 comment:
```bash
$ echo "Q1RGe24xY2VfdHJ5X2J1dF9uMH0=" | base64 -d
CTF{n1ce_try_but_n0}
```

The comment is an intentional decoy flag designed to catch automated or superficial regex scrapers.

---

## 3. Failed Attempts & Methodological Pivots

```
[Initial PNG File]
        │
        ├── Attempt 1: Standard Stego Tools (zsteg, row LSB) ──────► FAILED (White noise)
        │       │
        │       └── Pivot: Column-Major LSB Scan ──────────────────► SUCCESS (Found Zip Password)
        │
[Extracted tape.wav]
        │
        ├── Attempt 2: Channel 0 Audio Transcription (Whisper) ───► FAILED (Synthesized FSK modem noise)
        │       │
        │       └── Pivot: Instantaneous Frequency Analysis ──────► SUCCESS (FSK Demodulation @ 100 Baud)
        │
        ├── Attempt 3: Channel 1 Direct Morse Translation ────────► FAILED ("1ROTÄESFFDA" / "EEEENAEETNI...")
        │       │
        │       ├── Sub-attempt 3a: Caesar / ROT Decryption ──────► FAILED
        │       ├── Sub-attempt 3b: Language Identification ───────► FAILED
        │       └── Pivot: Temporal Reversal (Time Inversion) ────► SUCCESS ("NULLSECTOR9")
        │
[Encrypted Signal Payload]
        │
        └── Decryption with "nullsector9" (AES-256-CBC PBKDF2) ────► SUCCESS (Final Flag Recovered)
```

### Failed Attempt 1: Standard Row-by-Row Steganography

- **Observation:** Tools like `zsteg` or standard Python LSB scripts conventionally parse pixel arrays row-by-row (raster scan order): `(y=0, x=0), (y=0, x=1), ...`.
- **Why It Failed:** Running standard LSB extractors along rows produced high-entropy pseudorandom bytes with no recognizable file headers or printable ASCII strings.
- **The Pivot:** The prompt explicitly stated:
  `💡 Hint: Rows lie. Columns don’t`
  This was an instruction to traverse the pixel matrix column-by-column (Fortran order / column-major: `arr[:, x, c]`). When transposed, column traversal immediately uncovered readable text.

### Failed Attempt 2: Direct ASR / Audio Transcription

- **Observation:** `tape.wav` contains audible noise, FSK screeching, and beeps.
- **Why It Failed:** Automatic Speech Recognition (Vosk / Whisper) yielded no coherent speech transcriptions because the audio tracks carry pure synthetic tones: Channel 0 is binary FSK data, and Channel 1 is a 650 Hz continuous wave (CW) tone.
- **The Pivot:** Shifted from speech processing to RF/digital signal processing:
  - Channel 0: FSK demodulation via quadrature correlation.
  - Channel 1: Pulse-width / envelope timing analysis.

### Failed Attempt 3: Direct Forward Morse Interpretation

- **Observation:** Demodulating the 650 Hz tone on Channel 1 yielded clean dits and dahs.
- **Why It Failed:**
  - An initial thresholding pass sampled with an offset starting at the second pulse, falsely grouping pulses into `EEEENAEETNI[--..-..]LAF`.
  - Re-aligning the grid to the true first pulse at sample 703269 produced `.----` (1), `.-.` (R), `---` (O), `-` (T), `.-.-` (Ä), `.` (E), `...` (S), `..-.` (F), `..-.` (F), `-..` (D), `.-` (A) -> `1ROTÄESFFDA`.
  - Testing `1rotäesffda`, `1rotaesffda`, ROT ciphers, and anagrams against the OpenSSL ciphertext returned `bad decrypt`.
- **The Pivot:** In related challenges created by the same author (e.g., `Whisper Twice`, `Ghost in the Spectrogram`), secret data was frequently reversed in time or rotated 180°. Reversing the unit sequence in time transformed the symbols into clean standard English:
  `.-` (A) reversed is `-..` (D)... all the way to `NULLSECTOR9`.

---

## 4. Detailed Step-by-Step Walkthrough

### Phase 1: Breaking the Image Layer (`relic.png`)

Analyzing the spatial characteristics of `relic.png` in Python:

```python
from PIL import Image
import numpy as np

img = Image.open("relic.png")
arr = np.array(img)

# Inspect mean values across axes
col_means = arr[:, :, 0].mean(axis=0) # Channel 0 down columns: varies 1.39 to 247.71
row_means = arr[:, :, 1].mean(axis=1) # Channel 1 across rows: varies 6.90 to 247.45
```

The image has a directional gradient structure where Channel 0 corresponds to the horizontal axis (X) and Channel 1 to the vertical axis (Y).

Applying the hint "Rows lie. Columns don't", we scan all bit planes in column-major order:

```python
from PIL import Image
import numpy as np

img = Image.open("relic.png")
arr = np.array(img)

for c_idx, c_name in enumerate(["R", "G", "B"]):
    for bit in range(8):
        plane = (arr[:, :, c_idx] >> bit) & 1
        # Traverse column-by-column (Fortran order)
        bits_col = plane.T.flatten()
        bytes_col = np.packbits(bits_col).tobytes()
        
        # Check printable length
        if b"zip pass:" in bytes_col:
            print(f"Found in Channel {c_name} bit {bit}:")
            print(bytes_col[:80])
```

**Output:**
```text
Found in Channel R bit 1:
b'\x00Atape key: lowercase of what you hear. zip pass: relic-9Q4x-cipher2D\x94f@...'
```

Byte breakdown:
- `0x0041` (65 decimal): Big-endian 16-bit length prefix.
- Followed by exactly 65 bytes of ASCII plaintext:
  `tape key: lowercase of what you hear. zip pass: relic-9Q4x-cipher`

This extracts two critical elements:
1. Archive Password: `relic-9Q4x-cipher`
2. Decryption Rule: The key to the tape is the lowercase string of what is heard on the audio tape.

---

### Phase 2: Archive Extraction

Extracting `tape.wav` from `archive.zip` using the recovered passphrase:

```python
import zipfile

with zipfile.ZipFile("archive.zip") as zf:
    zf.extract("tape.wav", pwd=zip_pass)
```

File inspection:
- Name: `tape.wav`
- Format: RIFF WAVE audio, Microsoft PCM, 16-bit signed stereo, 48,000 Hz
- Duration: Exactly 30.000 seconds (1,440,000 frames)
- File size: 5,760,044 bytes

Comparing Channel 0 (Left) and Channel 1 (Right):
```python
import scipy.io.wavfile as wav
import numpy as np

rate, data = wav.read("tape.wav")
diff = data[:, 0].astype(int) - data[:, 1].astype(int)
print("Channels differ:", np.any(diff != 0)) # True
```

The channels carry completely independent signals.

---

### Phase 3: Left Channel Signal Demodulation (Channel 0)

Scanning Channel 0 for active segments shows silence/hiss except between `2.000000s` and `8.000000s` (sample indices `96000` to `384000`), an exact 6.0000-second transmission (288,000 samples).

Spectral analysis of this window reveals two dominant frequencies:
- Mark frequency: `2600.0 Hz`
- Space frequency: `1800.0 Hz`

Calculating symbol durations:
- Run lengths of frequency transitions occur at multiples of 480 samples.
- Baud rate: $48000 / 480 = 100\text{ Baud}$.
- Total symbols: $288,000 / 480 = 600\text{ bits}$.

Demodulating Channel 0 using coherent quadrature correlation:

```python
import numpy as np
import scipy.io.wavfile as wav

rate, data = wav.read("tape.wav")
sig = data[96000:384000, 0].astype(float)

symbol_len = 480
n_symbols = 600

t = np.arange(symbol_len) / rate
cos_1800 = np.cos(2 * np.pi * 1800 * t)
sin_1800 = np.sin(2 * np.pi * 1800 * t)
cos_2600 = np.cos(2 * np.pi * 2600 * t)
sin_2600 = np.sin(2 * np.pi * 2600 * t)

bits = []
for i in range(n_symbols):
    chunk = sig[i*symbol_len : (i+1)*symbol_len]
    p1800 = np.sum(chunk * cos_1800)**2 + np.sum(chunk * sin_1800)**2
    p2600 = np.sum(chunk * cos_2600)**2 + np.sum(chunk * sin_2600)**2
    bits.append("1" if p2600 > p1800 else "0")

bitstream = "".join(bits)
```

Inspecting the decoded bitstream:
- Preamble: `10101010101010101010101010101010` (32 bits alternating synchronization pattern).
- HDLC Flag: `01111110` (`0x7E`).
- Following `0x7E`, assembling remaining bits into bytes:
  - Byte `0..1`: `0x0040` (Big-endian uint16 length = 64 bytes).
  - Byte `2..65`: 64 bytes of ciphertext payload starting with `Salted__`.
  - Byte `66..69`: `0x2DFAF280` (4-byte CRC32 trailer).

Verifying the integrity of the payload:
```python
import zlib

payload = payload_bytes[2:66] # 64 bytes
crc_trailer = payload_bytes[66:70]
crc_calc = zlib.crc32(payload)

assert crc_calc.to_bytes(4, "big") == crc_trailer
print("CRC32 Verification: PASSED (0x2DFAF280)")
```

The ciphertext payload is intact and verified.

---

### Phase 4: Right Channel Audio Key Extraction (Channel 1)

Scanning Channel 1 for active segments:
- Inactive / noise: 0.0s to 14.65s.
- Active keyed tone: 14.651s to 24.999s.
- Continuous carrier: 25.0s to 30.0s (5.0-second end marker).
- Frequency: Exclusively 650.0 Hz.

Measuring the unit timing grid:
- First tone begins at sample `703269` ($t \approx 14.6514\text{ s}$).
- Unit duration: Exactly 4320 samples ($4320 / 48000 = 0.0900\text{ s} = 90\text{ ms}$).
- A dot (dit) is 1 unit ($4320$ samples).
- A dash (dah) is 3 units ($12960$ samples).
- An intra-character space is 1 unit ($4320$ samples).
- An inter-character space is 3 units ($12960$ samples).

Sampling the 650 Hz envelope on the 4320-sample grid:

```python
import numpy as np
import scipy.io.wavfile as wav

rate, data = wav.read("tape.wav")
c1 = data[:, 1].astype(float)
t = np.arange(len(c1)) / rate
cos_650 = np.cos(2 * np.pi * 650 * t)
sin_650 = np.sin(2 * np.pi * 650 * t)
window = 480
i_comp = np.convolve(c1 * cos_650, np.ones(window)/window, mode="same")
q_comp = np.convolve(c1 * sin_650, np.ones(window)/window, mode="same")
env = np.sqrt(i_comp**2 + q_comp**2)

start_sample = 703269
unit = 4320

units = []
for u in range(118):
    s = start_sample + u * unit
    val = np.mean(env[s+500 : s+unit-500])
    units.append("1" if val > 5000 else "0")

grid_str = "".join(units)
```

The raw grid bitstring:
```text
1011101110111011100010111010001110111011100011100010111010111000100010101000101011101000101011101000111010100010111000
```

Forward decoding:
- `.----` (1)
- `.-.` (R)
- `---` (O)
- `-` (T)
- `.-.-` (Ä)
- `.` (E)
- `...` (S)
- `..-.` (F)
- `..-.` (F)
- `-..` (D)
- `.-` (A)
-> `1ROTÄESFFDA` (unintelligible).

#### The Time-Reversal Solution:
Inverting the bitstream temporally (`grid_str[::-1]`):
```text
1110100010101110001011101010001011101010001010100010001110101110100011100011101110111000101110100011101110111011101
```

Splitting on `000` (letter gaps) and translating:

| Chunk | Morse Symbols | Translated Letter |
| :--- | :--- | :--- |
| `11101` | `-.` | **N** |
| `1010111` | `..-` | **U** |
| `101110101` | `.-..` | **L** |
| `101110101` | `.-..` | **L** |
| `10101` | `...` | **S** |
| `1` | `.` | **E** |
| `11101011101` | `-.-.` | **C** |
| `111` | `-` | **T** |
| `11101110111` | `---` | **O** |
| `1011101` | `.-.` | **R** |
| `11101110111011101` | `----.` | **9** |

The reversed audio spells:
**`NULLSECTOR9`**

Per the prompt instruction (*"tape key: lowercase of what you hear"*), the passphrase is:
**`nullsector9`**

---

### Phase 5: Cryptographic Decryption

The 64-byte payload extracted from Channel 0 has standard OpenSSL encryption framing:
- Bytes `0..7`: ASCII `Salted__`
- Bytes `8..15`: 8-byte salt (`b82ab0d339913c36`)
- Bytes `16..63`: 48 bytes of AES ciphertext (3 PKCS#7 padded 16-byte blocks)

Executing decryption using OpenSSL:

```bash
$ openssl enc -d -aes-256-cbc -pbkdf2 -md sha256 \
    -in signal_clean.enc \
    -pass pass:nullsector9
```

**Output:**
```text
HackCTF{m4tryoshka_pr0t0c0l_n0_sh0rtcut_5d8e}
```

---

## 5. Automated End-to-End Solve Script

The complete exploit chain implemented in a standalone Python script:

```python
#!/usr/bin/env python3
import struct
import zipfile
import zlib
import numpy as np
import scipy.io.wavfile as wav
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
import hashlib

def solve():
    print("[*] Stage 1: Extracting Zip Password from relic.png...")
    img = Image.open("relic.png")
    arr = np.array(img)
    
    # Red channel bit 1 down columns
    red_plane = (arr[:, :, 0] >> 1) & 1
    col_bytes = np.packbits(red_plane.T.flatten()).tobytes()
    
    # Parse uint16 length and message
    msg_len = int.from_bytes(col_bytes[:2], "big")
    msg = col_bytes[2:2+msg_len].decode("latin1")
    print(f"    Recovered string: {msg}")
    zip_pass = msg.split("zip pass: ")[1].strip().encode()
    print(f"    ZIP Passphrase: {zip_pass.decode()}")

    print("[*] Stage 2: Extracting tape.wav from archive.zip...")
    with zipfile.ZipFile("archive.zip") as zf:
        zf.extract("tape.wav", pwd=zip_pass)

    print("[*] Stage 3: Demodulating FSK Signal on Left Channel...")
    rate, audio = wav.read("tape.wav")
    left = audio[96000:384000, 0].astype(float) # 2.0s to 8.0s
    
    symbol_len = 480
    n_symbols = len(left) // symbol_len
    t = np.arange(symbol_len) / rate
    
    cos1800, sin1800 = np.cos(2*np.pi*1800*t), np.sin(2*np.pi*1800*t)
    cos2600, sin2600 = np.cos(2*np.pi*2600*t), np.sin(2*np.pi*2600*t)
    
    bits = []
    for i in range(n_symbols):
        chunk = left[i*symbol_len : (i+1)*symbol_len]
        p1800 = np.sum(chunk*cos1800)**2 + np.sum(chunk*sin1800)**2
        p2600 = np.sum(chunk*cos2600)**2 + np.sum(chunk*sin2600)**2
        bits.append("1" if p2600 > p1800 else "0")
        
    bit_str = "".join(bits)
    sync_idx = bit_str.find("01111110") + 8
    payload_bits = bit_str[sync_idx:]
    
    raw_packet = bytearray()
    for b in range(0, len(payload_bits) - 7, 8):
        raw_packet.append(int(payload_bits[b:b+8], 2))
        
    payload_len = int.from_bytes(raw_packet[:2], "big")
    enc_blob = bytes(raw_packet[2:2+payload_len])
    crc_rx = int.from_bytes(raw_packet[2+payload_len : 6+payload_len], "big")
    assert zlib.crc32(enc_blob) == crc_rx
    print(f"    Payload CRC32 0x{crc_rx:08X} verified OK.")

    print("[*] Stage 4: Demodulating and Reversing Morse Audio on Right Channel...")
    right = audio[:, 1].astype(float)
    cos650 = np.cos(2 * np.pi * 650 * np.arange(len(right)) / rate)
    sin650 = np.sin(2 * np.pi * 650 * np.arange(len(right)) / rate)
    window = 480
    i_c = np.convolve(right * cos650, np.ones(window)/window, mode="same")
    q_c = np.convolve(right * sin650, np.ones(window)/window, mode="same")
    env = np.sqrt(i_c**2 + q_c**2)

    start_sample = 703269
    unit = 4320
    units = []
    for u in range(118):
        s = start_sample + u * unit
        val = np.mean(env[s+500 : s+unit-500])
        units.append("1" if val > 5000 else "0")
        
    # Reverse unit string
    rev_str = "".join(units).strip("0")[::-1]
    
    MORSE = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
        "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
        "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
        ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
        "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3",
        "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
        "----.": "9"
    }
    
    letters = []
    import re
    for g in re.split("0{3,}", rev_str):
        if not g: continue
        sym = "".join("-" if e == "111" else "." for e in g.split("0"))
        letters.append(MORSE[sym])
        
    decoded_key = "".join(letters).lower()
    print(f"    Decoded Reversed Audio Key: {decoded_key}")

    print("[*] Stage 5: Decrypting Encrypted Signal Payload...")
    salt = enc_blob[8:16]
    ct = enc_blob[16:]
    
    # OpenSSL EVP_BytesToKey with PBKDF2 SHA256 (10,000 iterations)
    derived = hashlib.pbkdf2_hmac("sha256", decoded_key.encode(), salt, 10000, 48)
    key, iv = derived[:32], derived[32:48]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    pt = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    unpadder = padding.PKCS7(128).unpadder()
    flag = (unpadder.update(pt) + unpadder.finalize()).decode()

    print(f"\n[+] SUCCESS! Recovered Flag: {flag}\n")

if __name__ == "__main__":
    solve()
```

---

## 6. Key Values & Artifact Summary

| Layer | Artifact / Property | Value / Description |
| :--- | :--- | :--- |
| **Layer 1** | PNG File | `relic.png` (512x512 RGB) |
| **Layer 1** | ZIP Offset | `320541` (`0x4E41D`) |
| **Layer 1** | Stego Channel | Red Channel bit 1, Column-Major |
| **Layer 1** | ZIP Password | `relic-9Q4x-cipher` |
| **Layer 2** | Audio Container | `tape.wav` (48 kHz Stereo, 30.0s) |
| **Layer 3** | Signal Track | Left Channel (Channel 0) |
| **Layer 3** | Modulation | FSK @ 100 Baud (1800 Hz Space, 2600 Hz Mark) |
| **Layer 3** | Packet Structure | Preamble + `0x7E` + Length (`0x0040`) + Payload + CRC32 |
| **Layer 3** | CRC32 Checksum | `0x2DFAF280` |
| **Layer 4** | Key Track | Right Channel (Channel 1) |
| **Layer 4** | Modulation | OOK 650 Hz Carrier |
| **Layer 4** | Unit Grid | 90 ms (4320 samples) per Dit |
| **Layer 4** | Audio Orientation | Time-Reversed Morse Code |
| **Layer 4** | Audio Plaintext | `NULLSECTOR9` |
| **Layer 4** | Signal Key | `nullsector9` |
| **Layer 5** | Cryptography | AES-256-CBC, PBKDF2 SHA-256 (10,000 iter) |
| **Layer 5** | Plaintext Flag | `HackCTF{m4tryoshka_pr0t0c0l_n0_sh0rtcut_5d8e}` |

---

## 7. Lessons Learned & Key Takeaways

1. **Dimensional Traversal in Steganography:**  
   When a steganographic hint mentions rows vs. columns ("Rows lie. Columns don't"), standard row-major scanning (`arr[y, x]`) will completely jumble the data. Inspecting the bitstream in column-major order (`arr.T` or Fortran order) is mandatory.

2. **Decoy Awareness:**  
   Metadata comments (e.g. `CTF{n1ce_try_but_n0}`) are often deliberately placed to trigger pattern matchers and misdirect triage. Validating against the required flag format (`HackCTF{...}`) prevents chasing decoys.

3. **Packet Framing and Checksums Rule Out False Positives:**  
   In custom audio/signal demodulation, calculating and validating the embedded CRC32 checksum (`0x2DFAF280`) provides mathematical certainty that demodulation parameters (baud rate, mark/space frequencies, slice thresholds) are bit-exact before moving on to key derivation.

4. **Temporal Reversal in Audio/Morse Steganography:**  
   If clean Morse pulses translate to non-dictionary gibberish or phonetically unusual patterns (like `1ROTÄESFFDA`), testing for time reversal (`signal[::-1]`) is an essential step. Reversed audio is completely audible to human ears as beeps, but mathematically inverts every letter's constituent symbols and order.
