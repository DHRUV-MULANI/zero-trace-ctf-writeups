# Last Ferry Out — HackCTF Challenge Writeup

**Challenge:** Last Ferry Out  
**Category:** Digital Forensics / OSINT / Steganography / Signal Processing  
**Points:** 100  
**Flag:** `HackCTF{18-Feb-2024_23:41}`  

---

## 1. Challenge Overview

### Prompt
> Operator “N0rth Star” disappeared three weeks ago.  
> All we recovered is one photo from his burner phone.  
> He boarded a ferry that night and never came back.  
> We need the exact date and time he left.  
>  
> Flag format: `HackCTF{DD-Mon-YYYY_HH:MM}`  
> (24h time, month is 3 letters with a capital first letter, e.g. `HackCTF{05-Jan-2020_09:30}`)  
>  
> 💡 Hint: *The small picture remembers what the big one forgot*

### Given Files
- `ghost.jpg` (2.8 MB JPEG image)

---

## 2. Phase 1: Initial Inspection & Failed Hypotheses

### Visual Inspection
Viewing `ghost.jpg` displayed a nocturnal panoramic skyline of Los Angeles skyscrapers (notably the US Bank Tower). There was no visible ferry, terminal, or water body, contradicting the challenge narrative.

### Metadata Extraction
Running `exiftool` on `ghost.jpg` revealed two critical anomalies:
```text
File Modify Date     : 2026:10:25 18:58:30+05:30
Comment              : bjBydGhzdDRyNw==
Thumbnail Offset     : 222
Thumbnail Length     : 40729
Image Size           : 3556x2000
Thumbnail Image      : (Binary data 40729 bytes)
```

Decoding the base64 comment string:
```bash
echo -n "bjBydGhzdDRyNw==" | base64 -d
# Output: n0rthst4r7
```

### What We Tried & Where It Failed
1. **Direct Steghide Extraction with Obvious Passphrases:**
   - **Hypothesis:** The string `n0rthst4r7`, `bjBydGhzdDRyNw==`, or variants (`northstar`, `N0rth Star`, blank) might be the steghide passphrase for `ghost.jpg`.
   - **Execution:**
     ```bash
     steghide extract -sf ghost.jpg -p n0rthst4r7
     steghide extract -sf ghost.jpg -p bjBydGhzdDRyNw==
     steghide extract -sf ghost.jpg -p ""
     ```
   - **Failure:** All attempts failed with: `steghide: could not extract any data with that passphrase!`.
2. **File Append / Trailing Data Analysis:**
   - **Hypothesis:** Hidden ZIP, TAR, or payload appended after the JPEG EOI marker (`0xFF 0xD9`).
   - **Execution:** Measured the file size against the last `FF D9` marker.
   - **Failure:** 0 trailing bytes detected; binwalk found only standard JFIF chunks.

---

## 3. Phase 2: Resolving the Hint & Changing the Approach

### The Embedded Thumbnail ("The Small Picture")
The challenge hint states: *"The small picture remembers what the big one forgot."*

In digital forensics, when an image is replaced or cropped in basic photo editing software, the main image stream updates, but the embedded EXIF thumbnail often remains untouched.

Extracting the thumbnail using `exiftool`:
```bash
exiftool -b -ThumbnailImage ghost.jpg > thumb.jpg
```

Inspecting `thumb.jpg` visually:
- Instead of the Los Angeles night skyline, the thumbnail shows an outdoor daylight scene with a road sign:
  **`Changi Point Ferry Terminal ➔`**
- Geographic Location: Changi Point, Singapore (embarkation point for bumboat ferries to Pulau Ubin and Pengerang, Malaysia).

This confirmed the challenge context: the operator was operating around Changi Point, Singapore.

---

## 4. Phase 3: OSINT Pivot (Operator "N0rth Star")

Rather than being a steghide key, the comment `n0rthst4r7` was an online identifier for operator "N0rth Star".

### GitHub Profiling
Querying the GitHub API for user `n0rthst4r7`:
```bash
curl -s https://api.github.com/users/n0rthst4r7
```

The user existed with a single public repository: `n0rthst4r7/ferry-notes`.

Querying repository contents:
```bash
curl -s https://api.github.com/repos/n0rthst4r7/ferry-notes/contents
```
Found `README.md` and `notes.txt`. Fetching `notes.txt`:
```text
backup phrase for the photo vault: Biscuit
(named after the dog. do NOT forget)
```

The repository confirmed:
- Base: Changi Point
- Steghide / Photo Vault Passphrase: `Biscuit`

---

## 5. Phase 4: Steganography Extraction

Equipped with the confirmed passphrase `Biscuit`, `steghide` was executed against `ghost.jpg`:
```bash
steghide extract -sf ghost.jpg -p Biscuit
```

**Result:**
```text
wrote extracted data to "voicemail.wav".
```

---

## 6. Phase 5: Audio Signal Forensics (DTMF Decoding)

### File Analysis
```bash
file voicemail.wav
# RIFF (little-endian) data, WAVE audio, Microsoft PCM, 8 bit, mono 8000 Hz
# Total size: 8044 bytes (44 bytes header + 8000 samples = exactly 1.0 second)
```

### Signal Analysis
Performing an FFT over four 250ms windows (2000 samples each) revealed dual frequency peaks characteristic of standard telephone DTMF tones:

| Window (Time) | Detected Frequencies | DTMF Keypad Equivalent | Digit |
| :--- | :--- | :--- | :--- |
| **0.00s – 0.25s** | 697 Hz + 1336 Hz | Row 1 + Col 2 | **`2`** |
| **0.25s – 0.50s** | 697 Hz + 1477 Hz | Row 1 + Col 3 | **`3`** |
| **0.50s – 0.75s** | 770 Hz + 1209 Hz | Row 2 + Col 1 | **`4`** |
| **0.75s – 1.00s** | 697 Hz + 1209 Hz | Row 1 + Col 1 | **`1`** |

The 4-digit sequence decoded to: **`2341`**, representing the 24-hour departure time **`23:41`**.

---

## 7. Phase 6: Timeline Reconstruction & Date Identification

To determine the departure date, the git history and GitHub event logs for `n0rthst4r7/ferry-notes` were inspected.

Cloning the repository and fetching unreferenced commits from GitHub event logs:
```bash
curl -s https://api.github.com/users/n0rthst4r7/events
```

The push payload showed a `before` SHA of `d5e799a14e062a4b09b1804d54eacac5602b119c`. Fetching this commit:
```bash
git fetch origin d5e799a14e062a4b09b1804d54eacac5602b119c
git log -1 --format=fuller FETCH_HEAD
```

### Commit History:
1. `62894bc` — `Sun Feb 18 21:30:00 2024 +0800` (`init logbook`)
2. `b0d306d` — `Sun Feb 18 22:10:00 2024 +0800` (`add notes`)
3. `d5e799a` — `Sun Feb 18 23:05:00 2024 +0800` (`remove sensitive notes, going dark`)

All timestamps were recorded in **`+0800` (Singapore Standard Time)** on **`18-Feb-2024`**.

- **23:05 SGT (18-Feb-2024):** Operator wiped sensitive notes to go dark.
- **23:41 SGT (18-Feb-2024):** Operator boarded the ferry (decoded from `voicemail.wav`).

---

## 8. Flag Construction

- **Format:** `HackCTF{DD-Mon-YYYY_HH:MM}`
- **Date:** `18-Feb-2024`
- **Time:** `23:41`

```text
HackCTF{18-Feb-2024_23:41}
```

---

## 9. Full Automated Solution Script

```python
import base64
import json
import subprocess
import urllib.request
import wave
import numpy as np

# Step 1: Extract EXIF comment to get handle
cmd = ["exiftool", "-s3", "-Comment", "ghost.jpg"]
comment = subprocess.check_output(cmd).decode().strip()
handle = base64.b64decode(comment).decode().strip()
print(f"[+] Recovered Handle: {handle}")

# Step 2: Query GitHub for notes repository
api_url = f"https://raw.githubusercontent.com/{handle}/ferry-notes/main/notes.txt"
req = urllib.request.urlopen(api_url)
notes = req.read().decode()
passphrase = None
for line in notes.splitlines():
    if "backup phrase" in line:
        passphrase = line.split(":")[-1].strip()
print(f"[+] Found Passphrase: {passphrase}")

# Step 3: Extract hidden voicemail using steghide
subprocess.run(["steghide", "extract", "-sf", "ghost.jpg", "-p", passphrase, "-f"], check=True)

# Step 4: DTMF Decode on voicemail.wav
with wave.open("voicemail.wav", "rb") as w:
    frames = w.readframes(w.getnframes())
audio = np.frombuffer(frames, dtype=np.uint8).astype(np.float32) - 128.0

low_freqs = [697, 770, 852, 941]
high_freqs = [1209, 1336, 1477, 1633]
dtmf_map = {
    (697, 1209): "1", (697, 1336): "2", (697, 1477): "3", (697, 1633): "A",
    (770, 1209): "4", (770, 1336): "5", (770, 1477): "6", (770, 1633): "B",
    (852, 1209): "7", (852, 1336): "8", (852, 1477): "9", (852, 1633): "C",
    (941, 1209): "*", (941, 1336): "0", (941, 1477): "#", (941, 1633): "D",
}

def goertzel(samples, target_freq, sample_rate=8000):
    k = int(0.5 + (len(samples) * target_freq) / sample_rate)
    omega = (2.0 * np.pi * k) / len(samples)
    coeff = 2.0 * np.cos(omega)
    q1 = q2 = 0.0
    for s in samples:
        q0 = coeff * q1 - q2 + s
        q2 = q1
        q1 = q0
    return q1 * q1 + q2 * q2 - q1 * q2 * coeff

digits = []
segment_len = len(audio) // 4
for i in range(4):
    seg = audio[i * segment_len : (i + 1) * segment_len]
    best_low = max(low_freqs, key=lambda f: goertzel(seg, f))
    best_high = max(high_freqs, key=lambda f: goertzel(seg, f))
    digits.append(dtmf_map[(best_low, best_high)])

time_str = f"{digits[0]}{digits[1]}:{digits[2]}{digits[3]}"
print(f"[+] Decoded Time: {time_str}")

# Step 5: Format Final Flag
date_str = "18-Feb-2024"  # From commit timestamps
flag = f"HackCTF{{{date_str}_{time_str}}}"
print(f"[+] Flag: {flag}")
```
