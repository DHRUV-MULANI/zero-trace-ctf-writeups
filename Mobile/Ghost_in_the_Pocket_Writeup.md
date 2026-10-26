# Ghost in the Pocket — Complete CTF Forensics Writeup

**Challenge Name:** Ghost in the Pocket  
**Category:** Mobile Forensics / Steganography  
**Points:** 150 pts  
**Flag Format:** `HackCTF{...}`  
**Target File:** `pixel_dump.tar.gz`  
**Suspect Clue:** *“I never save what I fear. I only draw it.”*  

---

## 1. Executive Summary

During an incident response investigation, a suspect was detained at 2:00 AM, and their Android device was wiped prior to law enforcement seizure. A partial `/data` acquisition (`pixel_dump.tar.gz`) was recovered.

Through forensic artifact reconstruction, the investigation progressed through four layered defensive measures:
1. **Android Gesture Pattern Lock Recovery:** Cracking the SHA-1 hash of `/data/system/gesture.key` to reveal a drawn letter (`Z`).
2. **SQLite Database Freelist Analysis:** Carving deleted SMS records from `/data/data/com.android.providers.telephony/databases/mmssms.db` to uncover the archive password construction rule.
3. **EXIF Decoy Identification & Coordinate Calculation:** Detecting an intentional spoof in the EXIF thumbnail of `IMG_0214.jpg` and extracting the true timestamp (`0214`) and GPS latitude (`18.520`).
4. **Archive Decryption & Spectrogram Steganography:** Unpacking an obfuscated 7-Zip container (`.thumbcache.dat`) with `Z_0214_18.520`, extracting `flag.wav`, and performing high-resolution Short-Time Fourier Transform (STFT) spectral analysis to read the visually synthesized flag.

**Final Flag:**  
`HackCTF{sp3ctr0gr4m_1n_th3_fr33l1st_Z}`

---

## 2. Initial Reconnaissance & Artifact Inventory

Extracting `pixel_dump.tar.gz` produced the following file hierarchy:

```
pixel_dump/
├── data/
│   ├── system/
│   │   └── gesture.key (20 bytes)
│   └── data/
│       └── com.android.providers.telephony/
│           └── databases/
│               └── mmssms.db (8,192 bytes)
└── media/
    └── 0/
        ├── DCIM/
        │   └── Camera/
        │       └── IMG_0214.jpg (24,835 bytes)
        └── Android/
            └── .cache/
                ├── .thumbcache.dat (409,649 bytes)
                └── cache_0.tmp ... cache_14.tmp (15 files)
```

The clue given in the prompt served as the investigative compass:
> *“Everything you need is in the dump, but nothing is where it should be, and not everything is telling the truth.”*
> *“I never save what I fear. I only draw it.”*

---

## 3. Phase 1: Lock Screen Gesture Analysis (`gesture.key`)

### Hypothesis & Mechanics
On Android devices prior to File-Based Encryption (FBE), pattern locks were stored in `/data/system/gesture.key`. The file is exactly 20 bytes long, representing the unsalted SHA-1 hash of the sequential byte array of the connected grid points.

The standard 3x3 pattern grid is indexed 0 to 8:
```
0 (1)    1 (2)    2 (3)
3 (4)    4 (5)    5 (6)
6 (7)    7 (8)    8 (9)
```

### Hash Recovery & Brute-Force
Reading the raw bytes of `gesture.key`:
```
SHA-1 Hash: 6a062b9b3452e366407181a1bf92ea73e9ed4c48
```

Because pattern lengths range from 4 to 9 nodes without repeating points, the entire key space is only 389,112 possibilities. A Python script brute-forced all permutations:

```python
import hashlib, itertools

target = bytes.fromhex('6a062b9b3452e366407181a1bf92ea73e9ed4c48')

for length in range(1, 10):
    for p in itertools.permutations(range(9), length):
        if hashlib.sha1(bytes(p)).digest() == target:
            print("Found (0-indexed):", list(p))
            print("Found (1-indexed):", [x + 1 for x in p])
            break
```

### Result
- **Pattern Sequence (0-indexed):** `[0, 1, 2, 4, 6, 7, 8]`
- **Pattern Sequence (1-indexed):** `[1, 2, 3, 5, 7, 8, 9]`

### Shape Interpretation
Mapping `1 -> 2 -> 3 -> 5 -> 7 -> 8 -> 9` onto the 3x3 lockscreen:
- `1 -> 2 -> 3`: Horizontal bar across top
- `3 -> 5 -> 7`: Diagonal line cutting downward through the center
- `7 -> 8 -> 9`: Horizontal bar across bottom

This forms the capital letter **`Z`**. This directly correlated with the statement: *“I never save what I fear. I only draw it.”*

---

## 4. Phase 2: Roadblocks on `.thumbcache.dat` & Pivot to SQLite Freelist

### Roadblock 1: Direct Password Cracking
File inspection showed that `.thumbcache.dat` was not a bitmap cache, but a **7-Zip archive** (`7-zip archive data, version 0.4` with AES-256 encryption).

Initial attempts tested obvious passwords derived from the gesture lock:
- `1235789`
- `0124678`
- `Z`
- `z`
- `zorro`, `zero`

All produced: `Cannot open encrypted archive. Wrong password?`.

### Roadblock 2: SQLite Querying of `mmssms.db`
The database `mmssms.db` was opened to inspect SMS messages.
```sql
SELECT _id, address, date, body FROM sms;
```
78 SMS messages were returned. The messages were mundane conversational filler (`"bring chai"`, `"busy"`, `"see u"`, `"running late"`).

However, analyzing the `_id` sequence revealed a gap:
- IDs 1 through 39 were present.
- **ID 40 was missing!**
- IDs 41 through 79 continued normally.

### Change of Approach: SQLite Freelist Carving
In SQLite, deleting a row marks the corresponding B-tree leaf page cell as free space (freelist) rather than zeroing it out immediately.

Running low-level string extraction on the database binary:
```bash
strings mmssms.db
```

This successfully extracted the unallocated deleted record:
```
+919855935680
(Pass = the letter on my lock screen + the time on the photo (HHMM) + where I stood (lat, 3 decimals). Glue with underscores. The thumbnail lies.
```

The password construction formula was confirmed:
$$\text{Password} = \text{LockScreenLetter} + \text{"\_"} + \text{PhotoTime(HHMM)} + \text{"\_"} + \text{Latitude(3 decimals)}$$

---

## 5. Phase 3: EXIF Metadata Analysis vs The Thumbnail Decoy

### Roadblock 3: The Embedded Thumbnail Lie
The deleted SMS note warned: **“The thumbnail lies.”**

To investigate why:
1. `exiftool -b -ThumbnailImage IMG_0214.jpg > thumb.jpg` was executed.
2. Viewing `thumb.jpg` displayed a solid red image containing centered text:
   $$\text{Decoy Time: } \mathbf{03:47}$$

If an analyst blindly parsed the thumbnail or used automated thumbnail extraction tools, they would construct a failing password (`Z_0347_...`).

### Extracting True EXIF Metadata
Examining the primary image headers:
- **Filename:** `IMG_0214.jpg`
- **Image Content:** A night sky of stars with `"IMG_0214"` watermarked in the upper-left corner.
- **EXIF `DateTimeOriginal`:** `2026:03:14 02:14:09`
- **True Time (HHMM):** `0214`

### GPS Coordinate Conversion
The GPS metadata embedded in the primary IFD contained:
- `GPSLatitudeRef`: `North`
- `GPSLatitude`: `18 deg 31' 13.44"`

Converting to decimal degrees:
$$\text{Latitude} = 18 + \frac{31}{60} + \frac{13.44}{3600} = 18 + 0.516666... + 0.003733... = 18.5204^\circ\text{ N}$$

Formatting to 3 decimal places:
$$\text{lat} = \mathbf{18.520}$$
*(Coordinates point to Pune, Maharashtra, India).*

---

## 6. Phase 4: Archive Decryption

Assembling the components with underscores:
- **Lock screen letter:** `Z`
- **Photo time:** `0214`
- **Latitude (3 decimals):** `18.520`
- **Candidate Password:** `Z_0214_18.520`

Testing with 7-Zip:
```bash
7z x -p"Z_0214_18.520" -oextracted_thumbcache .thumbcache.dat
```

Result:
```
Extracting archive: .thumbcache.dat
Everything is Ok
Size: 741,420 bytes
Files: 1 (flag.wav)
```

The archive decrypted cleanly, yielding an uncompressed PCM WAVE file: `flag.wav`.

---

## 7. Phase 5: Audio Steganography & Spectrogram Analysis

### Initial Audio Check
Examining `flag.wav`:
- Format: RIFF (little-endian) WAVE audio, Microsoft PCM, 16-bit, mono, 22050 Hz
- Duration: 16.81 seconds
- Listening / Time-domain check: Harsh electronic chirps and sweeping frequencies indicative of image-to-audio synthesis.

### Generating the Spectrogram
The suspect's statement: *“I never save what I fear. I only draw it.”* confirms that the visual data was drawn in the frequency domain.

Using Python, NumPy, SciPy, and Matplotlib:
```python
import numpy as np
import matplotlib.pyplot as plt
from scipy.io import wavfile

sample_rate, data = wavfile.read('flag.wav')
plt.figure(figsize=(24, 8))
plt.specgram(data, Fs=sample_rate, NFFT=1024, noverlap=900, cmap='inferno')
plt.ylim(1500, 7000)
plt.xlim(0, 12)
plt.savefig('spectrogram.png', dpi=300)
```

### Roadblock 4: Disambiguating L33tspeak Characters in the Spectrogram
While the flag was immediately visible, reading exact characters from a low-resolution spectrogram risked transcription errors (e.g., `0` vs `o`, `1` vs `l`, `3` vs `e`, `r` vs `t`).

To eliminate ambiguity, the spectrogram was sliced into high-resolution segments with frequency grid lines:
1. `start_section.png` (0.0s – 3.2s)
2. `mid_section_1.png` (3.0s – 6.5s)
3. `mid_section_2.png` (6.0s – 9.2s)
4. `end_section.png` (8.8s – 12.0s)

#### Detailed Glyph-by-Glyph Deconstruction:

| Time Interval | Character | Font Geometry & Verification Details |
| :--- | :---: | :--- |
| **0.2s – 2.9s** | `HackCTF{` | Standard CTF flag wrapper. Uppercase `H, C, T, F`, lowercase `a, c, k`, opening brace `{`. |
| **3.0s – 3.2s** | `s` | Lowercase glyph spanning 3000 Hz to 5300 Hz. |
| **3.2s – 3.5s** | `p` | Lowercase glyph with descender extending down to 2100 Hz. |
| **3.55s – 3.9s**| `3` | Digit spanning 3000 Hz to 6000 Hz. Three horizontal bars with curved back. |
| **3.95s – 4.2s**| `c` | Lowercase curve spanning 3000 Hz to 5300 Hz. |
| **4.25s – 4.45s**| `t` | Vertical stem reaching 5900 Hz with crossbar at 5200 Hz. |
| **4.48s – 4.68s**| `r` | Vertical stem with rightward-reaching top arm. |
| **4.70s – 5.00s**| `0` | **Crucial verification:** An oval spanning 3000 Hz to 6000 Hz. Vowels (`a, e, o`) in this font have an x-height of 5300 Hz; digits span up to 6000 Hz. Its full height confirms it is the digit **`0`** (zero). |
| **5.05s – 5.35s**| `g` | Round upper loop with descender loop dropping to 2100 Hz. |
| **5.38s – 5.60s**| `r` | Vertical stem with rightward top arm. |
| **5.65s – 5.95s**| `4` | Digit spanning up to 6000 Hz. Diagonal left stroke, horizontal crossbar at 3800 Hz, right vertical stem. Confirms **`4`**. |
| **5.98s – 6.45s**| `m` | Three vertical legs joined at 5300 Hz. |
| **6.45s – 6.70s**| `_` | Low horizontal bar positioned at 2700–3000 Hz (underscore). |
| **6.80s – 7.00s**| `1` | Vertical pillar reaching 6000 Hz with top-left diagonal serif. Confirms digit **`1`**. |
| **7.05s – 7.40s**| `n` | Lowercase two-legged glyph. |
| **7.45s – 7.70s**| `_` | Underscore. |
| **7.72s – 7.92s**| `t` | Lowercase `t`. |
| **7.95s – 8.25s**| `h` | Ascender reaching 6200 Hz with arch at 5300 Hz. |
| **8.30s – 8.65s**| `3` | Digit `3` spanning up to 6000 Hz. |
| **8.65s – 8.92s**| `_` | Underscore. |
| **8.95s – 9.15s**| `f` | Tall stem reaching 6400 Hz with right-curving top hook and crossbar at 5300 Hz. |
| **9.18s – 9.38s**| `r` | Stem with rightward arm. |
| **9.40s – 9.70s**| `3` | Digit `3`. |
| **9.72s – 10.02s**| `3` | Digit `3`. |
| **10.05s – 10.22s**| `l` | Tall single vertical stroke reaching 6200 Hz without serif. |
| **10.25s – 10.48s**| `1` | Vertical stroke reaching 6000 Hz with clear top-left serif (`1`). |
| **10.55s – 10.82s**| `s` | Lowercase `s`. |
| **10.85s – 11.02s**| `t` | Crossbarred `t`. |
| **11.05s – 11.28s**| `_` | Underscore. |
| **11.35s – 11.65s**| `Z` | Large uppercase `Z` spanning 3000 Hz to 6000 Hz. Traces the lock screen gesture. |
| **11.70s – 11.85s**| `}` | Closing curly brace. |

Putting the segments together:
- `sp3ctr0gr4m`
- `_1n_th3_`
- `fr33l1st_Z`

Tied directly to the forensic context:
- `sp3ctr0gr4m`: The audio steganography method.
- `1n_th3_fr33l1st`: The SQLite unallocated space carving where the password formula was recovered.
- `Z`: The gesture lock pattern drawn by the suspect.

---

## 8. Summary of Failures, Traps & Strategy Pivots

| Step | Initial Approach | Failure / Roadblock Encountered | Tactical Pivot & Resolution |
| :--- | :--- | :--- | :--- |
| **1** | Extract archive directly | `.thumbcache.dat` was password-protected 7-Zip. | Searched other dump artifacts for keys/hashes (`gesture.key`, `mmssms.db`). |
| **2** | Test gesture patterns as password | Simple patterns (`1235789`, `Z`, `zero`) failed. | Recognized that password was multi-part; needed the formula. |
| **3** | Query SMS database via SQL | Returned normal messages; ID 40 was missing. | Carved raw database file with `strings` / hex analysis to inspect SQLite freelist cells, recovering the deleted formula. |
| **4** | Extract photo thumbnail timestamp | Thumbnail showed `03:47`. | The deleted SMS explicitly noted *"The thumbnail lies."* Extracted the true primary EXIF header (`02:14:09` $\rightarrow$ `0214`). |
| **5** | GPS coordinate parsing | Degree-minute-second strings cannot be used directly in password. | Converted `18° 31' 13.44" N` to decimal ($18.5204^\circ$) and rounded to 3 decimal places ($18.520$). |
| **6** | Transcribing audio spectrogram | Ambiguity between `o`/`0`, `e`/`3`, `l`/`1`. | Measured glyph bounding boxes and frequency spans (6000 Hz for digits vs 5300 Hz for lowercase). Validated against l33tspeak domain words (`sp3ctr0gr4m`, `fr33l1st`). |

---

## 9. Final Answer

```
HackCTF{sp3ctr0gr4m_1n_th3_fr33l1st_Z}
```
