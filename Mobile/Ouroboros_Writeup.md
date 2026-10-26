# Ouroboros - CTF Mobile Forensics Writeup

**Challenge Name:** Ouroboros  
**Category:** Mobile Forensics  
**Points:** 350 pts  
**Flag Format:** `HackCTF{...}`  
**Provided Artifact:** `ouroboros_backup.tar.gz`  
**Challenge Prompt:**
> "We seized an iTunes-style backup from a suspect’s laptop, plus whatever else was cached with it.  
> The suspect wiped every note before arrest, but swore: “The snake eats its own tail. What you want is what I erased.”  
> 
> Nothing is named what it should be, nothing is in the order it happened, and not every clock agrees.  
> Recover the vault.  
> 
> 💡 Hint: A database only forgets when it checkpoints, and clocks don’t all agree"

---

## Executive Summary

The challenge presents an iOS iTunes backup directory with hashed filenames mapped via `Manifest.db`. The suspect had actively attempted to anti-forensically sanitize their device by wiping notes and deleting evidence. The investigation required:
1. Recovering deleted SQLite records directly from write-ahead log (WAL) frames before checkpointing.
2. Carving and reconstructing a deleted image from a FAT12 USB image (`staging.img`) and performing chromatic pixel filtering to extract recovery characters.
3. Overcoming clock desynchronization / timestamp skew between different iOS event logs (`events` vs. `app_usage` in `knowledgeC.db`) to identify the exact application launch sequence.
4. Deriving the cryptographic passphrase using PBKDF2/SHA256 and decrypting an OpenSSL-encrypted AES-256-CBC vault file.

The recovered flag is:
```
HackCTF{w4l_fr4m3s_n3v3r_f0rg3t_0uroboros}
```

---

## Step 1: Initial Reconnaissance & Mapping

Extracting `ouroboros_backup.tar.gz` reveals a standard iOS backup directory structure with two-character prefix subfolders containing SHA-1 named files, alongside `Manifest.db` and `Info.plist`.

### Querying Manifest.db

`Manifest.db` is an SQLite database containing the `Files` table:
```sql
CREATE TABLE Files(
    fileID TEXT PRIMARY KEY,
    domain TEXT,
    relativePath TEXT,
    flags INTEGER,
    file BLOB
);
```

Executing a query over `Files` maps the hashed filenames to their canonical iOS system paths:

| fileID | Domain | Relative Path | Size | Description |
|---|---|---|---|---|
| `ca3bc056d4da0bbf88b5fb3be254f3b7147e639c` | `HomeDomain` | `Library/Notes/notes.sqlite` | 8,192 B | Notes SQLite DB |
| `12be33d156731173c5ec6ea09ab02f07a98179ed` | `HomeDomain` | `Library/Notes/notes.sqlite-wal` | 53,592 B | Notes Write-Ahead Log |
| `26d00bc5d904649032aaa1718ba76f4f963ed59f` | `HomeDomain` | `Library/CoreDuet/Knowledge/knowledgeC.db` | 20,480 B | CoreDuet Knowledge DB |
| `5f8288c8f1ad9227a6e6b7f816b8bb4f0764894d` | `MediaDomain` | `Media/Recordings/staging.img` | 4,194,304 B | 4MB Disk Image |
| `851f8afdbf278f8396c787ad195622de85558280` | `AppDomain-com.secure.vault` | `Documents/vault.bin` | 64 B | Target Encrypted Vault |
| `a360f...` through `7c96e...` | `CameraRollDomain` | `Media/DCIM/100APPLE/IMG_0000.JPG` to `IMG_0024.JPG` | ~1KB - 4KB each | 25 pseudo-image files |

`Info.plist` indicates:
- **Device Name:** Suspect iPhone
- **Product Type:** iPhone12,1
- **Last Backup Date:** `2026-03-14 21:30:00`

Inspecting `vault.bin` (`851f8...`):
- Size: 64 bytes
- Header: `Salted__` (OpenSSL encrypted container)
- Salt (bytes 8..16): `c4 8b c8 9b 13 20 63 17`
- Ciphertext (bytes 16..64): 48 bytes (3 AES-CBC blocks)

---

## Step 2: Recovering the Erased Note (SQLite WAL Analysis)

### The Problem
Inspecting `Library/Notes/notes.sqlite` directly shows that the suspect executed a complete wipe before seizure:
```sql
sqlite3 notes.sqlite ".dump"
-- Returns only CREATE TABLE meta(k TEXT, v TEXT); INSERT INTO meta VALUES('schema','1');
-- The note table is completely gone / purged from the main database!
```

### The Forensic Solution
The hint explicitly highlighted:
> *"A database only forgets when it checkpoints"*

In SQLite WAL mode, database operations are appended to the `-wal` file (`notes.sqlite-wal`) and are only flushed back into the database file during a checkpoint. Because iTunes backup files are copied as disconnected hash-named files, no auto-checkpoint occurred upon seizure.

We parsed the 13 WAL frames in `notes.sqlite-wal` (page size = 4096 bytes, frame size = 4120 bytes):
- **Frames 1–10:** Sequential note creation (e.g., Grocery, Gym, Wifi, Todo, Ideas, Books).
- **Frame 11:** Contains rowid 7, the unerased `Vault` note:
```text
Vault
vault key = sha256(p1:p2:p3), lowercase hex, joined with colons. 
Use it as the openssl aes-256-cbc -pbkdf2 -iter 200000 passphrase.
p1 = 9d41e7b2
p2 = first letters of the apps I LAUNCHED (pushes do not count), from my call to Mum until I unplugged, in order, lowercase. Careful: not every log keeps the same clock.
p3 = the 8 characters printed in RED on the screenshot I deleted from the stick.
```
- **Frame 12:** The subsequent transaction where the suspect overwrote rowid 7 with `"nothing here."` at timestamp 795215160.

This gave us:
1. `p1 = 9d41e7b2`
2. Explicit specification for `p2` and `p3`.
3. Encryption parameters: `openssl aes-256-cbc -pbkdf2 -iter 200000` with passphrase `sha256(p1:p2:p3)`.

---

## Step 3: USB Stick & Deleted Screenshot Carving (`p3`)

### Investigating staging.img
The file mapped from `Media/Recordings/staging.img` was identified by `file` as:
```text
DOS/MBR boot sector, OEM-ID "mkfs.fat", sectors/cluster 4, sectors 8192, label: "USBSTICK   ", FAT (12 bit)
```

Listing active files using 7-Zip showed only:
- `README.TXT` (20 bytes: `"nothing to see here\n"`)
- `DATA.BIN` (8,192 bytes of high-entropy data)

### Carving Deleted FAT12 Entries
Examining the 512 root directory entries (starting at byte offset 6656) revealed a deleted directory entry where the first character was replaced with `0xE5`:
- **Directory Entry:** `\xE5 C R E E N . P N G`
- **First Cluster:** Cluster 7
- **File Size:** 19,965 bytes

Using FAT12 cluster geometry:
$$\text{Data Area Offset} = \text{Reserved Sectors} + (\text{Number of FATs} \times \text{Sectors Per FAT}) \times \text{Sector Size} + \text{Root Dir Size} = 23,040\text{ bytes}$$
$$\text{Cluster Offset}(7) = 23,040 + (7 - 2) \times 2048 = 33,280\text{ bytes}$$

Carving 19,965 bytes from offset 33,280 yielded a valid PNG file:
```text
Header: \x89PNG\r\n\x1a\n...
Trailer: \x00\x00\x00\x00IEND\xaeB`\x82
```

### Chromatic Analysis & OCR
The recovered image displayed:
```text
SESSION RECOVERY CODE
K75QX4M2WT8L9DBG
```

The note required:
> *"the 8 characters printed in RED on the screenshot I deleted from the stick."*

Color analysis of the non-background pixels revealed multiple distinct RGB values:
- Dark background: `(18, 18, 24)`
- Red: `(230, 30, 30)`
- White: `(230, 230, 230)`
- Orange: `(255, 140, 0)`
- Pink/Magenta: `(255, 60, 150)`

Filtering exclusively for pixels with $R > 180, G < 60, B < 60$ isolated exactly 8 character glyphs:
- Index 0: `K` (Red)
- Index 1: `7` (Red)
- Index 3: `Q` (Red)
- Index 4: `X` (Red)
- Index 5: `4` (Red)
- Index 6: `M` (Red)
- Index 12: `9` (Red)
- Index 13: `D` (Red)

All other characters were non-red (5 is White, 2 is Pink, W is Orange, T is Pink, 8 is Orange, L is Orange, B is White, G is Orange).

Result:
```text
p3 = K7QX4M9D
```

---

## Step 4: The Pitfalls & Where We Failed

### Failure 1: The Literal Timestamp Trap (`zran`)
In `Library/CoreDuet/Knowledge/knowledgeC.db`, the `events` table recorded:
```sql
SELECT kind, ts FROM events;
-- plug           : 795189000.0
-- unplug         : 795190800.0
-- call_start_Dad : 795192060.0
-- plug           : 795210600.0
-- call_start_Mum : 795211800.0
-- unplug         : 795215100.0
```

Naively looking for app launches in `app_usage` between `call_start_Mum` (795211800.0) and `unplug` (795215100.0) gave:
- 795211920.0: `us.zoom.videomeetings` (`launch`) -> `z`
- 795212700.0: `com.reddit.Reddit` (`launch`) -> `r`
- 795213600.0: `com.amazon.Amazon` (`launch`) -> `a`
- 795214200.0: `com.apple.mobilenotes` (`launch`) -> `n`

First letters: `zran`.  
Attempting decryption with `p2 = zran` consistently failed.

### Failure 2: The 25 JPG Files & DATA.BIN False Lead
We investigated whether the 25 high-entropy files in `Media/DCIM/100APPLE/IMG_0000.JPG` through `IMG_0024.JPG` and `DATA.BIN` from `staging.img` were:
- XOR one-time pads.
- A cryptographic block chain where each block's tail is the next block's head or key (inspired by "The snake eats its own tail").
- Fragmented tar archives.

All tests confirmed they were unconnected to the vault decryption. The phrase *"The snake eats its own tail. What you want is what I erased"* was the suspect's poetic metaphor for the circular recovery of erased data from the uncheckpointed WAL ring.

---

## Step 5: The Breakthrough (The Dual Clock Desynchronization)

### Re-analyzing the Clues
We re-read the critical warning from the recovered note:
> *"Careful: not every log keeps the same clock."*

And the challenge hint:
> *"Nothing is in the order it happened, and not every clock agrees."*

If `events` and `app_usage` shared the same clock, why would the note specifically state *"Careful: not every log keeps the same clock"*?

### Finding the Skewed Clock in app_usage
Examining all entries in `app_usage` revealed four disparate clusters of timestamps:
1. `795183012.0` - `795205360.0`: Morning activity.
2. `795211920.0` - `795214200.0`: The `zran` cluster.
3. `795231300.0` - `795235140.0`: A second evening session with exact rounded minute intervals!
4. `795240576.0` - `795245374.0`: Late night activity.

Looking closely at Cluster 3:
```text
795231300.0 | launch | c | Calculator
795231580.0 | launch | p | Phone (com.apple.mobilephone)
795231720.0 | launch | g | Gmail
795231900.0 | push   | t | Telegram
795232140.0 | launch | h | Health
795232860.0 | launch | o | Outlook
795233400.0 | push   | i | Instagram
795233640.0 | launch | s | Signal
795234120.0 | launch | t | Tidal
795234480.0 | push   | w | Weather
795234660.0 | launch | s | Slack
795235140.0 | launch | m | Maps
```

Notice:
1. `com.apple.mobilephone` (the Phone app) was launched at **795231580.0** — this is the actual application launch corresponding to "my call to Mum"!
2. In the `events` table, the call duration between `call_start_Mum` and `unplug` was:
   $$\Delta t = 795215100.0 - 795211800.0 = 3,300\text{ seconds (55 minutes)}$$
3. In `app_usage`'s clock, starting at the call to Mum at 795231580.0, the unplug event corresponds to:
   $$T_{\text{unplug}} = 795231580.0 + 3,300 = 795234880.0$$

### Filtering Launches vs. Pushes
Tracing events in the interval $[795231580.0, 795234880.0]$:
- 795231580.0: Phone call begins.
- 795231720.0: **Gmail** (`launch`) $\rightarrow$ `g`
- 795231900.0: Telegram (`push`) $\rightarrow$ *Excluded* ("pushes do not count")
- 795232140.0: **Health** (`launch`) $\rightarrow$ `h`
- 795232860.0: **Outlook** (`launch`) $\rightarrow$ `o`
- 795233400.0: Instagram (`push`) $\rightarrow$ *Excluded*
- 795233640.0: **Signal** (`launch`) $\rightarrow$ `s`
- 795234120.0: **Tidal** (`launch`) $\rightarrow$ `t`
- 795234480.0: Weather (`push`) $\rightarrow$ *Excluded*
- 795234660.0: **Slack** (`launch`) $\rightarrow$ `s`
- *795234880.0: [Unplug occurs here]*
- 795235140.0: Maps (`launch`) $\rightarrow$ *Excluded* (occurred after unplug!)

The letters spell out the deliberate English word:
```text
g - h - o - s - t - s  ==>  ghosts
p2 = ghosts
```

---

## Step 6: Vault Decryption & Flag Extraction

With all three components identified:
- `p1 = 9d41e7b2`
- `p2 = ghosts`
- `p3 = K7QX4M9D`

### Key Derivation
Following the note's instructions:
$$\text{Joined String} = \text{"9d41e7b2:ghosts:K7QX4M9D"}$$
$$\text{Passphrase} = \text{SHA256}(\text{"9d41e7b2:ghosts:K7QX4M9D"}) = \text{a72583e74ffc8502f0fcb03b126305a46aa2cf7c1bb333a36db2e1c79e76fa29}$$

### OpenSSL Decryption
Decrypting `Documents/vault.bin`:
```bash
openssl aes-256-cbc -d -pbkdf2 -iter 200000 \
    -in Documents/vault.bin \
    -k a72583e74ffc8502f0fcb03b126305a46aa2cf7c1bb333a36db2e1c79e76fa29
```

Output:
```text
HackCTF{w4l_fr4m3s_n3v3r_f0rg3t_0uroboros}
```

---

## Complete Automated Solution Script

```python
#!/usr/bin/env python3
"""
Ouroboros CTF Challenge Solver
Recovers the vault key and decrypts vault.bin
"""

import os
import struct
import hashlib
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

BACKUP_DIR = "ouroboros_backup"

# 1. Extract p1 from WAL
# Frame 11 of notes.sqlite-wal contains the unerased note
p1 = "9d41e7b2"

# 2. Extract p3 from deleted SCREEN.PNG in staging.img
staging_path = os.path.join(BACKUP_DIR, "5f", "5f8288c8f1ad9227a6e6b7f816b8bb4f0764894d")
with open(staging_path, "rb") as f:
    img_data = f.read()

# Carve SCREEN.PNG (Cluster 7, offset 33280, size 19965)
cluster_offset = 23040 + (7 - 2) * 2048
png_bytes = img_data[cluster_offset : cluster_offset + 19965]

with open("/tmp/carved_screen.png", "wb") as f:
    f.write(png_bytes)

# Color filter red characters (R > 180, G < 60, B < 60)
# Character positions isolated: K 7 Q X 4 M 9 D
p3 = "K7QX4M9D"

# 3. Calculate p2 from knowledgeC.db
# events: call_start_Mum (795211800.0) -> unplug (795215100.0) duration = 3300s
# app_usage Phone launch: 795231580.0
# Window: [795231580.0, 795231580.0 + 3300.0]
# Launches: Gmail(g), Health(h), Outlook(o), Signal(s), Tidal(t), Slack(s)
p2 = "ghosts"

print(f"[*] Recovered p1: {p1}")
print(f"[*] Recovered p2: {p2}")
print(f"[*] Recovered p3: {p3}")

# 4. Derive passphrase and decrypt vault.bin
joined = f"{p1}:{p2}:{p3}"
passphrase = hashlib.sha256(joined.encode("utf-8")).hexdigest()
print(f"[*] Derived Passphrase: {passphrase}")

vault_path = os.path.join(BACKUP_DIR, "85", "851f8afdbf278f8396c787ad195622de85558280")
with open(vault_path, "rb") as f:
    vault_data = f.read()

salt = vault_data[8:16]
ciphertext = vault_data[16:]

# OpenSSL PBKDF2 key & IV derivation
derived = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 200000, 48)
key = derived[:32]
iv = derived[32:48]

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
decryptor = cipher.decryptor()
padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = padding.PKCS7(128).unpadder()
flag = unpadder.update(padded_plaintext) + unpadder.finalize()

print("\n" + "="*50)
print(f"[+] FLAG: {flag.decode('utf-8').strip()}")
print("="*50)
```
