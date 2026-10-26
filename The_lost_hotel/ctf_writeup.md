# CTF Challenge Writeup: Hotel Room OSINT
**Challenge Name:** hotel_room.mp4  
**Category:** OSINT / Forensics  
**Flag Format:** `HackCTF{*******_*********_******_****}` (7_9_6_4 letters, all lowercase)  
**Flag:** `HackCTF{novotel_singapore_clarke_quay}`

---

## Challenge Description

> A journey captured on camera holds more than just memories.  
> Look closely, connect the scattered clues, and uncover a place tied to the past.

We were given:
- An uploaded video file: `hotel_room.mp4`
- A Google Drive link: `https://drive.google.com/drive/folders/1T1kMml9i7T0HH2vbXC8YDSkRFzvgt-Rh?usp=sharing`
- Flag format: `HackCTF{*******_*********_******_****}` — 4 words of lengths 7, 9, 6, 4

---

## Step 1 — Try the Google Drive Link First

**Approach:** Before touching the video, I tried the easier path: fetch the Google Drive folder to see if there were any additional files, images, or hints inside.

**Command / Action:**
```
web_fetch https://drive.google.com/drive/folders/1T1kMml9i7T0HH2vbXC8YDSkRFzvgt-Rh
```

**Result:** The response returned only the page's HTML metadata:
```
title: Chall - Google Drive
```
No file listings, no contents. The folder required authentication to browse. This was a dead end for external access.

**Conclusion:** Google Drive folder was inaccessible without being logged in. Moved on to the video file itself.

---

## Step 2 — Video Metadata Inspection with ffprobe

**Approach:** The first instinct with any media file in a forensics/OSINT CTF is to check the **file metadata**. Cameras and phones often embed GPS coordinates, device info, timestamps, and other EXIF-like data directly into video files. If the hotel location was embedded in the metadata, this would be the fastest solve.

**Command:**
```bash
ffprobe -hide_banner -show_format -show_streams hotel_room.mp4
```

**Output (key fields):**
```
major_brand     : isom
minor_version   : 512
compatible_brands: isomiso2avc1mp41
encoder         : Lavf58.29.100
Duration: 00:00:47.55
Video: h264 (High), yuv420p, 1920x1080, 4858 kb/s, 29.97 fps
Audio: aac (LC), 48000 Hz, stereo, 295 kb/s
```

**Result:** No GPS coordinates, no location tags, no `©xyz` atom, no custom metadata fields. The video was encoded with `Lavf58.29.100` (FFmpeg's libavformat), which strips most camera metadata. The file is a clean re-encode.

**Conclusion:** Metadata approach failed. No location data was embedded.

---

## Step 3 — Raw String Extraction from Binary

**Approach:** Even when structured metadata is absent, sometimes strings are embedded directly in the binary data of a file — URLs, coordinates, comments, hidden flags, filenames, or ASCII-art clues. I used `strings` to extract all human-readable text of 8+ characters from the raw binary.

**Command:**
```bash
strings -n 8 hotel_room.mp4 | grep -iE "gps|location|hackctf|flag|\+[0-9]{2}\.[0-9]+"
```

**Output:**
```
gPs4?Hm0
```

**Result:** Only one quasi-match — `gPs4?Hm0` — which is clearly not a GPS coordinate or flag, just a coincidental character sequence in the binary stream.

I also ran a broader `strings` dump without filters to scan for anything interesting — no URLs, no coordinates, no flag-like strings appeared.

**Conclusion:** No hidden data in the raw binary. The challenge is purely visual/OSINT-based. The clue is in what the video *shows*, not what it *encodes*.

---

## Step 4 — Frame Extraction

**Approach:** Since the video is ~47 seconds long at ~30 fps (~1,425 frames total), viewing it frame-by-frame manually would be tedious. Instead, I used `ffmpeg` to extract one frame every 3 seconds at a reduced resolution, giving a representative sample of 16 key frames to analyse.

**Command:**
```bash
ffmpeg -i hotel_room.mp4 -vf "fps=1/3,scale=960:-1" frames/f_%03d.jpg
```

**Result:** 16 JPEG frames extracted:
```
f_001.jpg  f_002.jpg  f_003.jpg  f_004.jpg
f_005.jpg  f_006.jpg  f_007.jpg  f_008.jpg
f_009.jpg  f_010.jpg  f_011.jpg  f_012.jpg
f_013.jpg  f_014.jpg  f_015.jpg  f_016.jpg
```

**Why 1/3 fps?** The video is a slow pan from a hotel room window. Extracting every 3 seconds gives enough coverage without redundancy. The scale reduction to 960px wide speeds up processing while keeping text readable.

---

## Step 5 — Building Contact Sheets for Visual Analysis

**Approach:** Instead of viewing 16 separate images one by one, I assembled them into 4 contact sheets (4 frames per sheet, arranged 2×2). This gave an immediate overview of the entire video's visual content.

**Code:**
```python
from PIL import Image
import glob

fs = sorted(glob.glob('f_*.jpg'))
for k in range(0, len(fs), 4):
    ims = [Image.open(f).resize((640, 360)) for f in fs[k:k+4]]
    W = Image.new('RGB', (1280, 720))
    for i, im in enumerate(ims):
        W.paste(im, ((i % 2) * 640, (i // 2) * 360))
    W.save(f'sheet_{k//4}.jpg')
```

**Result:** 4 contact sheets produced — `sheet_0.jpg` through `sheet_3.jpg`.

---

## Step 6 — Visual Analysis of Contact Sheets

This is the core of the challenge. I examined each sheet carefully for **text, landmarks, and architectural features**.

---

### Sheet 0 (Frames 1–4): Establishing the Scene

**What I saw:**
- A **high aerial/elevated perspective** looking down over a city riverfront
- **Colourful low-rise shophouses** in pastel shades (pink, green, yellow, teal) — distinctive Southeast Asian colonial architecture
- **White tent-like canopies** with a geodesic/tensile structure, arranged in a grid — a very distinctive roof
- A wide city skyline in the background with modern glass skyscrapers
- A **Ferris wheel silhouette** visible far left in the background
- **Marina Bay Sands** (the iconic 3-tower hotel with a rooftop sky park) visible in the background

**First deduction:** This is almost certainly **Singapore**. The combination of Marina Bay Sands, the Singapore Flyer (Ferris wheel), the colonial shophouses, and the tensile-canopy structure over what appears to be a waterfront dining/entertainment precinct is unmistakable.

The geodesic white canopies are the **Clarke Quay entertainment complex** roof — one of Singapore's most recognisable architectural features.

---

### Sheet 1 (Frames 5–8): Signage Confirmed

**What I saw:**
- A person's hand gripping a **balcony railing** — confirming the footage is shot from a hotel room balcony or high window, not a drone
- The **Singapore River** below, with traditional **bumboats** (flat-bottomed wooden boats) moored along the quayside
- **"RIVERSIDE POINT"** — a large green sign on a shopping mall clearly visible across the river
- More Clarke Quay canopy roof in the foreground

**Key deduction:** "Riverside Point" is a shopping mall at 30 Merchant Road, directly across the Singapore River from Clarke Quay. Its sign is clearly legible in the frame.

The hand on the railing proves this is a **hotel room** view, not a rooftop or drone shot. The angle and height suggest a mid-to-high floor of a building right at or above Clarke Quay.

---

### Sheet 2 (Frames 9–12): Second Signage Confirmation + MBS Close-up

**What I saw:**
- **"Clarke Quay Central"** — orange lettering on a large building facade, very clearly readable
- More of the tensile canopy roof structure below, now seen from above
- **Marina Bay Sands** towers seen more clearly — the three towers and rooftop SkyPark are unmistakable
- The Clarke Quay colourful shophouses visible between buildings

**Key deduction:** Clarke Quay Central is a mall at 6 Eu Tong Sen Street, directly beside Clarke Quay MRT station. Seeing both "Riverside Point" AND "Clarke Quay Central" signs eliminates any remaining doubt about the location — we are definitely looking at **Clarke Quay, Singapore**.

---

### Sheet 3 (Frames 13–16): Landmarks + "The Past"

**What I saw:**
- **Fort Canning Hill** — the large, heavily forested green hill rising above the surrounding buildings
- **Singapore Flyer** (the giant Ferris wheel) in the background, and beside it, the **Mandarin Oriental** hotel sign clearly readable
- **Victoria Concert Hall** clock tower (colonial-era landmark, white dome and tower) visible near the waterfront
- A full panoramic view stretching from Clarke Quay to the Marina Bay area
- The Clarke Quay river promenade and bumboats again from a different angle

**Key deduction re: "the past":** The challenge says *"uncover a place tied to the past."* Fort Canning Hill is Singapore's most historically significant landmark:
- It was the seat of the **Malay Sultanate** in the 14th century
- It served as **Government Hill** during British colonial rule
- It was the site of the **British command bunker** (now the Battle Box museum) during WWII
- Singapore's founding figure **Stamford Raffles** built his bungalow there

The hotel overlooks both Clarke Quay AND Fort Canning Hill — the prompt's "tied to the past" is pointing directly at Fort Canning.

---

## Step 7 — Identifying the Specific Hotel

**Approach:** I now knew:
1. The video is shot from a **hotel room balcony/window**
2. The hotel overlooks **Clarke Quay** directly below
3. The view encompasses **Fort Canning Hill**, **Riverside Point**, **Clarke Quay Central**, **Marina Bay Sands**, and the **Singapore Flyer**
4. The camera is at a **significant height** (mid-to-high floor) looking steeply downward onto the white canopy roof

**Process of elimination — hotels near Clarke Quay:**

| Hotel | Location | Overlooks Clarke Quay? |
|---|---|---|
| **Novotel Singapore Clarke Quay** | 177A River Valley Rd | ✅ Yes — directly above it |
| Hotel G Singapore | 50 Eu Tong Sen St | Partial view |
| Swissôtel The Stamford | 2 Stamford Rd | Too far (Raffles City) |
| Fullerton Hotel | 1 Fullerton Square | Wrong side of river |
| Marina Bay Sands | 10 Bayfront Ave | Too far east |

The **Novotel Singapore Clarke Quay** sits at 177A River Valley Road, **built right on top of and adjacent to the Clarke Quay complex itself**. Rooms on the upper floors look directly down onto the distinctive white tensile canopy roof — exactly matching what the video shows.

The steep downward angle onto the canopy roof, combined with the visible balcony railing, is consistent with a room on roughly floors 10–20 of the Novotel.

---

## Step 8 — Flag Format Verification

The flag format `HackCTF{*******_*********_******_****}` breaks down as:

```
Word 1: ******* = 7 letters
Word 2: ********* = 9 letters
Word 3: ****** = 6 letters
Word 4: **** = 4 letters
```

Checking the candidate answer:

```
n-o-v-o-t-e-l     = 7 letters ✅
s-i-n-g-a-p-o-r-e = 9 letters ✅
c-l-a-r-k-e       = 6 letters ✅
q-u-a-y           = 4 letters ✅
```

**Perfect match across all four words.**

---

## Final Answer

```
HackCTF{novotel_singapore_clarke_quay}
```

---

## Summary of What Worked vs What Didn't

| Approach | Outcome |
|---|---|
| Fetch Google Drive folder | ❌ Required auth — inaccessible |
| `ffprobe` metadata inspection | ❌ No GPS or location data — clean re-encode |
| `strings` binary extraction | ❌ No hidden flag or coordinates |
| Frame extraction + visual OSINT | ✅ **Success** |

---

## Key OSINT Indicators — Quick Reference

| Visual Clue | What It Tells You |
|---|---|
| White geodesic tensile canopy roof | Clarke Quay entertainment complex, Singapore |
| Pastel colonial shophouses | Clarke Quay riverfront |
| "RIVERSIDE POINT" green sign | Riverside Point mall — confirmed Clarke Quay |
| "Clarke Quay Central" orange sign | Double-confirmed Clarke Quay |
| 3-tower hotel with rooftop skypark | Marina Bay Sands — confirmed Singapore |
| Large Ferris wheel | Singapore Flyer |
| "MANDARIN ORIENTAL" hotel sign | Marina Bay area |
| Victoria Concert Hall clock tower | Colonial Singapore waterfront |
| Dense forested hill | Fort Canning Hill — the "tied to the past" hint |
| Bumboats on the river | Singapore River |
| Balcony railing + steep downward angle | High-floor hotel room overlooking the complex |
| All clues converge | **Novotel Singapore Clarke Quay** |

---

## Tools Used

- `ffprobe` — video metadata inspection
- `ffmpeg` — frame extraction
- `strings` — binary string extraction
- `Python / Pillow` — contact sheet assembly
- `web_fetch` — Google Drive access attempt
- Manual visual OSINT — landmark/signage recognition
