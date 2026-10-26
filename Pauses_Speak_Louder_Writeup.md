# Pauses Speak Louder — HackCTF Challenge Writeup

**Challenge:** Pauses Speak Louder  
**Category:** Forensics / Network Steganography / Covert Channels  
**Points:** 200  
**Flag:** `HackCTF{t1m1ng_15_3v3ryth1ng_gh0st_pr0t0c0l}`  

---

## 1. Executive Summary

An IDS captured approximately two minutes of network traffic (`capture.pcap`) from a compromised workstation. The challenge description states:
> "Nobody saw anything leave. The attacker used no exploit kit, no known C2, and no encryption you can spot in the wire. Recover what was exfiltrated."

Official Hint:
> "The message is in the packets. The key is in the pauses."

The exfiltration mechanism uses a two-stage covert architecture:
1. **The Key:** Encoded in the inter-packet arrival times (pauses) of DNS queries to `update.cdn-sync.net` using NRZ timing gaps (0.20s = 0, 0.55s = 1).
2. **The Message:** Transferred across 52 segmented ICMP echo request packets to internal destination `10.13.37.99`. The reassembled payload is AES-128-CBC encrypted (using the pause key) and zlib-compressed.
3. **The Steganographic Layer:** The decrypted payload is 16-bit PCM audio containing a 2D bitmap font hidden in the sample LSBs with alternating row inversion, revealing the final flag.

---

## 2. PCAP Traffic Analysis

Inspection of `capture.pcap` reveals 564 total frames across three source IPs (`10.13.37.5`, `10.13.37.6`, and `10.13.37.7`) originating from MAC `00:15:5d:29:c7:24`:
- **DNS Queries (408 packets):** Sent to internal resolver `10.13.37.53`. 129 queries from `10.13.37.5` target `update.cdn-sync.net`.
- **ICMP Echo Requests (156 packets):** 52 packets per source IP directed to `10.13.37.99`.

---

## 3. Extracting the Decryption Key from the Pauses

Analyzing the inter-query arrival times ($\Delta t = t_{i+1} - t_i$) for `10.13.37.5` queries to `update.cdn-sync.net`:
- Total queries = 129 $\rightarrow 128$ inter-packet gaps.
- Strictly bimodal distribution:
  - Short intervals ($\approx 0.20\text{ s}$): Bit `0`
  - Long intervals ($\approx 0.55\text{ s}$): Bit `1`

The 128 decoded bits form a 16-byte key:
```text
00000011 00001101 00100101 10011110 01111011 11100011 11101111 11101100
10100101 00010111 10000100 10001000 11001101 10110001 10111010 10110101
```

Hex representation:
`030d259e7be3efeca5178488cdb1bab5`

---

## 4. Reassembling and Decrypting the ICMP Packets

The 52 ICMP packets from `10.13.37.5` contain a 2-byte sequence header (`0x0000` to `0x0033`) followed by 900 bytes of data (last packet has 228 bytes), totaling 46,128 bytes:
- Bytes `0..16`: Initialization Vector (IV)
- Bytes `16..46128`: AES-128-CBC Ciphertext

Decrypting with AES-128-CBC using the extracted pause key and decompressing with `zlib` yields 46,080 bytes of decompressed PCM audio (23,040 16-bit signed samples).

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import zlib

raw_payload = b"".join(chunks[i] for i in sorted(chunks.keys()))
iv = raw_payload[:16]
ct = raw_payload[16:]
key = bytes.fromhex("030d259e7be3efeca5178488cdb1bab5")

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
decryptor = cipher.decryptor()
pt = decryptor.update(ct) + decryptor.finalize()
decompressed = zlib.decompress(pt)  # 46,080 bytes
```

---

## 5. Bitmap Font Reconstruction

Examining the LSB of the 23,040 samples reveals a binary raster image of dimensions $96 \times 240$ (or $192 \times 120$):
- Alternating rows are inverted (`arr[r, c] ^ (r % 2)`).
- Realigning the alternating rows unmasks a 14-pixel tall bitmap font reading:

```text
HackCTF{t1m1ng_15_3v3ryth1ng_gh0st_pr0t0c0l}
```

---

## 6. Final Flag

`HackCTF{t1m1ng_15_3v3ryth1ng_gh0st_pr0t0c0l}`
