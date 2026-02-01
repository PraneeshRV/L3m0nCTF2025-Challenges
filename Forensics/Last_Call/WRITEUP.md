# Challenge Overview: Mystery Call

**Category:** Forensics  
**Event:** L3m0nCTF 2025  
**Role:** Challenge Author

> 🛠️ **Author Note**  
> This challenge was authored by me for **L3m0nCTF 2025**.  
> The following explanation describes the **intended forensic analysis path**.

<img width="445" height="676" alt="image" src="https://github.com/user-attachments/assets/1ea56118-63d8-44a4-a851-3da8766684cb" />

## Intended Analysis Path

The challenge was designed to test:
- recognition of signaling methods beyond direct decoding
- understanding that DTMF symbols may act as carriers, not data
- analysis of temporal properties rather than frequency content
- multi-channel signal combination to remove decoy information

Single-channel or direct decoding approaches were intentionally misleading.

## Overview

Files given : [mystery_call.tar.gz](https://github.com/rozariyomartin/L3m0nCTF2025-Writeups/blob/main/Forensics/LastCall/mystery_call.wav)

We are given a single audio file, mystery_call.wav.

The audio contains nothing except a sequence of repetitive electronic tones.
There is no speech, no music, and no obvious audible message.

At first listen, the tones resemble telephone beeps, but decoding them directly does not reveal any readable text.

The goal is to determine **what information is hidden inside these tones**.

## Analysis Phase 1 — Initial File Inspection

We begin by checking the file type.

```
file mystery_call.wav
```

<img width="782" height="110" alt="image" src="https://github.com/user-attachments/assets/9ee78a35-93aa-476c-bb32-541458e8ac29" />

The output confirms:

- WAV audio
- Stereo
- Fixed sample rate

This is important — the file has two channels, not one.

## Analysis Phase 2 — Eliminating Direct DTMF Decoding

Since the tones resemble telephone signals, we try a standard DTMF decoder.

```
multimon-ng -a DTMF -t wav mystery_call.wav
```

<img width="1868" height="384" alt="image" src="https://github.com/user-attachments/assets/bc65c082-1dae-41da-b295-1ee9903821f6" />


This produces a long stream of same repeated digits.

However:

- The output does not resemble a flag
- The sequence is far too long
- No readable structure appears

This tells us something important:

**The decoded DTMF symbols themselves are not the message.**

## Analysis Phase 3 — Channel-Level Inspection

On opening this file in audacity we can see that both left channel and right channel doesnt resemble same  sound.

<img width="1905" height="298" alt="image" src="https://github.com/user-attachments/assets/74af7526-be26-4625-976c-0b1be6b4e486" />

So, we separate the channels.

```
sox mystery_call.wav left.wav  remix 1
```

```
sox mystery_call.wav right.wav remix 2
```

Now we have:

- left.wav
- right.wav

Each channel contains valid tones.

Running a DTMF decoder on either channel alone still does not produce meaningful text.

So:

- The message is **not** stored in a single channel
- The channels must be **used together**

## Analysis Phase 4 — Identifying the True Signal Property

When visualizing the waveform or spectrogram, one key detail stands out:

- The frequencies do not change meaningfully
- The only variation is tone duration

Each tone is either:

- **Short**
- **Long**

This strongly suggests binary encoding.

We treat:

- Short tone → 0
- Long tone → 1

## Analysis Phase 5 — Binary Extraction via Temporal Analysis

For each channel independently:

1.Convert audio to mono signal

2.Compute short-time energy

3.Detect tone “on” segments

4.Measure duration of each segment

5.Convert duration to bits

The extraction logic is implemented in a helper script

**extract.py**

```
#!/usr/bin/env python3
import numpy as np
from scipy.io import wavfile

SHORT = 0.10
LONG  = 0.22
THRESH = (SHORT + LONG) / 2
WINDOW = 256

def extract_bits(wav):
    sr, x = wavfile.read(wav)

    # mono safety
    if x.ndim > 1:
        x = x[:,0]

    x = x.astype(np.float32)
    x /= np.max(np.abs(x))

    energy = np.convolve(x*x, np.ones(WINDOW)/WINDOW, mode="same")
    on = energy > (0.2 * energy.max())

    bits = []
    i = 0
    while i < len(on):
        if on[i]:
            j = i
            while j < len(on) and on[j]:
                j += 1
            dur = (j - i) / sr
            bits.append('1' if dur > THRESH else '0')
            i = j
        else:
            i += 1

    return ''.join(bits)

left  = extract_bits("left.wav")
right = extract_bits("right.wav")
print("[LEFT bits]")
print(left)
print("Length:", len(left))

print("\n[RIGHT bits]")
print(right)
print("Length:", len(right))


n = min(len(left), len(right))
xor_bits = ''.join(str(int(left[i]) ^ int(right[i])) for i in range(n))

out = []
for i in range(0, len(xor_bits), 8):
    byte = xor_bits[i:i+8]
    if len(byte) == 8:
        out.append(chr(int(byte, 2)))

print("".join(out))
```

Running this script produces two binary streams:

This produces two binary strings:

<img width="1893" height="179" alt="image" src="https://github.com/user-attachments/assets/b96ed226-4dba-4bf8-b40b-5a2cc6e48512" />

Neither stream alone forms valid ASCII.

## Analysis Phase 6 — Channel Combination via XOR

Because both channels are synchronized and neither decodes meaningfully by itself, the next step is to **combine them.**

The intended operation is a **bitwise XOR** between corresponding bits:

`FINAL_BIT = LEFT_BIT ⊕ RIGHT_BIT`

This operation removes the decoy structure present in each channel individually and reconstructs the original data.

The XOR and decoding process is handled by the that code even:

## Final Output

The resulting binary stream is grouped into 8-bit chunks and converted to ASCII.

This yields the final message:

`L3m0nCTF{DTMF_X0R_5T3R30_1S_N0T_4UD10_3V3RY0N3}`
