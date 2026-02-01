# Challenge Overview: The Cicada Archives

**Category:** Forensics  
**Event:** L3m0nCTF 2025  
**Role:** Challenge Author

> 🛠️ **Author Note**  
> This challenge was authored by me for **L3m0nCTF 2025**.  
> The following explanation describes the **intended multi-layer forensic analysis path**.

<img width="433" height="706" alt="image" src="https://github.com/user-attachments/assets/7fe49c38-293f-474f-8592-37be08a34f96" />

## Intended Analysis Path

The challenge was designed to test:
- recognition of document formats as structured containers
- detection of invisible data embedded in normal-looking files
- correlation of unrelated forensic artifacts across multiple layers
- reduction of large noisy datasets to isolate anomalies
- reconstruction of a fragmented narrative from subtle clues

Direct or surface-level inspection of any single file was intentionally insufficient.

## Analysis Phase 1 — Establishing the Scope

We are given a single archive [TheCicadaArchives.tar.gz](https://github.com/rozariyomartin/L3m0nCTF2025-Writeups/blob/main/Forensics/TheCicadaArchives/TheCicadaArchives.tar.gz) containing three files:

whiteletter.docx

archive_2021.bin

evidence.zip


At first glance, everything looks ordinary. No obvious corruption, no visible clues, no readable flags.
This challenge is about looking past what’s visible, and understanding that data can be hidden inside structure, noise, and normality.

## Analysis Phase 2 — Document Container Inspection

Opening the document normally reveals nothing interesting — just plain text.
This immediately suggests the content is not meant to be read directly.

A `.docx` file is actually a ZIP archive, so we extract it:

```
unzip whiteletter.docx -d whiteletter
```

Inside, we inspect the Word XML files. The footer is a common hiding place:

`whiteletter/word/footer.xml`

<img width="1622" height="226" alt="image" src="https://github.com/user-attachments/assets/310426b0-2feb-44e6-a1f2-22f1c512f32a" />

Reading it visually still shows nothing suspicious.

## Analysis Phase 3 — Hidden Unicode Signal Extraction

Since nothing visible stands out, the next step is to look for **invisible or non-ASCII characters**.

We search for zero-width Unicode characters:

```
grep -P "[\x{200C}\x{200D}]" footer.xml
```

<img width="1895" height="247" alt="image" src="https://github.com/user-attachments/assets/17f2887e-47f5-4e85-8646-b14f7763b89f" />

Nothing visible is printed, but output exists — meaning invisible characters are present.

We extract only those characters:

```
grep -oP "[\x{200C}\x{200D}]" footer.xml > zw.txt
```

A quick hex dump confirms they are real:

```xxd zw.txt | head
```

<img width="573" height="206" alt="image" src="https://github.com/user-attachments/assets/d95229d9-059c-46a3-83a2-047d2c455b69" />

We see repeating patterns of:

- e2 80 8c → U+200C
- e2 80 8d → U+200D

## Analysis Phase 4 — Zero-Width Character Decoding

These two characters can naturally represent binary:

- U+200C → 0
- U+200D → 1

We decode them as binary bytes:

```
python3 - << 'EOF'
data = open("zw.txt", "r", encoding="utf-8").read()

bits = ""
for c in data:
    if c == '\u200c':
        bits += "0"
    elif c == '\u200d':
        bits += "1"

out = ""
for i in range(0, len(bits), 8):
    byte = bits[i:i+8]
    if len(byte) == 8:
        out += chr(int(byte, 2))

print(out)
EOF
```

Output:

```
morseindocx
```

This is clearly a password.

Brute-force attempts using common wordlists were intentionally ineffective.

## Analysis Phase 5 — Password-Protected Artifact Recovery

Using the recovered password:

```
unzip evidence.zip
```

Password:

``morseindocx``

The archive extracts several files

## Analysis Phase 6 — Network Traffic Correlation

Opening the capture in Wireshark shows heavy, realistic traffic:

- DNS
- TCP
- ICMP
- Multiple IPs and hosts

Nothing obvious stands out initially.

#### DNS Analysis

We filter DNS packets:

Among many legitimate domains, one entry stands out subtly:

``frg3.tdn01s3s1gn4l.net``

This does not look random — it looks constructed.

Extracting the fragment:

```
tdn01s3s1gn4l
```

This becomes the 3rd **fragment**.

## Analysis Phase 7 — Secondary Signal Discovery

Still in the PCAP, we inspect HTTP traffic.

We follow TCP streams (Right-click → Follow → HTTP Stream).

One HTTP request contains a custom header:

<img width="438" height="110" alt="image" src="https://github.com/user-attachments/assets/ebedd6c0-dac9-42f0-aee2-0fdcd760f65a" />

This gives us the password:

```
inspectnext
```

## Analysis Phase 8 — Image-Based Data Extraction

Using the recovered password:

```
steghide extract -sf img002.jpg -p inspectnext
```

<img width="414" height="63" alt="image" src="https://github.com/user-attachments/assets/8329284d-7902-4868-be45-5861eaa81ed8" />

This extracts:

fragment2.txt

**Contents:**

```
tt3r_1nsp3c
```

## Analysis Phase 9 — Large-Scale Log Reduction

#### 1.Initial Analysis
We are provided with a file named massive_server.log. A quick check using ls -lh reveals the file is quite large (approx. 150MB+), containing over 1 million lines.

Attempting to read the file manually using cat or less is futile because of the sheer volume of data. The logs simulate a busy server environment with various formats:

- Apache/Nginx Access Logs
- Syslog messages (kernel, sshd, cron)
- JSON structured logs
- Java Stack Traces
- Hex Dumps

Since we don't know what string to search for (like "flag" or "L3M0N"), a simple grep won't work.

#### 2. The Trap
A common first attempt is to look for unique lines using sort | uniq -u. However, running this command returns almost the entire file.

Why? Every log line contains dynamic variables:

- Timestamps: ``[14:22:01]`` vs ``[14:22:02]``
- IP Addresses: ``192.168.1.5`` vs ``10.0.0.2``
- Request IDs/UUIDs: ``trace_id: "b394a2f7..."``

To a computer, these lines are all "unique," even if they are generated by the same logging event.

#### 3. The Solution: Log Reduction
To find the needle, we don't look for the needle; we look for the haystack. We need to perform **Frequency Analysis**.

By identifying the "templates" that generate the noise, we can mathematically filter them out. If 99.9% of the file follows 5 standard patterns, the flag will be the one line that follows a pattern appearing only once.

We wrote a Python script to **normalize** the logs—replacing all variables (numbers, IPs, UUIDs, dates) with generic placeholders like ``{VAR}``.

The Solver Script (``solve.py``)

```
import re
from collections import Counter

# --- CONFIGURATION ---
LOG_FILE = "massive_server.log"  # Make sure this matches your file name

def normalize_log(line):
    """
    Aggressively strips variable data to reveal the 'skeleton' of the log.
    """
    line = line.strip()

    # 1. DETECT HEX DUMPS (The lines with | at the end)
    # If it starts with hex address and ends with ascii representation
    if re.search(r'^[0-9a-fA-F]{4,8}\s+[0-9a-fA-F]{2}', line) and "|" in line:
        return "HEX_DUMP_LINE"

    # 2. STRIP UUIDs (The long trace_id strings)
    # Pattern: 8-4-4-4-12 hex characters
    line = re.sub(r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}', '{UUID}', line)

    # 3. STRIP TIMESTAMPS & IPs
    line = re.sub(r'\d{4}-\d{2}-\d{2}', '{DATE}', line)
    line = re.sub(r'\d{2}:\d{2}:\d{2}', '{TIME}', line)
    line = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '{IP}', line)

    # 4. AGGRESSIVE: Strip any word containing a number (e.g., "User123", "0x4f", "thread-5")
    # This turns your flag hash "28h3Jkh..." into "{VAR}"
    line = re.sub(r'\b\w*\d\w*\b', '{VAR}', line)

    # 5. Clean up multiple spaces
    return " ".join(line.split())

def solve():
    print(f"Scanning {LOG_FILE} with aggressive filters...")

    skeleton_counts = Counter()
    skeleton_examples = {}

    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                clean_line = line.strip()
                if not clean_line: continue

                # Get the skeleton
                skeleton = normalize_log(clean_line)

                # Count it
                skeleton_counts[skeleton] += 1

                # Save the first example we see of this type
                if skeleton not in skeleton_examples:
                    skeleton_examples[skeleton] = clean_line

    except FileNotFoundError:
        print(f"Error: Could not find '{LOG_FILE}'. Check the filename.")
        return

    print("\n--- RESULTS: The Rarest Log Entries ---")

    # Print the bottom 5 (rarest) items
    # The flag should be the very last one printed (Count: 1)
    found_any = False
    for skeleton, count in skeleton_counts.most_common()[:-6:-1]:
        found_any = True
        print(f"[Count: {count}]")
        print(f"Skeleton: {skeleton}")
        print(f"ORIGINAL: {skeleton_examples[skeleton]}")
        print("-" * 50)

    if not found_any:
        print("No results found. Is the file empty?")

if __name__ == "__main__":
    solve()
```

#### 4.Execution & Result

Running the script produced the following output:

<img width="1402" height="408" alt="image" src="https://github.com/user-attachments/assets/5dac3662-ca43-4688-b41f-1fa822c22411" />

#### 5. The Flag
The anomaly contained the hidden message:

can you see this 28h3JkhN8IVHxjDI4R8F5R

The encoded fragment can be identified as Base62 and decoded accordingly.

```
FRAG4: s_l0gg3d}
```

## Analysis Phase 10 — Fragment Reassembly

We can get the first part of the flag on the initial analysis even using strings,

<img width="352" height="56" alt="image" src="https://github.com/user-attachments/assets/31eee171-1e31-43a5-9af9-6c97c4b26441" />

```
L3m0nCTF{wh1t3l3
```

On reconstructing it fully we get the flag.

**Flag : ``L3m0nCTF{wh1t3l3tt3r_1nsp3ctdn01s3s1gn4ls_l0gg3d}``**
