# Ouroboros Archive

**Category:** Binary Exploitation  
**Difficulty:** Hard  
**Points:** 400

## Description

We've discovered a mysterious archive extraction utility running on a remote server. It claims to have security measures in place to prevent path traversal attacks, but something doesn't seem right...

Can you escape the sandbox and capture the flag?

## Connection

```bash
nc challenge.l3mon.com 1337
```

## Files

- `unzipper` - The extraction utility binary (for analysis)

## Usage

1. Create a ZIP file
2. Encode it as base64: `base64 yourfile.zip`
3. Send to the netcat service
4. Receive output

Example:
```bash
base64 test.zip | nc challenge.l3mon.com 1337
```

## Author - RadKriss
---

**Flag format:** `L3m0nCTF{...}`
