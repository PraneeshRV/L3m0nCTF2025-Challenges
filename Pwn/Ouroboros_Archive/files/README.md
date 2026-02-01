# Ouroboros Archive - Developer Documentation

## Challenge Overview

**Name:** Ouroboros Archive  
**Type:** Zip Slip (CVE-2018-1002200)  
**Flag:** `L3m0nCTF{symb0l1c_l1nk_3sc4p3_m4st3r}`  
**Difficulty:** Hard  

## Structure

```
ouroboros_archive/
├── src/
│   └── unzipper.c          # Vulnerable ZIP unpacker
├── dist/
│   ├── unzipper            # Stripped binary
│   ├── README.md           # Challenge description
│   └── example_normal.zip  # Example ZIP file
├── solution/
│   ├── create_exploit.py   # Creates malicious ZIP
│   ├── exploit.zip         # Generated exploit
│   └── exploit.b64         # Base64 for netcat
├── docker/
│   ├── Dockerfile          # Container with SUID setup
│   ├── docker-compose.yml  # Service configuration
│   └── wrapper.sh          # Netcat handler
└── build.sh                # Build script
```

## The Vulnerability

**Flaw:** `sanitize_path()` only checks if path STARTS with "sandbox/"
- Doesn't resolve symlinks before validation
- Extraction follows symlinks!

**Exploit:**
1. ZIP entry 1: symlink `escape` → `/`
2. ZIP entry 2: file `escape/tmp/pwned`
3. Result: Writes to `/tmp/pwned` (outside sandbox!)

## Security Features

### Flag Protection
- **XOR-encoded** with dynamic key
- **Key derivation:** XOR all bytes of "OUROBOROS_KEY" magic marker at offset 0x2000
- **Calculated key:** 0x4c (76)
- **NOT visible** in `strings` output

### Exploit Verification
Binary checks THREE conditions before printing flag:
1. Symlink `sandbox/escape` exists  
2. Symlink points to `/` or `../..`
3. File `pwned` or `/tmp/pwned` exists

All must pass → Flag prints

### Binary Hardening
- Strip all symbols
- Stack canaries (`-fstack-protector-all`)
- No debug info

Creates: `dist/unzipper` (stripped, 14-16KB)


## Deploying with Docker

I git pulled this repo in the gcp instance and then used the docker file which i created to create the docker image

```bash
cd docker
docker-compose up -d
```

Service runs on port 1337

Test:
```bash
cd ../solution
cat exploit.b64 | nc localhost 1337
```

## Distribution Package

Create ZIP for contestants:
```bash
cd dist
zip ouroboros_challenge.zip unzipper README.md example_normal.zip
```

Upload to CTFd with flag: `L3m0nCTF{symb0l1c_l1nk_3sc4p3_m4st3r}`

## Checklist

- [x] Binary compiled and stripped
- [x] Flag XOR-encoded (not in strings)
- [x] Exploit verification works
- [x] Docker setup complete
- [x] Solution script works
- [x] Docker tested locally
- [x] Deployed to GCP

## Notes

- Warnings during compilation are expected (ignored return values)
- SUID bit is set in Docker container only
- Resource limits: 256MB RAM, 0.5 CPU
- Timeout: 30 seconds per connection

