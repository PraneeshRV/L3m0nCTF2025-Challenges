from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
import secrets
flag = b"L3m0nCTF{REDACTED}"
m = bytes_to_long(flag)
key = RSA.generate(2048)
p, q = key.p, key.q
n = key.n
e = key.e
cipher = pow(m, e, n)
k0 = secrets.randbelow(1 << 26) + (1 << 26)
t = secrets.choice(range(-1000, 1001))
note = p*p + q*q - p - q + k0 * n + t
S = p + q
note_bits = note.bit_length()
hidden_bits_count = 22
mask = (1 << (note_bits - hidden_bits_count)) - 1
note_leak = note & mask
print(f"n = {n}")
print(f"e = {e}")
print(f"cipher = {long_to_bytes(cipher)}")
print(f"note_leak = {note_leak}")
print(f"note_bit_length = {note_bits}") 
print(f"hidden_bits_count = {hidden_bits_count}")
