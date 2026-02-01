#!/usr/bin/env sage
from Crypto.Util.number import *
from flag import flag
import random
def encrypt(msg, nbit):
    m = bytes_to_long(msg)
    p = getPrime(nbit)
    assert m < p
    e = randint(1, p - 1)
    while gcd(e, p-1) != 1:
        e = randint(1, p - 1)
    t = randint(5, nbit // 2)
    C = [randint(0, p - 1) for _ in range(t)] 
    ct_index = randint(0, t - 1)
    noise_range = 2**14
    noise = randint(0, noise_range)
    C[ct_index] = (pow(m, e, p) + noise) % p
    R.<x> = GF(p)[]
    f = sum(C[i] * x^(t - 1 - i) for i in range(t))
    xs = [randint(1, p - 1) for _ in range(t)]
    PT = [(a, f(a)) for a in xs]
    return e, p, PT, noise_range
nbit = 512
print("enc =", encrypt(flag, nbit))
