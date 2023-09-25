import random
import sys

import click
import Crypto.Cipher.AES

import onion

@click.group()
def main():
    pass

@main.command()
def peel():
    inp = onion.read_payload(sys.stdin)
    kek = inp[0 : 32]
    kiv = inp[32 : 40]
    key = unwrap_key(kek, kiv, inp[40 : 80])
    iv = inp[80 : 96]
    sys.stdout.write(encrypt(key, iv, inp[96:]).decode('ascii'))

@main.command()
def wrap():
    kek = random.randbytes(32)
    kiv = random.randbytes(8)
    key = random.randbytes(32)
    iv = random.randbytes(16)
    inp = sys.stdin.read().encode('ascii')
    onion.write_payload(sys.stdout, b''.join([kek, kiv, wrap_key(kek, kiv, key), iv, encrypt(key, iv, inp)]))

def wrap_key(kek, kiv, key):
    aes = Crypto.Cipher.AES.new(kek, Crypto.Cipher.AES.MODE_ECB)
    vals = unpack(kiv + key)
    for n in range(6):
        for i in range(1, 5):
            vals[0], vals[i] = unpack(aes.encrypt(pack([vals[0], vals[i]])))
            vals[0] ^= (n * 4 + i)
    return pack(vals)

def unwrap_key(kek, kiv, wrapped_key):
    aes = Crypto.Cipher.AES.new(kek, Crypto.Cipher.AES.MODE_ECB)
    vals = unpack(wrapped_key)
    for n in reversed(range(6)):
        for i in reversed(range(1, 5)):
            vals[0] ^= (n * 4 + i)
            vals[0], vals[i] = unpack(aes.decrypt(pack([vals[0], vals[i]])))
    if pack(vals[:1]) != kiv:
        raise ValueError('kiv mismatch')
    return pack(vals[1:])

def pack(vals):
    return b''.join(val.to_bytes(8, 'big') for val in vals)

def unpack(block):
    return [int.from_bytes(block[i : i + 8], 'big') for i in range(0, len(block), 8)]

def encrypt(key, iv, inp):
    out = []
    aes = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_ECB)
    counter = int.from_bytes(iv, 'big')
    for i in range(0, len(inp), 16):
        pad = aes.encrypt(counter.to_bytes(16, 'big'))
        out.append(xor(inp[i : i + 16], pad))
        counter += 1
    return b''.join(out)

def xor(inp, pad):
    return bytes(i ^ p for i, p in zip(inp, pad))

if __name__ == '__main__':
    main()
