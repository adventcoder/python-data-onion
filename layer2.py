import sys
import random

import click

import onion

@click.group()
def main():
    pass

@main.command()
def peel():
    inp = onion.read_payload(sys.stdin)
    sys.stdout.write(unpack(inp).decode('ascii'))

@main.command()
def wrap():
    inp = sys.stdin.read().encode('ascii')
    onion.write_payload(sys.stdout, pack(inp))

def unpack(inp):
    out = []
    n = 0
    nlen = 0
    for b in inp:
        if parity(b) == 0:
            n = (n << 7) | (b >> 1)
            nlen += 7
            if nlen == 56:
                out.append(n.to_bytes(7, 'big'))
                n = 0
                nlen = 0
    return b''.join(out)

def pack(inp):
    out = bytearray()
    for i in range(0, len(inp) - 6, 7):
        n = int.from_bytes(inp[i : i + 7], 'big')
        nlen = 56
        while nlen > 0:
            if random.randrange(4) == 0:
                bits = random.randrange(128)
                out.append((bits << 1) | (parity(bits) ^ 1))
            else:
                nlen -= 7
                bits = (n >> nlen) & 0x7F
                out.append((bits << 1) | parity(bits))
    return out

def parity(b):
    b ^= b >> 4
    b ^= b >> 2
    b ^= b >> 1
    return b & 1

if __name__ == '__main__':
    main()
