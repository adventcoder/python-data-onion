import random
import sys

import click

import onion

@click.group()
def main():
    pass

@main.command()
def peel():
    inp = onion.read_payload(sys.stdin)
    key = find_key(inp)
    sys.stdout.write(xor(inp, key).decode('ascii'))

@main.command()
def wrap():
    inp = sys.stdin.read().encode('ascii')
    key = random.randbytes(32)
    onion.write_payload(sys.stdout, xor(inp, key))

def find_key(inp):
    known = '==[ Payload ]===============================================\n\n<~'.encode('ascii')
    for i in range(len(inp) - 63):
        key = xor(inp[i : i + 32], known[0 : 32])
        if xor(inp[i + 32 : i + 64], key) == known[32 : 64]:
            return rotate(key, -i)

def rotate(arr, n):
    n %= len(arr)
    return arr[n:] + arr[:n]

def xor(inp, key):
    return bytes(inp[i] ^ key[i % len(key)] for i in range(len(inp)))

if __name__ == '__main__':
    main()
