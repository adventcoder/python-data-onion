import sys

import click

import onion

@click.group()
def main():
    pass

@main.command()
def peel():
    bs = onion.read_payload(sys.stdin)
    bs = bytes(ror(flip(b), 1) for b in bs)
    sys.stdout.write(bs.decode('ascii'))

@main.command()
def wrap():
    bs = sys.stdin.read().encode('ascii')
    bs = bytes(flip(ror(b, 7)) for b in bs)
    onion.write_payload(sys.stdout, bs)

def flip(b):
    return b ^ 0b01010101

def ror(b, n):
    return ((b >> n) | (b << (8 - n))) & 0xFF

if __name__ == '__main__':
    main()
