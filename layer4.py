import io
import random
import sys

import click

import onion

ip_header_length = 20
udp_header_length = 8

@click.group()
def main():
    pass

@main.command()
def peel():
    inp = io.BytesIO(onion.read_payload(sys.stdin))
    read_ip_packets(inp, sys.stdout)

@main.command()
def wrap():
    out = io.BytesIO()
    for line in sys.stdin:
        write_ip_packet(out, bytes([10, 1, 1, 10]), bytes([10, 1, 1, 200]), 42069, line.encode('ascii'))
    onion.write_payload(sys.stdout, out.getvalue())

def read_ip_packets(inp, out):
    while header := inp.read(ip_header_length):
        header_length = (header[0] & 0xF) * 4
        total_length = int.from_bytes(header[2 : 4], 'big')
        from_addr = header[12 : 16]
        to_addr = header[16 : 20]
        header += inp.read(header_length - ip_header_length)
        if checksum(header) == 0 and from_addr == bytes([10, 1, 1, 10]) and to_addr == bytes([10, 1, 1, 200]):
            read_udp_packet(inp, out, from_addr, to_addr)
        else:
            inp.read(total_length - header_length)

def read_udp_packet(inp, out, from_addr, to_addr):
    header = inp.read(udp_header_length)
    to_port = int.from_bytes(header[2 : 4], 'big')
    udp_length = int.from_bytes(header[4 : 6], 'big')
    data = inp.read(udp_length - udp_header_length)
    if udp_checksum(from_addr, to_addr, header, data) == 0 and to_port == 42069:
        out.write(data.decode('ascii'))

def write_ip_packet(out, from_addr, to_addr, to_port, data):
    header = bytearray(ip_header_length)
    header[0] = (4 << 4) | (len(header) // 4) # version | ihl
    header[2 : 4] = (len(header) + udp_header_length + len(data)).to_bytes(2, 'big') # total length
    header[6] = 1 << 6 # DF flag
    header[8] = random.randrange(32, 65) # TTL
    header[9] = 17 # protocol
    header[12 : 16] = from_addr
    header[16 : 20] = to_addr
    header[10 : 12] = checksum(header).to_bytes(2, 'big')
    out.write(header)
    write_udp_packet(out, from_addr, to_addr, to_port, data)

def write_udp_packet(out, from_addr, to_addr, to_port, data):
    header = bytearray(udp_header_length)
    header[0 : 2] = random.randrange(1 << 16).to_bytes(2, 'big')
    header[2 : 4] = to_port.to_bytes(2, 'big')
    header[4 : 6] = (len(header) + len(data)).to_bytes(2, 'big')
    header[6 : 8] = udp_checksum(from_addr, to_addr, header, data).to_bytes(2, 'big')
    out.write(header)
    out.write(data)

def udp_checksum(from_addr, to_addr, header, data):
    pseudo_header = bytearray(12)
    pseudo_header[0 : 4] = from_addr
    pseudo_header[4 : 8] = to_addr
    pseudo_header[9] = 17
    pseudo_header[10 : 12] = (len(header) + len(data)).to_bytes(2, 'big')
    return checksum(pseudo_header + header + data)

def checksum(data):
    sum = 0
    for i in range(0, data, 2):
        sum += data[i] << 8
        if i + 1 < len(data):
            sum += data[i + 1]
    sum = (sum & 0xFFFF) + (sum >> 16)
    return ~sum & 0xFFFF

if __name__ == '__main__':
    main()
