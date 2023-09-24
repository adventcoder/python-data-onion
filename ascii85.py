def decode(text):
    out = []
    i = 0
    while i < len(text):
        if text[i] == 'z':
            out.append((0).to_bytes(4, 'big'))
            i += 1
        else:
            n = from_ascii85(text[i : i + 5])
            pad = i + 5 - len(text)
            if pad > 0:
                p = 85**pad
                out.append((n*p + p - 1).to_bytes(4, 'big')[:-pad])
            else:
                out.append(n.to_bytes(4, 'big'))
            i += 5
    return b''.join(out)

def encode(data):
    out = []
    for i in range(0, len(data), 4):
        n = int.from_bytes(data[i : i + 4], 'big')
        pad = i + 4 - len(data)
        if pad > 0:
            out.append(to_ascii85(n << (pad * 8), 5)[:-pad])
        else:
            out.append(to_ascii85(n, 5))
    return ''.join(out)

def from_ascii85(text):
    n = 0
    for c in text:
        d = ord(c) - ord('!')
        if not 0 <= d < 85:
            raise ValueError('invalid ascii85: ' + repr(text))
        n = n * 85 + d
    return n

def to_ascii85(n, width):
    cs = []
    while len(cs) < width:
        cs.append(chr(ord('!') + n % 85))
        n //= 85
    cs.reverse()
    return ''.join(cs)
