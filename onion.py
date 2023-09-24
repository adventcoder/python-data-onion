import re

import ascii85

def read_payload(inp):
    return ascii85.decode(re.sub(r'\s+', '', read_between(inp, '<~', '~>')))

def read_between(inp, start, end):
    chunks = None
    for line in inp:
        if chunks is None:
            if start in line:
                chunk = line.split(start, 2)[1]
                if end in chunk:
                    return chunk.split(end, 2)[0]
                else:
                    chunks = [chunk]
        else:
            if end in line:
                chunks.append(line.split(end, 2)[0])
                return ''.join(chunks)
            else:
                chunks.append(line)
    return None

def write_payload(out, data):
    out.write('==[ Payload ]===============================================\n')
    out.write('\n')
    write_lines(out, '<~' + ascii85.encode(data) + '~>')
    out.write('\n')

def write_lines(out, text, width = 60):
    for i in range(0, len(text), width):
        out.write(text[i : i + width] + '\n')
