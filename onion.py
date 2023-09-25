import ascii85
import re

def read_payload(inp):
    return ascii85.decode(re.sub(r'\s+', '', between(inp.read(), '<~', '~>')))

def between(text, start, end):
    i = text.index(start) + len(start)
    j = text.index(end, i)
    return text[i : j]

def write_payload(out, data):
    out.write('==[ Payload ]===============================================\n')
    out.write('\n')
    write_line(out, ['<~', *ascii85.encode(data), '~>'], 60)
    out.write('\n')

def write_line(out, chunks, width):
    x = 0
    for chunk in chunks:
        if x + len(chunk) > width:
            out.write('\n')
            x = 0
        out.write(chunk)
        x += len(chunk)
    out.write('\n')
