import random
import sys

import click

import onion

@click.group()
def main():
    pass

@main.command()
@click.option('--emulate', is_flag=True)
def peel(emulate):
    code = onion.read_payload(sys.stdin)
    if emulate:
        vm = TomtelVM(code)
        vm.run()
        sys.stdout.write(vm.out.decode('ascii'))
    else:
        ciphertext = code[143 : -367]
        table = code[-291 : -35]
        key = code[-25 : -9]
        cipher = DallingCipher(key, table)
        plaintext = cipher.decrypt(ciphertext)
        sys.stdout.write(plaintext.decode('ascii'))

@main.command()
def wrap():
    plaintext = sys.stdin.read().encode('ascii')

    key = random.randbytes(16)
    table = bytearray(range(256))
    random.shuffle(table)

    cipher = DallingCipher(key, table)
    ciphertext = cipher.encrypt(plaintext)

    assembler = TomtelAssembler('layer6.tom', { 'key': key, 'table': table, 'ciphertext': ciphertext })
    assembler.assemble()
    assembler.resolve_refs()
    onion.write_payload(sys.stdout, assembler.code)

class TomtelVM:
    def __init__(self, code):
        self.mem = bytearray(code)
        self.out = bytearray()
        self.reg8 = bytearray(6)
        self.reg32 = [0] * 6

    @staticmethod
    def reg8(i):
        def getter(self):
            return self.reg8[i]
        def setter(self, val):
            self.reg8[i] = val
        return property(getter, setter)

    a = reg8(0)
    b = reg8(1)
    c = reg8(2)
    d = reg8(3)
    e = reg8(4)
    f = reg8(5)

    @staticmethod
    def reg32(i):
        def getter(self):
            return self.reg32[i]
        def setter(self, val):
            self.reg32[i] = val
        return property(getter, setter)

    la = reg32(0)
    lb = reg32(1)
    lc = reg32(2)
    ld = reg32(3)
    ptr = reg32(4)
    pc = reg32(5)

    def imm8(self):
        x = self.mem[self.pc]
        self.pc += 1
        return x

    def imm32(self):
        x = int.from_bytes(self.mem[self.pc : self.pc + 4], 'little')
        self.pc += 4
        return x

    def run(self):
        while True:
            opcode = self.imm8()
            if opcode == 0x01: # HALT
                break 
            elif opcode == 0x02: # OUT
                self.out.append(self.a)
            elif opcode == 0x21: # JEZ imm32
                dest = self.imm32()
                if self.f == 0:
                    self.pc = dest
            elif opcode == 0x22: # JNZ imm32
                dest = self.imm32()
                if self.f != 0:
                    self.pc = dest
            elif opcode == 0xC1: # CMP
                self.f = 0 if self.a == self.b else 1
            elif opcode == 0xC2: # ADD a <- b
                self.a = (self.a + self.b) & 0xFF
            elif opcode == 0xC3: # SUB a <- b
                self.a = (self.a - self.b) & 0xFF
            elif opcode == 0xC4: # XOR a <- b
                self.a = self.a ^ self.b
            elif opcode == 0xE1: # APTR imm8
                self.ptr += self.imm8()
            elif (opcode >> 6) == 0b01: # MV[I] {dest} <- {src}
                src = opcode & 7
                dest = (opcode >> 3) & 7
                if src == 0:
                    val = self.imm8()
                elif src <= 6:
                    val = self.reg8[src - 1]
                else:
                    val = self.mem[self.ptr + self.c]
                if dest == 0:
                    raise ValueError('imm8 assign')
                elif dest <= 6:
                    self.reg8[dest - 1] = val
                else:
                    self.mem[self.ptr + self.c] = val
            elif (opcode >> 6) == 0b10: # MV[I]32 {dest} <- {src}
                src = opcode & 7
                dest = (opcode >> 3) & 7
                if src == 0:
                    val = self.imm32()
                else:
                    val = self.reg32[src - 1]
                if dest == 0:
                    raise ValueError('imm32 assign')
                else:
                    self.reg32[dest - 1] = val
            else:
                raise ValueError('opcode: ' + hex(opcode))

class TomtelAssembler:
    def __init__(self, path, data):
        self.tokens = self.lex(path)
        self.index = 0
        self.data = data
        self.code = bytearray()
        self.labels = {}
        self.refs = []

    @staticmethod
    def lex(path):
        with open(path, 'r') as file:
            return file.read().split()

    def assemble(self):
        while op := self.next():
            if op.endswith(':'):
                label = op[:-1]
                self.labels[label] = len(self.code)
            elif op == 'HALT':
                self.code.append(0x01)
            elif op == 'OUT':
                self.code.append(0x02)
                self.match('a')
            elif op == 'JEZ':
                self.code.append(0x21)
                self.imm32()
            elif op == 'JNZ':
                self.code.append(0x22)
                self.imm32()
            elif op == 'CMP':
                self.code.append(0xC1)
            elif op == 'ADD':
                self.code.append(0xC2)
                self.match('a', '<-', 'b')
            elif op == 'SUB':
                self.code.append(0xC3)
                self.match('a', '<-', 'b')
            elif op == 'XOR':
                self.code.append(0xC4)
                self.match('a', '<-', 'b')
            elif op == 'APTR':
                self.code.append(0xE1)
                self.imm8()
            elif op == 'MV':
                dest = self.reg8()
                self.match('<-')
                src = self.reg8()
                self.code.append((0b01 << 6) | (dest << 3) | src)
            elif op == 'MVI':
                dest = self.reg8()
                self.code.append((0b01 << 6) | (dest << 3))
                self.match('<-')
                self.imm8()
            elif op == 'MV32':
                dest = self.reg32()
                self.match('<-')
                src = self.reg32()
                self.code.append((0b10 << 6) | (dest << 3) | src)
            elif op == 'MVI32':
                dest = self.reg32()
                self.code.append((0b10 << 6) | (dest << 3))
                self.match('<-')
                self.imm32()
            elif op == 'DATA':
                key = self.next()
                self.code.extend(self.data[key])
            else:
                raise ValueError('op: ' + repr(op))

    def resolve_refs(self):
        for i, label in self.refs:
            self.code[i : i + 4] = self.labels[label].to_bytes(4, 'little')

    def next(self):
        if self.index < len(self.tokens):
            token = self.tokens[self.index]
            self.index += 1
            return token
        return None

    def match(self, *tokens):
        for expecting in tokens:
            token = self.next()
            if token != expecting:
                raise ValueError('expecting: ' + expecting + ', but got: ' + token)

    def reg8(self):
        return ('a', 'b', 'c', 'd', 'e', 'f', '(ptr+c)').index(self.next()) + 1

    def reg32(self):
        return ('la', 'lb', 'lc', 'ld', 'ptr', 'pc').index(self.next()) + 1

    def imm8(self):
        self.code.append(int(self.next()))

    def imm32(self):
        token = self.next()
        if token.startswith(':'):
            label = token[1:]
            self.refs.append((len(self.code), label))
            val = 0
        else:
            val = int(token)
        self.code.extend(val.to_bytes(4, 'little'))

class DallingCipher:
    def __init__(self, key, table):
        self.key = bytearray(key)
        self.table = table
        self.inv_table = self.invert(self.table)

    @staticmethod
    def invert(table):
        inv_table = bytearray(len(table))
        for i in range(len(table)):
            inv_table[table[i]] = i
        return inv_table

    def decrypt(self, inp):
        out = bytearray()
        i = 0
        while True:
            block = self.decrypt_block(inp[i : i + 16])
            if block[0] == 0:
                break
            self.next_key(block)
            out.extend(block[1:][:block[0]])
            i += 16
        return out

    def encrypt(self, inp):
        out = bytearray()
        for i in range(0, len(inp), 15):
            data = inp[i : i + 15]
            block = bytes([len(data)]) + data + bytes(15 - len(data))
            out.extend(self.encrypt_block(block))
            self.next_key(block)
        out.extend(self.encrypt_block(bytes(16)))
        return out

    def decrypt_block(self, inp):
        out = bytearray(inp)
        self.xor(out, self.key)
        self.rot1(out, 1)
        self.rot2(out, 2)
        self.rot3(out, 3)
        self.sub(out, self.table)
        return out

    def encrypt_block(self, inp):
        out = bytearray(inp)
        self.sub(out, self.inv_table)
        self.rot3(out, 1)
        self.rot2(out, 2)
        self.rot1(out, 3)
        self.xor(out, self.key)
        return out

    def next_key(self, plain):
        self.key.reverse()
        self.xor(self.key, plain)
        self.sub(self.key, self.table)

    @staticmethod
    def xor(block, key):
        for i in range(16):
            block[i] ^= key[i]

    @staticmethod
    def sub(block, table):
        for i in range(16):
            block[i] = table[block[i]]

    @staticmethod
    def rot1(block, i):
        t             = block[i     ]
        block[i     ] = block[i +  4]
        block[i +  4] = block[i +  8]
        block[i +  8] = block[i + 12]
        block[i + 12] = t

    @staticmethod
    def rot2(block, i):
        t1            = block[i     ]
        block[i     ] = block[i +  8]
        block[i +  8] = t1
        t2            = block[i +  4]
        block[i +  4] = block[i + 12]
        block[i + 12] = t2

    @staticmethod
    def rot3(block, i):
        t             = block[i + 12]
        block[i + 12] = block[i +  8]
        block[i +  8] = block[i +  4]
        block[i +  4] = block[i     ]
        block[i     ] = t

if __name__ == '__main__':
    main()
