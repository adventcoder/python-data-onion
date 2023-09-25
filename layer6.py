import sys

import click

import onion

@click.group()
def main():
    pass

@main.command()
def peel():
    vm = TomtelVM(onion.read_payload(sys.stdin))
    vm.run()
    sys.stdout.write(vm.out.decode('ascii'))

@main.command()
def wrap():
    onion.write_payload(sys.stdout, bytes())

class TomtelVM:
    def __init__(self, mem):
        self.mem = bytearray(mem)
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

if __name__ == '__main__':
    main()
