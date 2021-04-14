# disasm.py
import sys

memory = bytearray(4096)
memsize = 0

def dump(mem, size):
    print("dump of: {}".format(filename))
    i=0x0200
    while i < size:
        print("{:04x} :: ".format(i), end="")
        for j in range(16):
            print("{:02x} ".format(mem[i+j]),end="")
        print("")
        i = i+j+1

def decode(hbyte, lbyte, opaddr):
    # extract some values which might come handy
    opcode = (hbyte << 8) | lbyte  # complete 2-byte opcode
    nibble = hbyte >> 4            # first hex-digit of opcode

    addr = opcode & 0x0FFF         # three byte address
    reg  = hbyte & 0x0F            # register number
    reg2 = lbyte >> 4              # register number for opcodes with two registers
    val  = lbyte                   # second byte as value
        
    if nibble == 0x00:
        if lbyte == 0xE0:
            print("CLS", end="")
        elif lbyte == 0xEE:
            print("RET", end="")
        else:
            print("", end="")
    elif nibble == 0x01:
        print("JP\t0x{:03x}".format(addr), end="")
    elif nibble == 0x02:
        print("CALL\t0x{:03x}".format(addr), end="")
    elif nibble == 0x03:
        print("SE\tV{:0x}, {}".format(reg, val), end="")
    elif nibble == 0x04:
        # 4xkk - SNE Vx, byte
        print("SNE\tV{:x}, {}".format(reg, val), end="")
    elif nibble == 0x05:
        # 5xy0 - SE Vx, Vy
        print("SE\tV{:x}, V{:x}".format(reg, reg2), end="")
    elif nibble == 0x06:
        # 6xkk - LD Vx, byte
        print("LD\tV{:x}, {}".format(reg, val), end="")
    elif nibble == 0x07:
        # 7xkk - ADD Vx, byte
        print("ADD\tV{:x}, {}".format(reg, val), end="")
    elif nibble == 0x08:
        selector = lbyte & 0x0F

        if selector == 0x0:
            # 8xy0 - LD Vx, Vy
            print("LD\t", end="")
        if selector == 0x1:
            # 8xy1 - OR Vx, Vy
            print("OR\t", end="")
        if selector == 0x2:
            # 8xy2 - AND Vx, Vy
            print("AND\t", end="")
        if selector == 0x3:
            # 8xy3 - XOR Vx, Vy
            print("XOR\t", end="")
        if selector == 0x4:
            # 8xy4 - ADD Vx, Vy
            print("ADD\t", end="")
        if selector == 0x5:
            # 8xy5 - SUB Vx, Vy
            print("SUB\t", end="")
        if selector == 0x6:
            # 8xy6 - SHR Vx
            print("SHR\t", end="")
        if selector == 0x7:
            # 8xy7 - SUBN Vx, Vy
            print("SUBN\t", end="")
        if selector == 0xe:
            # 8xyE - SHL Vx {, Vy}
            print("SHL\t", end="")
        print("V{:x}, V{:x}".format(reg, reg2), end="")
    elif nibble == 0x09:
        # 9xy0 - SNE Vx, Vy
        print("SNE\tV{:x}, V{:x}".format(reg, reg2), end="")
    elif nibble == 0x0A:
        # Annn - LD I, addr
        print("LD\tI, 0x{:03x}".format(addr), end="")
    elif nibble == 0x0B:
        # Bnnn - JP V0, addr
        print("JP\tV0, 0x{:03x}".format(addr), end="")
    elif nibble == 0x0C:
        # Cxkk - RND Vx, byte
        print("RND\tV{:x}, {}".format(reg, val), end="")
    elif nibble == 0x0D:
        # Dxyn - DRW Vx, Vy, nibble
        n = lbyte & 0x0F
        print("DRW\tV{:x}, V{:x}, {}".format(reg,reg2,n), end="")
    elif nibble == 0x0E:
        if lbyte == 0x9E:
            # Ex9E - SKP Vx
            print("SKP\tV{:x}".format(reg), end="")
        if lbyte == 0xA1:
            # ExA1 - SKNP Vx
            print("SKNP\tv{:x}".format(reg), end="")
        else:
            print()
    elif nibble == 0x0F:
        if lbyte == 0x07:
            # Fx07 - LD Vx, DT
            print("LD\tV{:x}, DT".format(reg), end="")
        elif lbyte == 0x0A:
            # Fx0A - LD Vx, K
            print("LD\tV{:x}, K".format(reg), end="")
        elif lbyte == 0x15:
            # Fx15 - LD DT, Vx
            print("LD\tDT, V{:x}".format(reg), end="")
        elif lbyte == 0x18:
            # Fx18 - LD ST, Vx
            print("LD\tST, V{:x}".format(reg), end="")
        elif lbyte == 0x1E:
            # Fx1E - ADD I, Vx
            print("ADD\tI, V{:x}".format(reg), end="")
        elif lbyte == 0x29:
            # Fx29 - LD F, Vx
            print("LD\tI, V{:x}".format(reg), end="")
        elif lbyte == 0x33:
            # Fx33 - LD B, Vx
            print("LD\tB, V{:x}".format(reg), end="")
        elif lbyte == 0x55:
            # Fx55 - LD [I], Vx
            print("LD\t[I], V{:x}".format(reg), end="")
        elif lbyte == 0x65:
            # Fx65 - LD Vx, [I]
            print("LD\tV{:x}, [I]".format(reg), end="")
        else:
            print()

    else:
        print("unhandled opcode", end="")
    
    # print address and opcode as comment
    print("   \t; {:04x} :: {:02x} {:02x}\t".format(opaddr, hbyte, lbyte))


def disasm(mem, size):
    print("disasm of: {}".format(filename))
    i = 0x0200
    while i < size:
        #print("{:04x} :: ".format(i), end="")
        decode(mem[i], mem[i+1], i)
        i = i + 2
    

if __name__ == "__main__":
    print("Py8Tools disasm v0.1")
    error   = False
    dumping = False    
    # Commandline arguments
    argcount = len(sys.argv)
    if argcount > 3 or argcount < 2:
        error = True
    elif argcount == 2:
        filename = sys.argv[1]
    elif (argcount == 3) & (sys.argv[1] == "dump"):
        dumping = True
        filename = sys.argv[2]
    else:
        error = True
        
    if error == True:
        print("Usage: disasm.py [dump] filename")
        sys.exit(-1)
        print("exit")

    # read file into memory
    pc = 0x0200
    try:
        with open(filename, "rb") as file:
            while True:
                byte = file.read(1)
                if not byte:
                    break
                memory[pc] = ord(byte)
                pc = pc +1
        memsize = pc
    except:
        print("cannot open file {}".format(filename))
        sys.exit(-1)
    
    if dumping:
        dump(memory, memsize)
    else:
        disasm(memory, memsize)
    