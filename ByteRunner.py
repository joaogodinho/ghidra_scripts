# Emulates the selected assembly. Shows all changed registers and stack contents. Asks for registers to be ignored and initial register values.
#@author jcfg
#@category jcfg
#@keybinding F5
#@menupath jcfg.ByteRunner
#@toolbar 
import inspect

from unicorn import *
from unicorn.x86_const import *

INCLUDE_REGS = []
EXCLUDE_REGS = []
STACK_FILLER = b'\xDE\xAD\xBE\xEF'


def get_bytes(addr, size):
    return bytes(map(lambda b: b & 0xff, getBytes(addr, size)))


# From https://gist.github.com/mzpqnxow/a368c6cd9fae97b87ef25f475112c84c
def hexdump(src, base=0, length=16, sep='.'):
    """Hex dump bytes to ASCII string, padded neatly
    In [107]: x = b'\x01\x02\x03\x04AAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBB'

    In [108]: print('\n'.join(hexdump(x)))
    00000000  01 02 03 04 41 41 41 41  41 41 41 41 41 41 41 41 |....AAAAAAAAAAAA|
    00000010  41 41 41 41 41 41 41 41  41 41 41 41 41 41 42 42 |AAAAAAAAAAAAAABB|
    00000020  42 42 42 42 42 42 42 42  42 42 42 42 42 42 42 42 |BBBBBBBBBBBBBBBB|
    00000030  42 42 42 42 42 42 42 42                          |BBBBBBBB        |
    """
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c: c + length]
        hex_ = ' '.join(['{:02x}'.format(x) for x in chars])
        if len(hex_) > 24:
            hex_ = '{} {}'.format(hex_[:24], hex_[24:])
        printable = ''.join(['{}'.format((x <= 127 and FILTER[x]) or sep) for x in chars])
        # Added the base parameter so the hexdump can start from a specific address
        lines.append('{0:08x}  {1:{2}s} |{3:{4}s}|'.format(base + c, hex_, length * 3, printable, length))
    return lines


def find_changes(before, after, search=b'\xDE\xAD\xBE\xEF'):
    """
    Takes 2 bytearrays and returns an array with tuples of (pos, size) where the arrays
    differ in content. Used to search the Stack for changes
    """
    changes = []
    in_change = False
    size = 0
    s_size = len(search)
    new_before = [before[i:i + s_size] for i in range(0, len(before), s_size)]
    new_after =  [after[i:i + s_size] for i in range(0, len(after), s_size)]
    for index, (pre, post) in enumerate(zip(new_before, new_after)):
        if pre != post:
            if not in_change:
                in_change = True
                size += s_size
            else:
                size += s_size
        else:
            if in_change:
                changes.append((s_size * index - size, size))
                in_change = False
                size = 0
    return changes


def main():
    if not currentSelection():
        popup('No code selected!')
        exit(0)

    # Get the correct settings for the emulation
    arch, _, bit, _ = currentProgram().getLanguageID().getIdAsString().split(':')
    if arch == 'x86':
        UC_ARCH = UC_ARCH_X86
        REG_NAME = 'UC_X86_REG_'
    else:
        popup(f'Arch {arch} not supported.')
        raise Exception(f'Arch {arch} not supported.')

    if bit == '32':
        UC_MODE = UC_MODE_32
        INCLUDE_REGS.append('E')
    elif bit == '64':
        UC_MODE = UC_MODE_64
        INCLUDE_REGS.append('R')
    else:
        popup(f'Address size {bit} not supported.')
        raise Exception(f'Address size {bit} not supported.')

    uc = Uc(UC_ARCH, UC_MODE)

    # We need to map the sections so emulation works when referencing other sections and calls
    for memory in currentProgram().getMemory():
        start = memory.getMinAddress()
        end = memory.getMaxAddress()
        # Needs to be 4KB aligned
        size = ((end.subtract(start) // 0x1000) + 1) * 0x1000
        data = get_bytes(start, size)
        start = start.getAddressableWordOffset()
        uc.mem_map(start, size)
        uc.mem_write(start, data)

    stack_base = 0x100000
    stack_size = 0x100000

    # Set up registers
    esp = stack_base + (stack_size // 4)
    ebp = stack_base + stack_size - (stack_size // 4)
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EBP, ebp)

    # Set up memory
    uc.mem_map(stack_base, stack_size)
    uc.mem_write(stack_base, STACK_FILLER * (stack_size // len(STACK_FILLER)))

    # Ask for registers to ignore
    global EXCLUDE_REGS
    EXCLUDE_REGS += filter(lambda x: x, askString('Exclude Registers', 'Registers: (e.g. eax,esp)', ',').split(','))

    # Ask for register values
    for setup in askString('Register Values', 'Values: (e.g. eax=0x3,ebx=0xc)', ',').split(','):
        if not setup:
           continue
        reg, value = setup.split('=')
        reg = REG_NAME + reg.upper()
        for name, idx in inspect.getmembers(unicorn.x86_const):
            if reg == name:
                uc.reg_write(idx, int(value, 16))
                break

    start_addr = currentSelection().getMinAddress()
    end_addr = currentSelection().getMaxAddress().add(1)
    code_size = end_addr.subtract(start_addr)

    print(f'Emulating code from {start_addr} to {end_addr} ({hex(code_size)} bytes)...')

    # Save registers before emulation
    registers = {}
    for name, value in inspect.getmembers(unicorn.x86_const):
        if not name.startswith(REG_NAME):
            continue
        name = name.replace(REG_NAME, '')
        if any([name.startswith(x.upper()) for x in EXCLUDE_REGS]):
            continue
        if not any([name.startswith(x.upper()) for x in INCLUDE_REGS]):
            continue
        registers[value] = name

    reg_values_pre = {}
    for key, _ in registers.items():
        try:
            reg_values_pre[key] = uc.reg_read(key)
        except unicorn.UcError:
            continue

    # Start emulation
    uc.emu_start(start_addr.getAddressableWordOffset(), end_addr.getAddressableWordOffset(), count=0)

    # Print registers that changed before and after emulation
    out = ''
    for key, value in reg_values_pre.items():
        new_value = uc.reg_read(key)
        if value != new_value:
            out += f'{registers[key].replace(REG_NAME, "").ljust(4)}{hex(new_value)}\n'
    print(out)

    pre_emulation_stack =  STACK_FILLER * (stack_size // len(STACK_FILLER))
    post_emulation_stack = uc.mem_read(stack_base, stack_size)

    changes = find_changes(pre_emulation_stack, post_emulation_stack)

    for idx, size in changes:
        addr = idx + stack_base
        print(hex(addr))
        print('\n'.join(hexdump(post_emulation_stack[idx:idx+size], addr)))
        print()

if __name__ == '__main__':
    main()

