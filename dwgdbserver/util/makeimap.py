#!/usr/bin/env python3
"""
Read the file given as an argument and return a dict called instrmap that
maps each opcode to a memonic (if legal). The file contains an assembler listing
with all known opcodes.
"""
import sys
import re


def main():
    try:
        in_file = open(sys.argv[1], "r")
    except:
        sys.exit("ERROR. Did you make a mistake in the spelling the file name?")

    text = in_file.readlines()
    text = text[text.index("__trampolines_start():\n")+1:]
    print("instrmap = {")
    for line in text:
        elems = re.search(".*:\\s*([0-9a-f][0-9a-f]) ([0-9a-f][0-9a-f])[^a-z]*([a-z]*)", line).groups()
        if elems[2] in ['call', 'jmp', 'lds', 'sts']:
            words = 2
        else:
            words = 1
        type = 'nobranch'
        if elems[2][0:3] == 'sbr' or elems[2] == 'sbic' or elems[2] == 'sbis' or \
            elems[2][0:2] == 'br' or elems[2] == 'cpse':
            type = 'cond'
        elif elems[2] in ['ijmp', 'eijmp', 'ret', 'icall', 'reti', 'eicall', 'call', 'rjmp', 'rcall']:
            type = 'branch'
        if elems[2] in ['brie', 'brid']:
            type = 'icond'
        print("0x{}{} : ('{}', {}, '{}'),".format(elems[1], elems[0], elems[2], words, type))
    print("0x9598 : ('break', 1, 'nobranch')")
    print("}")

if __name__ == "__main__":
    main()

    
