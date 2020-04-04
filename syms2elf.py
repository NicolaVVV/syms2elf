# Plugin to export function names created in ghidra
#@author NicolaVVV
#@category elf
#@menupath File.Run.Syms2Elf

import subprocess  # For calling real syms2elf
import tempfile
import os

from base64 import *
from ctypes import *
from struct import unpack

SHN_UNDEF = 0
STB_GLOBAL_FUNC = 0x12

class Symbol:
    def __init__(self, name, info, value, size, shname, shndx=-1):
        self.name   = name
        self.info   = info
        self.value  = value
        self.size   = size
        self.shname = shname
        self.shndx  = shndx

    def __repr__(self):
        return "%s\t\t%s\t\t%s\t\t%s\t\t%s" % (self.name, self.info, self.value, self.size, self.shname)
        
def get_ghidra_section(addr):
    sections = currentProgram.getMemory().getBlocks()
    for idx, s in enumerate(sections):
        try:
            startAddr = int(str(s.getStart()), 16)
            endAddr = int(str(s.getEnd()), 16)
            if (startAddr <= addr <= endAddr) == True:
                return (idx, s.getName())
        except:
            pass
    return None

def ghidra_fnc_filter(fnc):
    if fnc.isThunk() == True or fnc.isExternal() == True:
        return False
    return True

def get_ghidra_symbols():
    symbols = []
    functions = currentProgram.getFunctionManager().getFunctions(True)
    for fnc in filter(ghidra_fnc_filter, functions):
        if 'syscall' in str(fnc.getEntryPoint()):
            continue
        fnc_addr = int(str(fnc.getEntryPoint()), 16)
        fnc_name = fnc.getName()
        fnc_size = fnc.getBody().getNumAddresses()
        sh_idx, sh_name = get_ghidra_section(fnc_addr)
        symbols.append(Symbol(fnc.name, STB_GLOBAL_FUNC,
            fnc_addr, fnc_size, sh_name))
    return symbols

# Get stripped binary location
infile = currentProgram.getDomainFile().getMetadata()["Executable Location"]
if askYesNo('Warning', 'Do you want to change the input path? \n%s' % infile):
    infile = askFile("Select the input file", "Select").getAbsolutePath()
outfile = infile + '.sym.elf'
if askYesNo('Warning', 'Do you want to change the output path? \n%s' % outfile):
    outfile = askFile("Select the output file", "Select").getAbsolutePath()
flag = True
# Check if user wants to overwrite
if os.path.isfile(outfile):
    flag = askYesNo('Warning', 'Are you sure you want to overwrite \n%s ?' % outfile)
# Write unstripped binary
if flag:
    symbols = get_ghidra_symbols()
    encoded_syms = [b64encode(str(s)) for s in symbols]
    fd, tmp_path = tempfile.mkstemp()
    
    try:
        with os.fdopen(fd, 'w') as tmp:
            tmp.write('\n'.join(encoded_syms))
        # Need subprocess because jython doesn't support ctypes properly
        helper = '%s/ghidra_scripts/syms2elf_HELPER.py' % os.environ['HOME']
        if not os.path.exists(helper):
            print 'Error: did you copy the HELPER script in the right position?'
            print '%s/ghidra_scripts/syms2elf_HELPER.py not found' % os.environ['HOME']
        else:
            subprocess.call(['python2', '%s/ghidra_scripts/syms2elf_HELPER.py' % os.environ['HOME'], infile, outfile, tmp_path])
    finally:
        os.remove(tmp_path)
