import platform

def is64bitSystem():
    return platform.architecture()[0] == '64bit'

def dbgCommand(command, suppressOutput = False):
    raise

def dprintln(str, dml = False):
    raise

def findMemoryRegion(va):
    raise

def findSymbol(va):
    raise

def getCurrentProcess():
    raise

def getCurrentProcessId():
    raise

def getImplicitThread():
    # returns the current TEB address
    raise

def getProcessThreads():
    # returns a list of TEB addresses
    raise

def getVaProtect(va):
    raise

def isValid(va):
    raise

def loadBytes(va, count):
    raise

def loadChars(va, count):
    raise

def loadCStr(va):
    raise

def loadDwords(va, count):
    raise

def loadUnicodeString(va):
    # returns string inside UNICODE_STRING at va
    raise

def loadWChars(va, count):
    raise

def loadWStr(va):
    raise

def ptrDWord(va):
    raise

def reg(name):
    raise

def typedVar(type, va):
    raise

def typedVarList(va, type, flink):
    raise

version = '0.3.2.1'

def ptrPtr(va):
    raise

class disasm:
    def __init__(self):
        raise

    def __init__(self, offset):
        raise

    def __str__(self):
        raise

    def asm(self, code):
        raise

    def begin(self):
        raise

    def current(self):
        raise

    def disasm(self):
        raise

    def disasm(self, offset):
        raise

    def ea(self):
        raise

    def findOffset(self, arg2):
        raise

    def instruction(self):
        raise

    def jump(self, arg2):
        raise

    def jumprel(self, arg2):
        raise

    def length(self):
        raise

    def opcode(self):
        raise

    def opmnemo(self):
        raise

    def reset(self):
        raise

class DbgException(Exception):
    pass

class MemoryException(DbgException):
    pass

class module:
    def __init__(self, name):
        raise

    def __getattr__(self, item):
        raise

    def __str__(self):
        raise

    def begin(self):
        raise

    def checksum(self):
        raise

    def containingRecord(self, arg2, arg3, arg4):
        raise

    def end(self):
        raise

    def enumSymbols(self, mask):
        raise

    def enumTypes(self, mask):
        raise

    def findSymbol(self, offset, showDisplacement = True):
        raise

    def findSymbolAndDisp(self, offset):
        # return (name, displacement)
        raise

    def getFixedFileInfo(self):

        raise

    def getVersion(self):
        raise

    def image(self):
        raise

    def name(self):
        raise

    def offset(self, symbol):
        raise

    def queryVersion(self, string):
        raise

    def reload(self):
        raise

    def rva(self, va):
        raise

    def size(self):
        raise

    def sizeof(self, type):
        raise

    def symfile(self):
        raise

    def timestamp(self):
        raise

    def type(self, name):
        raise

    def typedVar(self, offset):
        raise

    def typedVarArray(self, offset, name, count):
        raise

    def typedVarList(self, offset, name, flink):
        raise

    def um(self):
        # is user module
        raise

    def unloaded(self):
        raise