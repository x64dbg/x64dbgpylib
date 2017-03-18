import platform
import traceback

def notImplemented():
    try:
        raise NotImplementedError()
    except:
        traceback.print_stack()
        raise

def is64bitSystem():
    return platform.architecture()[0] == '64bit'

def dbgCommand(command, suppressOutput = False):
    notImplemented()

def dprintln(str, dml = False):
    notImplemented()

def findMemoryRegion(va):
    notImplemented()

def findSymbol(va):
    notImplemented()

def getCurrentProcess():
    notImplemented()

def getCurrentProcessId():
    notImplemented()

def getImplicitThread():
    # returns the current TEB address
    notImplemented()

def getProcessThreads():
    # returns a list of TEB addresses
    notImplemented()

def getVaProtect(va):
    notImplemented()

def isValid(va):
    notImplemented()

def loadBytes(va, count):
    notImplemented()

def loadChars(va, count):
    traceback.print_stack()

def loadCStr(va):
    notImplemented()

def loadDwords(va, count):
    notImplemented()

def loadUnicodeString(va):
    # returns string inside UNICODE_STRING at va
    notImplemented()

def loadWChars(va, count):
    notImplemented()

def loadWStr(va):
    notImplemented()

def ptrDWord(va):
    notImplemented()

def reg(name):
    notImplemented()

def typedVar(type, va):
    notImplemented()

def typedVarList(va, type, flink):
    notImplemented()

version = '0.3.2.1'

def ptrPtr(va):
    notImplemented()

class disasm:
    def __init__(self):
        notImplemented()

    def __init__(self, offset):
        notImplemented()

    def __str__(self):
        notImplemented()

    def asm(self, code):
        notImplemented()

    def begin(self):
        notImplemented()

    def current(self):
        notImplemented()

    def disasm(self):
        notImplemented()

    def disasm(self, offset):
        notImplemented()

    def ea(self):
        notImplemented()

    def findOffset(self, arg2):
        notImplemented()

    def instruction(self):
        notImplemented()

    def jump(self, arg2):
        notImplemented()

    def jumprel(self, arg2):
        notImplemented()

    def length(self):
        notImplemented()

    def opcode(self):
        notImplemented()

    def opmnemo(self):
        notImplemented()

    def reset(self):
        notImplemented()

class DbgException(Exception):
    pass

class MemoryException(DbgException):
    pass

class module:
    def __init__(self, name):
        notImplemented()

    def __getattr__(self, item):
        notImplemented()

    def __str__(self):
        notImplemented()

    def begin(self):
        notImplemented()

    def checksum(self):
        notImplemented()

    def containingRecord(self, arg2, arg3, arg4):
        notImplemented()

    def end(self):
        notImplemented()

    def enumSymbols(self, mask):
        notImplemented()

    def enumTypes(self, mask):
        notImplemented()

    def findSymbol(self, offset, showDisplacement = True):
        notImplemented()

    def findSymbolAndDisp(self, offset):
        # return (name, displacement)
        notImplemented()

    def getFixedFileInfo(self):

        notImplemented()

    def getVersion(self):
        notImplemented()

    def image(self):
        notImplemented()

    def name(self):
        notImplemented()

    def offset(self, symbol):
        notImplemented()

    def queryVersion(self, string):
        notImplemented()

    def reload(self):
        notImplemented()

    def rva(self, va):
        notImplemented()

    def size(self):
        notImplemented()

    def sizeof(self, type):
        notImplemented()

    def symfile(self):
        notImplemented()

    def timestamp(self):
        notImplemented()

    def type(self, name):
        notImplemented()

    def typedVar(self, offset):
        notImplemented()

    def typedVarArray(self, offset, name, count):
        notImplemented()

    def typedVarList(self, offset, name, flink):
        notImplemented()

    def um(self):
        # is user module
        notImplemented()

    def unloaded(self):
        notImplemented()