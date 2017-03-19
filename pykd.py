import platform
import traceback
import array
import x64dbgpy.pluginsdk.x64dbg as x64dbg
import x64dbgpy.pluginsdk._scriptapi as script

version = '0.3.2.1'

def notImplemented():
    try:
        raise NotImplementedError()
    except:
        traceback.print_stack()
        raise

def is64bitSystem():
    return platform.architecture()[0] == '64bit'

def dbgCommand(command, suppressOutput = False):
    print "command: %s" % command
    notImplemented()

def dprintln(str, dml = False):
    print str

def findMemoryRegion(va):
    base = script.GetBase(va)
    size = script.GetSize(va)
    if base == 0 or size == 0:
        raise MemoryException('No such address 0x%x' % va)
    return base, size

def findSymbol(va):
    notImplemented()

def getCurrentProcess():
    return x64dbg.DbgGetPebAddress(x64dbg.DbgGetProcessId())

def getCurrentProcessId():
    return x64dbg.DbgGetProcessId()

def getImplicitThread():
    return x64dbg.DbgGetTebAddress(x64dbg.DbgGetThreadId())

def getProcessThreads():
    l = x64dbg.THREADLIST()
    x64dbg.DbgGetThreadList(l)
    result = []
    if l.count > 0:
        return [t.BasicInfo.ThreadLocalBase for t in x64dbg.GetThreadInfoList(l)]
    return result

def getVaProtect(va):
    return script.GetProtect(va)

def isValid(va):
    return x64dbg.DbgMemIsValidReadPtr(va)

def loadBytes(va, count):
    return list(script.Read(va, count))

def loadChars(va, count):
    return script.Read(va, count)

def loadCStr(va):
    return loadChars(va, 256).rstrip('\0')

def loadDwords(va, count):
    A = array.array('I')
    A.fromstring(script.Read(va, count * 4))
    return A.tolist()

def loadUnicodeString(va):
    # http://www.nirsoft.net/kernel_struct/vista/UNICODE_STRING.html
    Length = script.ReadWord(va)
    va += 2
    MaximumLength = script.ReadWord(va)
    va += 2
    if is64bitSystem():
        va += 4
    Buffer = script.ReadPtr(va)
    if Length > MaximumLength or not script.IsValidPtr(Buffer):
        raise DbgException('Corrupted UNICODE_STRING structure')
    A = array.array('u')
    A.fromstring(script.Read(Buffer, Length * 2))
    return A.tounicode()

def loadWChars(va, count):
    A = array.array('u')
    A.fromstring(script.Read(va, count * 2))
    return A.tounicode()

def loadWStr(va):
    return loadWChars(va, 256 * 2).rstrip(u'\0')

def ptrDWord(va):
    return script.ReadDword(va)

def writeBytes(va, data):
    A = array.array('B')
    A.fromlist(data)
    script.Write(va, A.tostring())

def reg(name):
    return x64dbg.DbgValFromString(name)

def ptrPtr(va):
    return script.ReadPtr(va)

def typedVar(type, va):
    notImplemented()

def typedVarList(va, type, flink):
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