import platform
import traceback
import array
import enum
import x64dbgpy.pluginsdk.x64dbg as x64dbg
import x64dbgpy.pluginsdk._scriptapi as script

version = "0.2.0.29"

def notImplemented():
    try:
        raise NotImplementedError()
    except:
        traceback.print_stack()
        raise

def archValue(x32, x64):
    if is64bitSystem():
        return x64
    return x32

def is64bitSystem():
    return platform.architecture()[0] == "64bit"

def dbgCommand(command, suppressOutput = False):
    if command == "!teb":
        return "TEB at %x" % getImplicitThread()
    else:
        print "command: %s" % command
        notImplemented()

def dprintln(str, dml = False):
    print str

def findMemoryRegion(va):
    base = script.GetBase(va)
    size = script.GetSize(va)
    if base == 0 or size == 0:
        raise MemoryException("No such address 0x%x" % va)
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
    return memoryProtect(script.GetProtect(va))

def isValid(va):
    return x64dbg.DbgMemIsValidReadPtr(va)

def loadBytes(va, count):
    return list(script.Read(va, count))

def loadChars(va, count):
    return script.Read(va, count)

def loadCStr(va):
    chars = loadChars(va, 256)
    index = chars.find('\0')
    if index != -1:
        return chars[:index]
    return chars

def loadDwords(va, count):
    A = array.array("I")
    A.fromstring(script.Read(va, count * 4))
    return A.tolist()

def loadUnicodeString(va):
    va = int(va)
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa380518(v=vs.85).aspx
    Length = script.ReadWord(va)
    va += 2
    MaximumLength = script.ReadWord(va)
    va += 2
    if is64bitSystem():
        va += 4
    Buffer = script.ReadPtr(va)
    if Length > MaximumLength or not script.IsValidPtr(Buffer):
        raise DbgException("Corrupted UNICODE_STRING structure")
    A = array.array("u")
    A.fromstring(script.Read(Buffer, Length))
    return A.tounicode().rstrip(u'\0')

def loadWChars(va, count):
    A = array.array("u")
    A.fromstring(script.Read(va, count * 2))
    return A.tounicode()

def loadWStr(va):
    wchars = loadWChars(va, 256)
    index = wchars.find(u'\0')
    if index != -1:
        return wchars[:index]
    return wchars

def ptrDWord(va):
    return script.ReadDword(va)

def writeBytes(va, data):
    A = array.array("B")
    A.fromlist(data)
    script.Write(va, A.tostring())

def reg(name):
    return x64dbg.DbgValFromString(name)

def ptrPtr(va):
    return script.ReadPtr(va)

def typedVar(typename, va):
    if typename == "ntdll!_PEB":
        # TODO: fill in x64 offsets
        peb = typeStruct("_PEB", va)
        peb.Ldr = typePtr("_PEB_LDR_DATA*", va + archValue(0x000c, 0x0000))
        peb.ProcessParameters = typePtr("_RTL_USER_PROCESS_PARAMETERS*", va + archValue(0x0010, 0x0000))
        peb.NumberOfHeaps = typeInt32(va + archValue(0x008c, 0x0000))
        peb.ProcessHeaps = typePtr("void**", va + archValue(0x0090, 0x0000))
        peb.OSMajorVersion = typeInt16(va + archValue(0x00a4, 0x0000))
        peb.OSMinorVersion = typeInt16(va + archValue(0x00a8, 0x0000))
        peb.OSBuildNumber = typeInt8(va + archValue(0x00ac, 0x0000))
        return peb
    elif typename == "_PEB_LDR_DATA":
        # TODO: fill in x64 offsets
        ldr = typeStruct("_PEB_LDR_DATA", va)
        ldr.InLoadOrderModuleList = typeStruct("_LDR_DATA_TABLE_ENTRY", va + archValue(0x0014, 0x0000))
        return ldr
    elif typename == "_TEB":
        teb = typeStruct("_TEB", va)
        teb.Self = va
        return teb
    elif typename in ("_IMAGE_NT_HEADERS", "_IMAGE_NT_HEADERS64"):
        ntheaders = typeStruct(typename, va)
        ntheaders.FileHeader = typedVar("_IMAGE_FILE_HEADER", va + 0x0004)
        ntheaders.OptionalHeader = typedVar(archValue("_IMAGE_OPTIONAL_HEADER", "_IMAGE_OPTIONAL_HEADER64"), va + 0x0018)
        return ntheaders
    elif typename == "_IMAGE_FILE_HEADER":
        fileheader = typeStruct("_IMAGE_FILE_HEADER", va)
        fileheader.NumberOfSections = typeInt16(va + 0x0002)
        fileheader.SizeOfOptionalHeader = typeInt16(va + 0x0010)
        return fileheader
    elif typename in ("_IMAGE_OPTIONAL_HEADER", "_IMAGE_OPTIONAL_HEADER64"):
        optheader = typeStruct(typename, va)
        optheader.SizeOfCode = typeInt32(va + 0x0004)
        optheader.AddressOfEntryPoint = typeInt32(va + 0x0010)
        optheader.BaseOfCode = typeInt32(va + 0x0014)
        if not is64bitSystem():
            optheader.BaseOfData = typeInt32(va + 0x0018)
        optheader.ImageBase = typeInt32(va + archValue(0x001c, 0x0018))
        optionalheadersize = int(typeInt16(va - 0x0004))
        optheader.DataDirectory = [typedVar("_IMAGE_DATA_DIRECTORY", i) for i in range(va + archValue(0x0060, 0x0070), va + optionalheadersize, 8)]
        return optheader
    elif typename == "_IMAGE_DATA_DIRECTORY":
        imgdatadir = typeStruct("_IMAGE_DATA_DIRECTORY", va)
        imgdatadir.VirtualAddress = typeInt32(va)
        imgdatadir.Size = typeInt32(va + 0x0004)
        return imgdatadir
    else:
        print "typename: %s, va: %x" % (typename, va)
        notImplemented()

def typedVarList(va, typename, flink):
    if typename == "ntdll!_LDR_DATA_TABLE_ENTRY" and flink == "InMemoryOrderLinks.Flink":
        # TODO: fill in x64 offsets
        va = script.ReadPtr(int(va) + archValue(0x0008, 0x0000))
        result = []

        while va != 0 and len(result) < 10:
            entry = typeStruct("_LDR_DATA_TABLE_ENTRY", va)
            entry.BaseDllName = typeStruct("UNICODE_STRING", va + archValue(0x001c, 0x0000))
            result.append(entry)
            va = script.ReadPtr(va)
            pass
        return result
    else:
        notImplemented()

class typeBase(object):
    def __init__(self, name, size, addr = 0):
        self.name = name
        self.size = size
        self.addr = addr

    def getAddress(self):
        return self.addr

    def __int__(self):
        return self.getAddress()

    def __add__(self, other):
        return int(self) + other

class typePrimitive(typeBase):
    def __init__(self, name, size, addr = 0):
        super(typePrimitive, self).__init__(name, size, addr)

    def __int__(self):
        if self.size == 1:
            return script.ReadByte(self.addr)
        elif self.size == 2:
            return script.ReadWord(self.addr)
        elif self.size == 4:
            return script.ReadDword(self.addr)
        elif self.size == 8:
            return script.ReadQword(self.addr)
        else:
            notImplemented()

class typeInt8(typePrimitive):
    def __init__(self, addr = 0):
        super(typeInt8, self).__init__("uint8_t", 1, addr)

class typeInt16(typePrimitive):
    def __init__(self, addr = 0):
        super(typeInt16, self).__init__("uint16_t", 2, addr)

class typeInt32(typePrimitive):
    def __init__(self, addr = 0):
        super(typeInt32, self).__init__("uint32_t", 4, addr)

class typeInt64(typePrimitive):
    def __init__(self, addr = 0):
        super(typeInt64, self).__init__("uint64_t", 8, addr)

class typePtr(typePrimitive):
    def __init__(self, type = "void*", addr = 0):
        super(typePtr, self).__init__(type, archValue(4, 8), addr)

    def deref(self):
        return typedVar(self.name[:-1], int(self))

class typeStruct(typeBase):
    def __init__(self, name, addr):
        super(typeStruct, self).__init__(name, 0, addr)

class memoryProtect(enum.Enum):
    PageExecute = 16
    PageExecuteWriteCopy = 128
    PageReadOnly = 2
    PageReadWrite = 4
    PageExecuteRead = 32
    PageExecuteReadWrite = 64
    PageNoAccess = 1
    PageWriteCopy = 2

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
    def __init__(self, arg):
        if isinstance(arg, basestring):
            self._base = script.BaseFromName(arg)
        else:
            self._base = arg
        
        self._image = script.NameFromAddr(self._base)
        self._size = script.SizeFromAddr(self._base)
        
        index = self._image.rfind(".")
        if index != -1:
            self._name = self._image[:index]
        else:
            self._name = self._image
        
        if self._base == 0 or self._size == 0:
            raise DbgException("Failed to get module for %s" % arg)

    def begin(self):
        return self._base

    def size(self):
        return self._size

    def image(self):
        return self._image

    def name(self):
        return self._name

    def end(self):
        return self._base + self._size

    def typedVar(self, typename, va):
        return typedVar(typename, va)