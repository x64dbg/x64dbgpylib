import platform
import traceback
import array
import fnmatch
import x64dbgpy.pluginsdk.x64dbg as x64dbg
import x64dbgpy.pluginsdk._scriptapi as script
import x64dbgpy.__breakpoints as breakpoints

from collections import deque

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
    args = command.split(" ")
    if args[0] == "!teb":
        return "TEB at %x" % getImplicitThread()
    elif args[0] == "ba":
        bpaccess = args[1]
        addr = int(args[3], 16)
        bpsingleton = breakpoints.Breakpoint()
        if bpaccess == "e":
            hw_type = bpsingleton.HW_EXECUTE
        elif bpaccess == "r":
            hw_type = bpsingleton.HW_ACCESS
        elif bpaccess == "w":
            hw_type = bpsingleton.HW_WRITE
        else:
            return
        bpsingleton.add(addr, None, bp_type=bpsingleton.BP_MEMORY, hw_type=hw_type)
        return
    elif args[0] == "bc":
        bpid = int(args[1], 16)
        bpsingleton = breakpoints.Breakpoint()
        bpsingleton.remove(bpid)
        return
    elif args[0] == "bl":
        output = ""
        bpsingleton = breakpoints.Breakpoint()
        bpkeys = bpsingleton.list()
        for bpkey in bpkeys:
            output += "%0.8x X %0.8x \n" % (bpkey, bpkey) # address as key, dummy type
        return output
    elif args[0] == "bp":
        addr = int(args[1], 16)
        bpsingleton = breakpoints.Breakpoint()
        bpsingleton.add(addr, None)
        return
    elif args[0] == "eb":
        addr = int(args[1], 16)
        bytestowrite = [ int(x, 16) for x in args[2:] ]
        for b in bytestowrite:
            script.memory.WriteByte(addr, b)
            addr += 1
        return
    elif args[0] == "lm":
        output = ""
        modules = script.module.GetList()
        for m in modules:
            modname = "_".join(m.name.split(".")[:-1])
            output += "%0.8x %0.8x   %s\n" % (m.base, m.base + m.size, modname)
        return output
    elif args[0] == "ln":
        output = ""
        addr = None
        try:
            addr = int(args[1], 16)
            info = script.module.InfoFromAddr(addr)
            modulename = info.name
            modulebaseaddr = info.base
        except:
            functionparts = args[1].split("!")
            modulename = functionparts[0]
            functionname = None
            if len(functionparts) > 1:
                functionname = functionparts[1]
            info = script.module.InfoFromName(modulename)
            modulename = info.name # get full name
            modulebaseaddr = info.base
        symbols = list(filter(lambda s: s.mod == modulename, script.symbol.GetList()))
        symbols = sorted(symbols, key=lambda x: x.rva)
        if addr:
            closestsymbol = min(symbols, key=lambda s: abs(modulebaseaddr + s.rva - addr))
        else:
            try:
                if functionname:
                    closestsymbol = next(s for s in symbols if s.name == functionname)
                else:
                    closestsymbol = symbols[0]
            except:
                return output
        closestsymbolindex = symbols.index(closestsymbol)
        closestsymboladdr = modulebaseaddr + closestsymbol.rva
        closestsymbols = [ closestsymbol ]
        if addr and closestsymboladdr > addr:
            if closestsymbolindex - 1 > 0:
                closestsymbols.insert(0, symbols[closestsymbolindex - 1])
        elif closestsymbolindex + 1 < len(symbols):
            closestsymbols.append(symbols[closestsymbolindex + 1])
        for i, s in enumerate(closestsymbols):
            if i > 0:
                output += " | "
            output += "(%0.8x) " % (modulebaseaddr + s.rva)
            output += "_".join(modulename.split(".")[:-1]) + "!" + s.name
        if closestsymboladdr == addr or functionname:
            output += "\nExact matches:"
        return output
    elif args[0] == "u":
        output = ""
        try:
            addr = int(args[1], 16)
        except:
            lnoutput = dbgCommand("ln " + args[1])
            if "(" in lnoutput.lower():
                lineparts = lnoutput.split(")")
                address = lineparts[0].replace("(", "")
                addr = int(address, 16)
            else:
                return output
        try:
            length = int(args[2][1:], 16)
        except:
            length = int(args[3])
        disasminstr = x64dbg.DISASM_INSTR()
        while length > 0:
            x64dbg.DbgDisasmAt(addr, disasminstr)
            instrsize = disasminstr.instr_size
            instrbytes = ''.join('%02x' % ord(c) for c in loadBytes(addr, instrsize))
            output += "\n%0.8x %-15s %s\n" % (addr, instrbytes, disasminstr.instruction)
            addr += instrsize
            length -= 1
        return output
    elif args[0] == "ub":
        output = ""
        addr = int(args[1], 16)
        length = int(args[2][1:], 16)
        disasminstr = x64dbg.DISASM_INSTR()
        deq = deque() # stores the base addresses of the found instructions
        deq.append(addr)
        banned = {}
        banned[addr] = []
        # loop end is just a guess, observed closer results to windbg
        while len(deq) < (2 * length + 2):
            x64dbg.DbgDisasmAt(addr, disasminstr)
            endaddr = addr + disasminstr.instr_size
            # check if instruction expands till another base address
            if endaddr in deq and addr not in banned[endaddr]:
                # remove base addresses if already covered by this instruction
                while deq[-1] != endaddr:
                    deq.pop()
                deq.append(addr)
                banned[addr] = []
            elif deq[-1] - addr > 15:
                if len(deq) == 1:
                    return ""
                # base address too far away, won't find instruction, so
                # add to ban list for this end address
                bannedaddr = deq.pop()
                banned[deq[-1]].append(bannedaddr)
                addr = deq[-1]
            addr -= 1
        for i in range(length):
            output += "\n" + "%0.8x" % deq[length - i] + "\n"
        return output
    elif args[0] == "x":
        output = ""
        functionparts = args[1].split("!")
        shortname = functionparts[0]
        crit = functionparts[1]
        info = script.module.InfoFromName(shortname)
        modulename = info.name # get full name
        symbols = script.symbol.GetList()
        symbols = list(filter(lambda s: s.mod == modulename and fnmatch.fnmatch(s.name, crit), symbols))
        symbols = sorted(symbols, key=lambda x: x.rva)
        for s in symbols:
            output += "%0.8x%s%s!%s\n" % (info.base + s.rva, " " * 10, shortname, s.name)
        return output
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
        peb = typeStruct("_PEB", va)
        peb.Ldr = typePtr("_PEB_LDR_DATA*", va + archValue(0x000c, 0x0018))
        peb.ProcessParameters = typePtr("_RTL_USER_PROCESS_PARAMETERS*", va + archValue(0x0010, 0x0020))
        peb.NumberOfHeaps = typeInt32(va + archValue(0x0088, 0x00e8))
        peb.ProcessHeaps = typePtr("void**", va + archValue(0x0090, 0x00f0))
        peb.OSMajorVersion = typeInt16(va + archValue(0x00a4, 0x0118))
        peb.OSMinorVersion = typeInt16(va + archValue(0x00a8, 0x011c))
        peb.OSBuildNumber = typeInt8(va + archValue(0x00ac, 0x0120))
        return peb
    elif typename == "_PEB_LDR_DATA":
        ldr = typeStruct("_PEB_LDR_DATA", va)
        ldr.InLoadOrderModuleList = typeStruct("_LDR_DATA_TABLE_ENTRY", va + archValue(0x000c, 0x0010))
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
        start = va + archValue(0x0008, 0x0010)
        va = script.ReadPtr(start)
        result = []

        while va != start and len(result) < 50:
            entry = typeStruct("_LDR_DATA_TABLE_ENTRY", va)
            # This is actually _LDR_DATA_TABLE_ENTRY.FullDllName
            entry.BaseDllName = typeStruct("UNICODE_STRING", va + archValue(0x001c, 0x0038))
            result.append(entry)
            va = script.ReadPtr(va)

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
        return self.getAddress() + other

    def __radd__(self, other):
        return  other + self.getAddress()

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
    def __init__(self, typename = "void*", addr = 0):
        super(typePtr, self).__init__(typename, archValue(4, 8), addr)

    def deref(self):
        return typedVar(self.name[:-1], int(self))

class typeStruct(typeBase):
    def __init__(self, name, addr):
        super(typeStruct, self).__init__(name, 0, addr)

class memoryProtect(int):
    PageExecute = 16
    PageExecuteWriteCopy = 128
    PageReadOnly = 2
    PageReadWrite = 4
    PageExecuteRead = 32
    PageExecuteReadWrite = 64
    PageNoAccess = 1
    PageWriteCopy = 2

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