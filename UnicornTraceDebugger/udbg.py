from unicorn import *
from unicorn import arm_const
import sys
import hexdump
import capstone as cp

BPT_EXECUTE = 1
BPT_MEMREAD = 2
UDBG_MODE_ALL = 1
UDBG_MODE_FAST = 2



REG_ARM = {arm_const.UC_ARM_REG_R0: "R0",
           arm_const.UC_ARM_REG_R1: "R1",
           arm_const.UC_ARM_REG_R2: "R2",
           arm_const.UC_ARM_REG_R3: "R3",
           arm_const.UC_ARM_REG_R4: "R4",
           arm_const.UC_ARM_REG_R5: "R5",
           arm_const.UC_ARM_REG_R6: "R6",
           arm_const.UC_ARM_REG_R7: "R7",
           arm_const.UC_ARM_REG_R8: "R8",
           arm_const.UC_ARM_REG_R9: "R9",
           arm_const.UC_ARM_REG_R10: "R10",
           arm_const.UC_ARM_REG_R11: "R11",
           arm_const.UC_ARM_REG_R12: "R12",
           arm_const.UC_ARM_REG_R13: "R13",
           arm_const.UC_ARM_REG_R14: "R14",
           arm_const.UC_ARM_REG_R15: "R15",
           arm_const.UC_ARM_REG_PC: "PC",
           arm_const.UC_ARM_REG_SP: "SP",
           arm_const.UC_ARM_REG_LR: "LR"
           }

REG_TABLE = {UC_ARCH_ARM: REG_ARM}


def str2int(s):
    if s.startswith('0x') or s.startswith("0X"):
        return int(s[2:], 16)
    return int(s)


def advance_dump(data, base):
    PY3K = sys.version_info >= (3, 0)
    generator = hexdump.genchunks(data, 16)
    retstr = ''
    for addr, d in enumerate(generator):
        # 00000000:
        line = '%08X: ' % (base + addr * 16)
        # 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
        dumpstr = hexdump.dump(d)
        line += dumpstr[:8 * 3]
        if len(d) > 8:  # insert separator if needed
            line += ' ' + dumpstr[8 * 3:]
        # ................
        # calculate indentation, which may be different for the last line
        pad = 2
        if len(d) < 16:
            pad += 3 * (16 - len(d))
        if len(d) <= 8:
            pad += 1
        line += ' ' * pad

        for byte in d:
            # printable ASCII range 0x20 to 0x7E
            if not PY3K:
                byte = ord(byte)
            if 0x20 <= byte <= 0x7E:
                line += chr(byte)
            else:
                line += '.'
        retstr += line + '\n'
    return retstr


def _dbg_trace(mu, address, size, self):

    self._tracks.append(address)
    if not self._is_step and self._tmp_bpt == 0:
        if address not in self._list_bpt:
            return

    if self._tmp_bpt != address and self._tmp_bpt != 0:
        return

    return _dbg_trace_internal(mu, address, size, self)

def _dbg_memory(mu, access, address, length, value, self):
    pc = mu.reg_read(arm_const.UC_ARM_REG_PC)
    print ("memory error: pc: %x access: %x address: %x length: %x value: %x" %
                 (pc, access, address, length, value))
    #if pc == 0x268df00:
        #mu.mem_protect(pc, 0x1000, UC_PROT_ALL)
        #return False
    _dbg_trace_internal(mu, pc, 4, self)
    mu.emu_stop()
    return True

def _dbg_trace_internal(mu, address, size, self):

    self._is_step = False
    print ("======================= Registers =======================")
    self.dump_reg()
    print ("======================= Disassembly =====================")
    if size == 4:
        mode = 'arm'
    else:
        mode = 'thumb'
    self.dump_asm(address, size * self.dis_count, mode)

    while True:
        raw_command = input(">")
        if raw_command == '':
            raw_command = self._last_command
        self._last_command = raw_command
        command = []
        for c in raw_command.split(" "):
            if c != "":
                command.append(c)
        try:
            if command[0] == 'set':
                if command[1] == 'reg':# set reg regname value
                    self.write_reg(command[2], str2int(command[3]))
                elif command[1] == 'bpt':
                    self.add_bpt(str2int(command[2]))
                else:
                    print("[Debugger Error]command error see help.")

            elif command[0] == 's' or command[0] == 'step':
                # self._tmp_bpt = address + size
                self._tmp_bpt = 0
                self._is_step = True
                break
            elif command[0] == 'n' or command[0] == 'next':
                self._tmp_bpt = address + size
                self._is_step = False
                break

            elif command[0] == 'r' or command[0] == 'run':
                self._tmp_bpt = 0
                self._is_step = False
                break
            elif command[0] == 'dump':
                if len(command) >= 3:
                    nsize = str2int(command[2])
                else:
                    nsize = 4 * 16
                self.dump_mem(str2int(command[1]), nsize)
            elif command[0] == 'list':
                if command[1] == 'bpt':
                    self.list_bpt()
            elif command[0] == 'del':
                if command[1] == 'bpt':
                    self.del_bpt(str2int(command[2]))
            elif command[0]=='stop':
                exit(0)
            elif command[0] == 't':
                self._castone = self._capstone_thumb
                print ("======================= Disassembly =====================")
                self.dump_asm(address, size * self.dis_count)
            elif command[0] == 'a':
                self._castone = self._capstone_arm
                print ("======================= Disassembly =====================")
                self.dump_asm(address, size * self.dis_count)
            elif command[0] == 'f':
                print (" == recent ==")
                for i in self._tracks[-10:-1]:
                    print (self.sym_handler(i))
            else:
                print ("Command Not Found!")

        except:
            print("[Debugger Error]command error see help.")


class UnicornDebugger:
    def __init__(self, mu, mode = UDBG_MODE_ALL):
        self._tracks = []
        self._mu = mu
        self._arch = mu._arch
        self._mode = mu._mode
        self._list_bpt = []
        self._tmp_bpt = 0
        self._error = ''
        self._last_command = ''
        self.dis_count = 5
        self._is_step = False
        self.sym_handler = self._default_sym_handler
        self._capstone_arm = None
        self._capstone_thumb = None

        if self._arch != UC_ARCH_ARM:
            mu.emu_stop()
            raise RuntimeError("arch:%d is not supported! " % self._arch)

        if self._arch == UC_ARCH_ARM:
            capstone_arch = cp.CS_ARCH_ARM
        elif self._arch == UC_ARCH_ARM64:
            capstone_arch = cp.CS_ARCH_ARM64
        elif self._arch == UC_ARCH_X86:
            capstone_arch = cp.CS_ARCH_X86
        else:
            mu.emu_stop()
            raise RuntimeError("arch:%d is not supported! " % self._arch)

        if self._mode == UC_MODE_THUMB:
            capstone_mode = cp.CS_MODE_THUMB
        elif self._mode == UC_MODE_ARM:
            capstone_mode = cp.CS_MODE_ARM
        elif self._mode == UC_MODE_32:
            capstone_mode = cp.CS_MODE_32
        elif self._mode == UC_MODE_64:
            capstone_mode = cp.CS_MODE_64
        else:
            mu.emu_stop()
            raise RuntimeError("mode:%d is not supported! " % self._mode)

        self._capstone_thumb = cp.Cs(cp.CS_ARCH_ARM, cp.CS_MODE_THUMB)
        self._capstone_arm = cp.Cs(cp.CS_ARCH_ARM, cp.CS_MODE_ARM)

        self._capstone = self._capstone_thumb

        if mode == UDBG_MODE_ALL:
            mu.hook_add(UC_HOOK_CODE, _dbg_trace, self)

        mu.hook_add(UC_HOOK_MEM_UNMAPPED, _dbg_memory, self)
        mu.hook_add(UC_HOOK_MEM_FETCH_PROT, _dbg_memory, self)


        self._regs = REG_TABLE[self._arch]

    def dump_mem(self, addr, size):
        data = self._mu.mem_read(addr, size)
        print (advance_dump(data, addr))


    def dump_asm(self, addr, size, mode):
        if mode == 'arm':
            md = cp.Cs(cp.CS_ARCH_ARM, cp.CS_MODE_ARM)
        else:
            md = cp.Cs(cp.CS_ARCH_ARM, cp.CS_MODE_THUMB)

        code = self._mu.mem_read(addr, size)
        count = 0
        for ins in md.disasm(code, addr):
            if count >= self.dis_count:
                break
            print("%s:\t%s\t%s" % (self.sym_handler(ins.address), ins.mnemonic, ins.op_str))

    def dump_reg(self):
        result_format = ''
        count = 0
        for rid in self._regs:
            rname = self._regs[rid]
            value = self._mu.reg_read(rid)
            if count < 4:
                result_format = result_format  + rname + '=' + hex(value) + '\t\t\t'
                count += 1
            else:
                count = 0
                result_format += '\n' + rname + '=' + hex(value)
        print (result_format)

    def write_reg(self, reg_name, value):
        for rid in self._regs:
            rname = self._regs[rid]
            if rname == reg_name:
                self._mu.reg_write(rid, value)
                return
        print ("[Debugger Error] Reg not found:%s " % reg_name)



    def show_help(self):
        help_info = """
        # commands
        # set reg <regname> <value>
        # set bpt <addr>
        # n[ext]
        # s[etp]
        # r[un]
        # dump <addr> <size>
        # list bpt
        # del bpt <addr>
        # stop
        # a/t change arm/thumb
        # f show ins flow
        """
        print (help_info)

    def list_bpt(self):
        for idx in range(len(self._list_bpt)):
            print ("[%d] %s" % (idx, self.sym_handler(self._list_bpt[idx])))

    def add_bpt(self, addr):
        self._list_bpt.append(addr)

    def del_bpt(self, addr):
        self._list_bpt.remove(addr)

    def get_tracks(self):
        for i in self._tracks[-100:-1]:
            #print (self.sym_handler(i))
            pass
        return self._tracks

    def _default_sym_handler(self, address):
        return hex(address)

    def set_symbol_name_handler(self, handler):
        self.sym_handler = handler


