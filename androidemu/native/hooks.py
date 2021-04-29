import logging

from androidemu.hooker import Hooker
from androidemu.native.memory import NativeMemory

from androidemu.java.helpers.native_method import native_method
from androidemu.utils import memory_helpers
from unicorn import arm_const
from unicorn import Uc

logger = logging.getLogger(__name__)


class NativeHooks:
    """
    :type memory NativeMemory
    :type modules Modules
    :type hooker Hooker
    """

    def __init__(self, emu, memory, modules, hooker):
        self._module_mgr = modules
        self._emu = emu
        self._memory = memory
        self.atexit = []

        modules.add_symbol_hook('__system_property_get', hooker.write_function(self.system_property_get) + 1)
        modules.add_symbol_hook('dlopen', hooker.write_function(self.mydlopen) + 1)
        modules.add_symbol_hook('pthread_create', hooker.write_function(self.pass_hook("pthread_create")) + 1)
        modules.add_symbol_hook('pthread_join', hooker.write_function(self.nop('pthread_join')) + 1)
        modules.add_symbol_hook('vfprintf', hooker.write_function(self.nop('vfprintf')) + 1)
        modules.add_symbol_hook('fprintf', hooker.write_function(self.pass_hook('fprintf')) + 1)
        modules.add_symbol_hook('cacheflush', hooker.write_function(self.pass_hook('cacheflush')) + 1)
        modules.add_symbol_hook('dladdr', hooker.write_function(self.dladdr) + 1)
        modules.add_symbol_hook('dlsym', hooker.write_function(self.dlsym) + 1)
        modules.add_symbol_hook('__android_log_print', hooker.write_function(self.__android_log_print) + 1)

        #memory
        modules.add_symbol_hook('malloc', hooker.write_function(self.malloc) + 1)
        modules.add_symbol_hook('free', hooker.write_function(self.free) + 1)
        modules.add_symbol_hook('calloc', hooker.write_function(self.calloc) + 1)

        # others
        modules.add_symbol_hook('dlerror', hooker.write_function(self.dlerror) + 1)

    def pass_hook(self, name):
        @native_method
        def nop_inside(emu, p1, p2, p3 ,p4):
            logger.info('Symbol hook not implemented %s passed %x %x %x %x' % (name, p1, p2, p3, p4))
        return nop_inside

    @native_method
    def calloc(self, mu, num, size):
        logger.info("calloc(%d,%d)", num, size)
        addr = self._memory.allocate(num * size)
        mu.mem_write(addr, bytes(num * size))
        return addr


    @native_method
    def dlerror(self, mu):
        logger.info("dlerror")
        data = 'dlerror handler...emu,...,'
        addr = self._memory.allocate(len(data))
        memory_helpers.write_utf8(mu, addr, data)
        return addr

    @native_method
    def malloc(self, mu, malloc_len):
        logger.info("malloc(%d)" % malloc_len)
        return self._memory.allocate(malloc_len)

    @native_method
    def free(self, mu, addr):
        logger.info("free")
        return 1

    @native_method
    def __android_log_print(self, uc, fmt, args):
        pass
        # logger.info(fmt % args)

    @native_method
    def dlsym(self, uc, handle, name_ptr):
        name = memory_helpers.read_utf8(uc, name_ptr)
        logger.debug("Called dlsym(0x%x, %s)" % (handle, name))


        for mod in self._module_mgr.modules:
            sym = mod.find_symbol(name)
            if sym != None:
                return sym.address

        lr = uc.reg_read(arm_const.UC_ARM_REG_LR)

        raise RuntimeError("dlsym(0x%x, %s) Not found lr:%x" % (handle, name, lr))
        uc.emu_stop()

            #if mod.base == handle:
            #    x = mod.find_symbol(name)
            #    return x.address

    @native_method
    def system_property_get(self, uc, name_ptr, buf_ptr):
        name = memory_helpers.read_utf8(uc, name_ptr)
        logger.debug("Called __system_property_get(%s, 0x%x)" % (name, buf_ptr))

        if name in self._emu.system_properties:
            memory_helpers.write_utf8(uc, buf_ptr, self._emu.system_properties[name])
        else:
            logger.warning('%s was not found in system_properties dictionary.' % name)
        #    raise ValueError('%s was not found in system_properties dictionary.' % name)

        return None

    @native_method
    def mydlopen(self, uc, path):
        path = memory_helpers.read_utf8(uc, path)
        logger.debug("Called dlopen(%s)" % path)
        for mod in self._module_mgr.modules:
            if mod.filename.split('/')[-1] == path.split('/')[-1]:
                return mod.base
            elif mod.filename.split('/')[-1] == path:
                return mod.base

        if path == 'liblog.so':
            return 0x4
        raise RuntimeError("[dlopen] %s was not loaded!" % path)

    @native_method
    def dladdr(self, uc, addr, info):
        infos = memory_helpers.read_uints(uc, info, 4)

        nm = self._emu.native_memory

        if addr == 0:
            addr = uc.reg_read(arm_const.UC_ARM_REG_PC)

        # isfind = False
        for mod in self._module_mgr.modules:
            if mod.base <= addr < mod.base + mod.size:
                dli_fname = nm.allocate(len(mod.filename) + 1)
                memory_helpers.write_utf8(uc, dli_fname, mod.filename + '\x00')
                memory_helpers.write_uints(uc, info, [dli_fname, mod.base, 0, 0])
                return 1


    def nop(self, name):
        @native_method
        def nop_inside(emu):
            raise NotImplementedError('Symbol hook not implemented %s' % name)
        return nop_inside
