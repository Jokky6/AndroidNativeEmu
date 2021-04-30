import logging
import sys

from unicorn import  UcError

from UnicornTraceDebugger import udbg
from androidemu.emulator import Emulator
from androidemu.java.helpers.native_method import native_method
from androidemu.utils import memory_helpers

logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
    )
logger = logging.getLogger(__name__)

@native_method
def __aeabi_memclr(mu, addr, size):
    print('__aeabi_memclr(%x,%d)' % (addr, size))
    # bytes作用: 输入数字创建n个00
    mu.mem_write(addr, bytes(size))

@native_method
def __aeabi_memcpy(mu, dist, source, size):
    print ('__aeabi_memcpy(%x,%x,%d)' % (dist, source, size))
    data = mu.mem_read(source, size)
    mu.mem_write(dist, bytes(data))

@native_method
def __aeabi_memset(mu,buffer,count,c):
    pass

@native_method
def sprintf(mu, buffer, format1, a1, a2):
    format1 = memory_helpers.read_utf8(mu, format1)
    if "x" in format1:
        result = format1 % (a1)
    else:
        result = format1 % (memory_helpers.read_utf8(mu, a1), memory_helpers.read_utf8(mu, a2))
    mu.mem_write(buffer, bytes((result + '\x00').encode('utf-8')))

if __name__ == "__main__":

    emulator = Emulator()

    emulator.modules.add_symbol_hook('__aeabi_memclr',emulator.hooker.write_function(__aeabi_memclr) + 1)
    emulator.modules.add_symbol_hook('__aeabi_memcpy', emulator.hooker.write_function(__aeabi_memcpy) + 1)
    emulator.modules.add_symbol_hook('__aeabi_memset', emulator.hooker.write_function(__aeabi_memset) + 1)
    emulator.modules.add_symbol_hook('sprintf',emulator.hooker.write_function(sprintf)+1)

    emulator.load_library(filename="example_binaries/libdl.so",do_init=False)
    emulator.load_library(filename="example_binaries/libc.so",do_init=False)
    emulator.load_library(filename="example_binaries/libm.so",do_init=False)
    emulator.load_library(filename="example_binaries/liblog.so",do_init=False)
    lib_module = emulator.load_library(filename="example/libroysue.so",do_init=False)

    dbg = udbg.UnicornDebugger(emulator.mu)

    try:
        s = emulator.call_symbol(lib_module, 'Java_com_roysue_easyso1_MainActivity_stringFromJNI',
                                 emulator.java_vm.jni_env.address_ptr,  # jnienv指针
                                 0)
        print(s)
    except UcError as e:
        list_tracks = dbg.get_tracks()
        for addr in list_tracks[-100:-1]:
            print(hex(addr - 0xcbc66000))
        print(e)
