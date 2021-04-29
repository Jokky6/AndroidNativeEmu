from unicorn import *
# from keystone import *
# 导入模拟器
from androidemu.emulator import Emulator
# 无名侠写的unicorn debug插件
from UnicornTraceDebugger import udbg
# 自实现native函数装饰器
from androidemu.java.helpers.native_method import native_method
# 读取内存中的字符串等功能
from androidemu.utils import memory_helpers
from androidemu.java.java_classloader import JavaClassDef
from androidemu.java.java_method_def import java_method_def

import logging
import sys

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
    pass


@native_method
def __aeabi_memcpy(mu, dist, source, size):
    print('__aeabi_memcpy(%x,%x,%d)' % (dist, source, size))
    data = mu.mem_read(source, size)
    mu.mem_write(dist, bytes(data))


@native_method
def sprintf(mu, buffer, format1, a1, a2):
    # 读取内存中的字符串
    format1 = memory_helpers.read_utf8(mu, format1)
    result = format1 % (memory_helpers.read_utf8(mu, a1), a2)
    # print("sprintf:%s" % result)
    mu.mem_write(buffer, bytes((result + '\x00').encode('utf-8')))


# 自实现java类
class com_sec_udemo_MainActivity(metaclass=JavaClassDef, jvm_name="com/sec/udemo/MainActivity"):
    def __init__(self):
        pass

    # 创建java方法
    @java_method_def(name='getSaltFromJava',
                     signature='(Ljava/lang/String;)Ljava/lang/String;',
                     native=False,
                     args_list=['jstring'])
    def getSaltFromJava(self, mu, str):
        # print('hello')
        return str.value.value + "salt.."
    # 注册Native方法
    @java_method_def(name='sign_lv4',
                     signature='(Ljava/lang/String;)Ljava/lang/String;',
                     native=True)
    def sign_lv4(self, mu):
        pass

if __name__ == "__main__":
    # 创建模拟器对象
    emulator = Emulator()

    # got hook 一定要在载入library之前设置， 由于框架实现不好需要自己写hook实现
    emulator.modules.add_symbol_hook('__aeabi_memclr',
                                     emulator.hooker.write_function(__aeabi_memclr) + 1)

    emulator.modules.add_symbol_hook('__aeabi_memcpy',
                                     emulator.hooker.write_function(__aeabi_memcpy) + 1)

    emulator.modules.add_symbol_hook('sprintf',
                                     emulator.hooker.write_function(sprintf) + 1)
    # 模拟器中注册Class
    emulator.java_classloader.add_class(com_sec_udemo_MainActivity)
    # 加载库 do_init 是否初始化 是否执行init_array里的函数，一般禁用掉，libc里init_array有很多系统调用，而这些调用没有实现
    # 在so中有自加密、自解密就要使用do_init， 抖音的so有字符串加密
    emulator.load_library('lib/libc.so', do_init=False)
    libmod = emulator.load_library('lib/libnative-lib.so', do_init=False)

    dbg = udbg.UnicornDebugger(emulator.mu)
    # CODE = B'NOP'
    # ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
    # encoding, count = ks.asm(CODE, as_bytes=True)
    try:
        print(libmod.base)
        obj = com_sec_udemo_MainActivity()
        # nop掉反调试
        emulator.mu.mem_write(libmod.base + 0xAA02, b'\x00\xBF\x00\xBF')
        emulator.mu.mem_write(libmod.base + 0xAA06, b'\x00\xBF\x00\xBF')
        # 调用JNI_OnLoad
        emulator.call_symbol(libmod, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0)
        # 实例对象调用Native，第一个参数需要传递模拟器对象
        result = obj.sign_lv4(emulator, '123')
        print("result is =>", result)
    except UcError as e:
        list_tracks = dbg.get_tracks()
        for addr in list_tracks[-100:-1]:
            print(hex(addr - 0xcbc66000))
        print(e)
