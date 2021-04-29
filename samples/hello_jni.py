import logging
import sys

from unicorn import  UcError

from UnicornTraceDebugger import udbg
from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def

logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
    )
logger = logging.getLogger(__name__)

class HelloJni(metaclass=JavaClassDef,jvm_name="com/example/hellojni/HelloJni"):
    def __init__(self):
        pass

    @java_method_def(name="stringFromJNI",signature='()Ljava/lang/String;', native=True)
    def string_from_jni(self,mu):
        pass

    def test(self):
        pass

if __name__ == "__main__":

    emulator = Emulator()
    emulator.java_classloader.add_class(HelloJni)
    emulator.load_library(filename="example_binaries/libdl.so",do_init=False)
    emulator.load_library(filename="example_binaries/libc.so",do_init=False)
    emulator.load_library(filename="example_binaries/libm.so",do_init=False)
    emulator.load_library(filename="example_binaries/liblog.so",do_init=False)
    lib_module = emulator.load_library(filename="example/libhello-jni.so",do_init=False)

    dbg = udbg.UnicornDebugger(emulator.mu)

    # Show loaded modules.
    logger.info("Loaded modules:")

    for module in emulator.modules:
        logger.info("=> 0x%08x - %s" % (module.base, module.filename))

    try:
        # Run JNI_OnLoad.
        #   JNI_OnLoad will call 'RegisterNatives'.
        emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)
        # Do native stuff.
        hello_jni = HelloJni()
        # logger.info("Response from JNI call: %s" % hello_jni.string_from_jni(emulator))

        # Dump natives found.

        # for method in HelloJni.jvm_methods.values():
        #     if method.native:
        #         logger.info("- [0x%08x] %s - %s" % (method.native_addr, method.name, method.signature))signature
    except UcError as e:
        list_tracks = dbg.get_tracks()
        for addr in list_tracks[-100:-1]:
            print(hex(addr - 0xcbc66000))
        print(e)
