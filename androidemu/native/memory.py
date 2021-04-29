from unicorn import Uc, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.native.memory_heap import UnicornSimpleHeap
from androidemu.utils.memory_helpers import hex_dump
from androidemu.utils import memory_helpers
class NativeMemory:

    """
    :type mu Uc
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, mu, memory_base, memory_size, syscall_handler, file_system):
        self._mu = mu
        self._file_system = file_system
        self._heap = UnicornSimpleHeap(mu, memory_base, memory_base + memory_size)
        self._memory_base = memory_base
        self._memory_current = memory_base
        self._memory_size = memory_size
        self._syscall_handler = syscall_handler
        self._syscall_handler.set_handler(0x5B, "munmap", 2, self._handle_munmap)
        self._syscall_handler.set_handler(0x7D, "mprotect", 3, self._handle_mprotect)
        self._syscall_handler.set_handler(0xC0, "mmap2", 6, self._handle_mmap2)
        self._syscall_handler.set_handler(0xDC, "madvise", 3, self._handle_madvise)

    def allocate(self, length, prot=UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC):
        prot = UC_PROT_ALL
        addr = self._heap.malloc(length, prot)
        # print ("allocate:%x size:%x" % (addr, length))
        return addr

    def _handle_munmap(self, uc, addr, len_in):
        # TODO: Use len_in
        return
        self._heap.free(addr)

    def _handle_mmap2(self, mu, addr, length, prot, flags, fd, offset):
        """
        void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
        """

        # MAP_FILE	    0
        # MAP_SHARED	0x01
        # MAP_PRIVATE	0x02
        # MAP_FIXED	    0x10
        # MAP_ANONYMOUS	0x20
        prot = UC_PROT_ALL
        addr = self._heap.malloc(length, prot)

        if fd != 0xffffffff:
            if fd <= 2:
                raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)

            if fd not in self._file_system._file_descriptors:
                # TODO: Return valid error.
                raise NotImplementedError()

            file = self._file_system._file_descriptors[fd]
            data = open(file.name_virt, 'rb').read(length)
            self._mu.mem_write(addr, data)
        return addr

    def _handle_madvise(self, mu, start, len_in, behavior):
        """
        int madvise(void *addr, size_t length, int advice);
        The kernel is free to ignore the advice.
        On success madvise() returns zero. On error, it returns -1 and errno is set appropriately.
        """
        # We don't need your advise.
        return 0

    def _handle_mprotect(self, mu, addr, len_in, prot):
        """
        int mprotect(void *addr, size_t len, int prot);

        mprotect() changes protection for the calling process's memory page(s) containing any part of the address
        range in the interval [addr, addr+len-1]. addr must be aligned to a page boundary.
        """
        #print(hex_dump(mu, addr, len_in))

        self._heap.protect(addr, len_in, prot)
        return 0

    def free(self, addr):
        self._heap.free(addr)
