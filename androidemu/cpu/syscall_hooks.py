import math
import time
from random import randint

import hexdump
from unicorn import Uc
from unicorn.arm_const import *

from androidemu.const.android import *
from androidemu.const.linux import *
from androidemu.cpu.syscall_handlers import SyscallHandlers
import logging

log = logging.getLogger(__name__)

OVERRIDE_TIMEOFDAY = False
OVERRIDE_TIMEOFDAY_SEC = 0
OVERRIDE_TIMEOFDAY_USEC = 0

OVERRIDE_CLOCK = False
OVERRIDE_CLOCK_TIME = 0


class SyscallHooks:

    """
    :type mu Uc
    :type syscall_handler SyscallHandlers
    """
    def __init__(self, mu, syscall_handler):
        self._mu = mu
        self._syscall_handler = syscall_handler
        self._syscall_handler.set_handler(0x4E, "gettimeofday", 2, self._handle_gettimeofday)
        self._syscall_handler.set_handler(0xAC, "prctl", 5, self._handle_prctl)
        self._syscall_handler.set_handler(0xF0, "futex", 6, self._handle_futex)
        self._syscall_handler.set_handler(0x107, "clock_gettime", 2, self._handle_clock_gettime)
        self._syscall_handler.set_handler(0x119, "socket", 3, self._socket)
        self._syscall_handler.set_handler(0x11b, "connect", 3, self._connect)
        self._syscall_handler.set_handler(0x159, "getcpu", 3, self._getcpu)
        #self._syscall_handler.set_handler(0x14e, "faccessat", 4, self._faccessat)
        self._syscall_handler.set_handler(0x14, "getpid", 0, self._getpid)
        self._syscall_handler.set_handler(0xe0, "gettid", 0, self._gettid)
        self._syscall_handler.set_handler(0x180, "null1", 0, self._null)
        self._syscall_handler.set_handler(0x7e, "sigprocmask", 0, self._null)
        self._syscall_handler.set_handler(0xaf, "rt_sigprocmask", 0, self._null)
        self._syscall_handler.set_handler(0x10c, "sigaction", 0, self._tgkill)
        self._syscall_handler.set_handler(0x43, "sigaction", 0, self._sigaction)
        self._syscall_handler.set_handler(0xf8, "exit", 0, self._null)
        self._syscall_handler.set_handler(0x16e, "accept4", 0, self.accept4)



        self._clock_start = time.time()
        self._clock_offset = randint(1000, 2000)
    def accept4(self, mu):
        log.info("accept4")
        mu.emu_stop()
        return 0

    def _tgkill(self, mu):
        log.info("tgkill")
        return 1

    def _sigaction(self, mu):
        log.info("sigaction")
        return 0

    def _null(self, mu):
        return 0

    def _gettid(self, mu):
        return  0x2211

    def _getpid(self, mu):
        return 0x1122

    def _faccessat(self, mu, filename, pathname, mode, flag):
        return 0

    def _getcpu(self, mu, _cpu, node, cache):
        pc = mu.reg_read(UC_ARM_REG_PC)
        logging.info("getcpu pc:%x" % pc)
        if _cpu != 0:
            mu.mem_write(_cpu, int(0).to_bytes(4, byteorder='little'))
        return 0

    def _handle_gettimeofday(self, uc, tv, tz):
        """
        If either tv or tz is NULL, the corresponding structure is not set or returned.
        """

        if tv != 0:
            if OVERRIDE_TIMEOFDAY:
                uc.mem_write(tv + 0, int(OVERRIDE_TIMEOFDAY_SEC).to_bytes(4, byteorder='little'))
                uc.mem_write(tv + 4, int(OVERRIDE_TIMEOFDAY_USEC).to_bytes(4, byteorder='little'))
            else:
                timestamp = time.time()
                (usec, sec) = math.modf(timestamp)
                usec = abs(int(usec * 100000))

                uc.mem_write(tv + 0, int(sec).to_bytes(4, byteorder='little'))
                uc.mem_write(tv + 4, int(usec).to_bytes(4, byteorder='little'))

        if tz != 0:
            uc.mem_write(tz + 0, int(-120).to_bytes(4, byteorder='little'))  # minuteswest -(+GMT_HOURS) * 60
            uc.mem_write(tz + 4, int().to_bytes(4, byteorder='little'))  # dsttime

        return 0

    def _handle_prctl(self, mu, option, arg2, arg3, arg4, arg5):
        """
        int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
        See:
        - https://linux.die.net/man/2/prctl
        - https://github.com/torvalds/linux/blob/master/include/uapi/linux/prctl.h

        For PR_SET_VMA:
        - https://android.googlesource.com/platform/bionic/+/263325d/libc/include/sys/prctl.h
        - https://sourceforge.net/p/strace/mailman/message/34329772/
        """

        if option == PR_SET_VMA:
            # arg5 contains ptr to a name.
            return 0
        else:
            return 0
            raise NotImplementedError("Unsupported prctl option %d (0x%x)" % (option, option))

    def _handle_futex(self, mu, uaddr, op, val, timeout, uaddr2, val3):
        """
        See: https://linux.die.net/man/2/futex
        """

        if op & FUTEX_WAIT:
            raise NotImplementedError()
        elif op & FUTEX_WAKE:
            wakes_at_most = val
            return 0
        elif op & FUTEX_FD:
            raise NotImplementedError()
        elif op & FUTEX_REQUEUE:
            raise NotImplementedError()
        elif op & FUTEX_CMP_REQUEUE:
            raise NotImplementedError()

        return 0

    def _handle_clock_gettime(self, mu, clk_id, tp_ptr):
        """
        The functions clock_gettime() retrieve the time of the specified clock clk_id.

        The clk_id argument is the identifier of the particular clock on which to act. A clock may be system-wide and
        hence visible for all processes, or per-process if it measures time only within a single process.

        clock_gettime(), clock_settime() and clock_getres() return 0 for success, or -1 for failure (in which case
        errno is set appropriately).
        """

        if clk_id == CLOCK_MONOTONIC_COARSE:
            if OVERRIDE_CLOCK:
                mu.mem_write(tp_ptr + 0, int(OVERRIDE_CLOCK_TIME).to_bytes(4, byteorder='little'))
                mu.mem_write(tp_ptr + 4, int(0).to_bytes(4, byteorder='little'))
            else:
                clock_add = time.time() - self._clock_start  # Seconds passed since clock_start was set.

                mu.mem_write(tp_ptr + 0, int(self._clock_start + clock_add).to_bytes(4, byteorder='little'))
                mu.mem_write(tp_ptr + 4, int(0).to_bytes(4, byteorder='little'))
            return 0
        else:
            return -1
            raise NotImplementedError("Unsupported clk_id: %d (%x)" % (clk_id, clk_id))

    def _socket(self, mu, family, type_in, protocol):
        return -1
        # raise NotImplementedError()

    def _connect(self, mu, fd, addr, addr_len):
        print(hexdump.hexdump(mu.mem_read(addr, addr_len)))
        return -1
