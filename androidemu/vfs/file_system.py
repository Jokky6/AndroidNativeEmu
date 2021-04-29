import logging
import os
import posixpath
import sys

from androidemu.config import WRITE_FSTAT_TIMES
from androidemu.cpu.syscall_handlers import SyscallHandlers
from androidemu.utils import memory_helpers
from androidemu.vfs import file_helpers

logger = logging.getLogger(__name__)
from androidemu.java.helpers.native_method import native_method

OVERRIDE_URANDOM = False
OVERRIDE_URANDOM_BYTE = b"\x00"



class VirtualFile:

    def __init__(self, name, file_descriptor, name_virt=None):
        self.name = name
        self.name_virt = name_virt
        self.descriptor = file_descriptor


class VirtualFileSystem:

    """
    :type syscall_handler SyscallHandlers
    """

    def __init__(self, root_path, emu, syscall_handler):
        self._root_path = root_path
        self._emu = emu

        # TODO: Improve fd logic.
        self._file_descriptor_counter = 3
        self._file_descriptors = dict()
        self._file_descriptors[0] = VirtualFile('stdin', 0)
        self._file_descriptors[1] = VirtualFile('stdout', 1)
        self._file_descriptors[2] = VirtualFile('stderr', 2)

        syscall_handler.set_handler(0x3, "read", 3, self._handle_read)
        syscall_handler.set_handler(0x4, "write", 3, self._handle_write)
        syscall_handler.set_handler(0x5, "open", 3, self._handle_open)
        syscall_handler.set_handler(0x6, "close", 1, self._handle_close)
        syscall_handler.set_handler(0x92, "writev", 3, self._handle_writev)
        syscall_handler.set_handler(0xC5, "fstat64", 2, self._handle_fstat64)
        syscall_handler.set_handler(0x142, "openat", 4, self._handle_openat)
        syscall_handler.set_handler(0x147, "fstatat64", 4, self._handle_fstatat64)
        syscall_handler.set_handler(0x14e, "faccessat", 4, self._faccessat)
        syscall_handler.set_handler(0x14d, "fchmodat", 4, self._fchmodat)
        syscall_handler.set_handler(0x8c, "_llseek", 5, self._llseek)
        syscall_handler.set_handler(0x13, "lseek", 3, self._lseek)
        syscall_handler.set_handler(0x143, "mkdirat", 3, self._mkdirat)

        # assert hook
        modules = self._emu.modules
        hooker = self._emu.hooker
        modules.add_symbol_hook('AAssetManager_fromJava', hooker.write_function(self.AAssetManager_fromJava) + 1)
        modules.add_symbol_hook('AAssetManager_open', hooker.write_function(self.AAssetManager_open) + 1)
        modules.add_symbol_hook('AAsset_close', hooker.write_function(self.AAsset_close) + 1)
        modules.add_symbol_hook('AAsset_getLength', hooker.write_function(self.AAsset_getLength) + 1)
        modules.add_symbol_hook('AAsset_read', hooker.write_function(self.AAsset_read) + 1)

        #libc hook
        # modules.add_symbol_hook('fopen', hooker.write_function(self.fopen) + 1)


    @native_method
    def fopen(self, mu, filename_ptr, mode):
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        mode = memory_helpers.read_utf8(mu, mode)
        logger.info("Call fopen(%s,%s)", filename, mode)


    @native_method
    def AAssetManager_fromJava(self, mu, env, assetManager):
        return 0x2233

    @native_method
    def AAssetManager_open(self, mu, mgr, filename_ptr, mode):
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        filename = "assert/" + filename

        logger.info("AAssetManager_open(%s,%d)" % (filename, mode))
        fd = self._open_file(filename, 0, mode)
        if fd == -1:
            fd = 0
        return fd

    @native_method
    def AAsset_close(self, mu, asset):
        return self._handle_close(mu, asset)

    @native_method
    def AAsset_getLength(self, mu, asset):
        fd = asset
        if fd <= 2:
            raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)

        if fd not in self._file_descriptors:
            # TODO: Return valid error.
            raise NotImplementedError()

        file = self._file_descriptors[fd]
        return os.path.getsize(file.name_virt)



    @native_method
    def AAsset_read(self, mu, aasset, buf, count):
        return self._handle_read(mu, aasset, buf, count)

    def _mkdirat(self, mu, dfd, name_ptr, mode):
        name = memory_helpers.read_utf8(mu, name_ptr)
        logger.info("mkdirat was called(%s) " % name)


    def _llseek(self, mu, fd, offset_high, offset_low, result, origin):

        if fd <= 2:
            raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)

        if fd not in self._file_descriptors:
            # TODO: Return valid error.
            raise NotImplementedError()

        file = self._file_descriptors[fd]
        os.lseek(file.descriptor, offset_low, origin)

    def _lseek(self, mu, fd, offset, ori):
        if fd <= 2:
            raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)

        if fd not in self._file_descriptors:
            # TODO: Return valid error.
            raise NotImplementedError()

        file = self._file_descriptors[fd]
        os.lseek(file.descriptor, offset, ori)

    def _handle_write(self, mu, fd, buffer, count):
        if fd <= 2:
            raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)

        if fd not in self._file_descriptors:
            # TODO: Return valid error.
            raise NotImplementedError()

        file = self._file_descriptors[fd]
        data = memory_helpers.read_byte_array(mu, buffer, count)
        return os.write(file.descriptor, data)

    def _fchmodat(self, mu, dirfd, pathname, mode, flag):
        pathname = memory_helpers.read_utf8(mu, pathname)
        logger.info("File faccessat '%s'" % pathname)
        pathname = self.translate_path(pathname)
        os.chmod(pathname, mode)
        return 0

    def _faccessat(self, mu, dirfd, pathname, mode, flags):
        pathname = memory_helpers.read_utf8(mu, pathname)
        logger.info("File faccessat '%s'" % pathname)
        pathname = self.translate_path(pathname)

        if mode == 0:
            if not os.path.exists(pathname):
                logger.warning('> File was not found.')
                return -1

        logger.warning('> File was found.')
        return 0

    def translate_path(self, filename):
        if filename.startswith("/"):
            filename = filename[1:]

        if os.name == 'nt':
            filename = filename.replace(':', '_')

        file_path = posixpath.join(self._root_path, filename)
        file_path = posixpath.normpath(file_path)

        if posixpath.commonpath([file_path, self._root_path]) != self._root_path:
            raise RuntimeError("Emulated binary tried to escape vfs jail.")

        return file_path

    def _store_fd(self, name, name_virt, file_descriptor):
        next_fd = self._file_descriptor_counter
        self._file_descriptor_counter += 1
        self._file_descriptors[next_fd] = VirtualFile(name, file_descriptor, name_virt=name_virt)
        return next_fd

    def _open_file(self, filename, flags, mode):
        # Special cases, such as /dev/urandom.
        orig_filename = filename

        if filename == '/dev/urandom':
            logger.info("File opened '%s'" % filename)
            return self._store_fd('/dev/urandom', None, 'urandom')

        file_path = self.translate_path(filename)

        if os.path.isfile(file_path):
            logger.info("File opened '%s'" % orig_filename)
            flags = os.O_RDWR
            if hasattr(os, "O_BINARY"):
                flags = os.O_BINARY
            return self._store_fd(orig_filename, file_path, os.open(file_path, flags=flags))
        elif os.path.exists(file_path):
            return 1
        else:
            logger.warning("File does not exist '%s'" % orig_filename)
            return -1

    def _handle_read(self, mu, fd, buf_addr, count):
        """
        ssize_t read(int fd, void *buf, size_t count);

        On files that support seeking, the read operation commences at the current file offset, and the file offset
        is incremented by the number of bytes read. If the current file offset is at or past the end of file,
        no bytes are read, and read() returns zero.

        If count is zero, read() may detect the errors described below. In the absence of any errors, or if read()
        does not check for errors, a read() with a count of 0 returns zero and has no other effects.

        If count is greater than SSIZE_MAX, the result is unspecified.
        """
        if fd <= 2:
            raise NotImplementedError("Unsupported read operation for file descriptor %d." % fd)

        if fd not in self._file_descriptors:
            # TODO: Return valid error.
            raise NotImplementedError()

        file = self._file_descriptors[fd]
        #if file.name == '/proc/self/maps':
            #logger.info("Reading %d bytes from '%s'" % (count, file.name))

        if file.descriptor == 'urandom':
            if OVERRIDE_URANDOM:
                buf = OVERRIDE_URANDOM_BYTE * count
            else:
                buf = os.urandom(count)
        else:
            buf = os.read(file.descriptor, count)

        result = len(buf)
        mu.mem_write(buf_addr, buf)
        return result

    def _handle_open(self, mu, filename_ptr, flags, mode):
        """
        int open(const char *pathname, int flags, mode_t mode);

        return the new file descriptor, or -1 if an error occurred (in which case, errno is set appropriately).
        """
        filename = memory_helpers.read_utf8(mu, filename_ptr)
        return self._open_file(filename, flags, mode)

    def _handle_close(self, mu, fd):
        """
        int close(int fd);

        close() closes a file descriptor, so that it no longer refers to any file and may be reused. Any record locks
        (see fcntl(2)) held on the file it was associated with, and owned by the process, are removed (regardless of
        the file descriptor that was used to obtain the lock).

        close() returns zero on success. On error, -1 is returned, and errno is set appropriately.
        """
        if fd not in self._file_descriptors:
            return 0

        file = self._file_descriptors[fd]

        if file.descriptor != 'urandom':
            logger.info("File closed '%s'" % file.name)
            os.close(file.descriptor)
        else:
            logger.info("File closed '%s'" % '/dev/urandom')

        return 0

    def _handle_writev(self, mu, fd, vec, vlen):
        if fd == 2:
            for i in range(0, vlen):
                addr = memory_helpers.read_ptr(mu, (i * 8) + vec)
                size = memory_helpers.read_ptr(mu, (i * 8) + vec + 4)
                sys.stderr.buffer.write(mu.mem_read(addr, size))

            return 0

        raise NotImplementedError()

    def _handle_fstat64(self, mu, fd, buf_ptr):
        """
        These functions return information about a file. No permissions are required on the file itself, but-in the
        case of stat() and lstat() - execute (search) permission is required on all of the directories in path that
        lead to the file.

        fstat() is identical to stat(), except that the file to be stat-ed is specified by the file descriptor fd.
        """
        if fd not in self._file_descriptors:
            return -1

        file = self._file_descriptors[fd]
        logger.info("File stat64 '%s'" % file.name)

        stat1 = os.fstat(file.descriptor)
        stat = file_helpers.stat64(file.name_virt,stat1)

        file_helpers.stat_to_memory(mu, buf_ptr, stat, WRITE_FSTAT_TIMES)

        return 0

    def _handle_openat(self, mu, dfd, filename_ptr, flags, mode):
        """
        int openat(int dirfd, const char *pathname, int flags, mode_t mode);

        On success, openat() returns a new file descriptor.
        On error, -1 is returned and errno is set to indicate the error.

        EBADF
            dirfd is not a valid file descriptor.
        ENOTDIR
            pathname is relative and dirfd is a file descriptor referring to a file other than a directory.
        """
        filename = memory_helpers.read_utf8(mu, filename_ptr)

        #if not filename.startswith("/") and dfd != 0:
        #    raise NotImplementedError("Directory file descriptor has not been implemented yet.")

        return self._open_file(filename, flags, mode)

    def _handle_fstatat64(self, mu, dirfd, pathname_ptr, buf, flags):
        """
        int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);

        If the pathname given in pathname is relative, then it is interpreted relative to the directory referred
        to by the file descriptor dirfd (rather than relative to the current working directory of the calling process,
        as is done by stat(2) for a relative pathname).

        If pathname is relative and dirfd is the special value AT_FDCWD,
        then pathname is interpreted relative to the current working directory of the calling process (like stat(2)).

        If pathname is absolute, then dirfd is ignored.

        flags can either be 0, or include one or more of the following flags ..

        On success, fstatat() returns 0. On error, -1 is returned and errno is set to indicate the error.
        """
        pathname = memory_helpers.read_utf8(mu, pathname_ptr)

        if not pathname.startswith('/'):
            raise NotImplementedError("Directory file descriptor has not been implemented yet.")

        if not flags == 0:
            if flags & 0x100:  # AT_SYMLINK_NOFOLLOW
                pass
            if flags & 0x800:  # AT_NO_AUTOMOUNT
                pass
            # raise NotImplementedError("Flags has not been implemented yet.")

        logger.info("File fstatat64 '%s'" % pathname)
        pathname = self.translate_path(pathname)

        if not os.path.exists(pathname):
            logger.warning('> File was not found.')
            return -1

        logger.warning('> File was found.')

        stat = file_helpers.stat64(path=pathname)
        # stat = os.stat(path=file_path, dir_fd=None, follow_symlinks=False)
        file_helpers.stat_to_memory(mu, buf, stat, WRITE_FSTAT_TIMES)

        return 0
