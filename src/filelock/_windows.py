from __future__ import annotations

import os
import sys
from contextlib import suppress
from errno import EACCES
from functools import lru_cache
from pathlib import Path
from typing import cast

from ._api import BaseFileLock
from ._util import raise_on_not_writable_file

if sys.platform == "win32":  # pragma: win32 cover
    import ctypes
    import msvcrt
    from ctypes import wintypes

    # Windows API constants for reparse point detection
    FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF

    # Load kernel32.dll
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    _kernel32.GetFileAttributesW.restype = wintypes.DWORD

    def _is_reparse_point(path: str) -> bool:
        """
        Check if a path is a reparse point (symlink, junction, etc.) on Windows.

        :param path: Path to check
        :return: True if path is a reparse point, False otherwise
        :raises OSError: If GetFileAttributesW fails for reasons other than file-not-found
        """
        attrs = _kernel32.GetFileAttributesW(path)
        if attrs == INVALID_FILE_ATTRIBUTES:
            # File doesn't exist yet - that's fine, we'll create it
            err = ctypes.get_last_error()
            if err == 2:  # noqa: PLR2004  # ERROR_FILE_NOT_FOUND
                return False
            if err == 3:  # noqa: PLR2004 # ERROR_PATH_NOT_FOUND
                return False
            # Some other error - let caller handle it
            return False
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)

    # Windows API constants for creating the lock file with an owner-only DACL, matching what os.open passes to
    # CreateFileW for O_RDWR | O_CREAT | O_TRUNC
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _FILE_SHARE_READ_WRITE = 0x00000001 | 0x00000002  # FILE_SHARE_READ | FILE_SHARE_WRITE
    _CREATE_ALWAYS = 2
    _FILE_ATTRIBUTE_READONLY = 0x00000001
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _OWNER_WRITE = 0o200
    _GROUP_AND_OTHERS = 0o077
    # The DACL os.mkdir(mode=0o700) applies, less the inheritance flags a file has no use for: protected, so the
    # directory's inheritable entries stay out, with full access for SYSTEM, Administrators and the owner.
    _OWNER_ONLY_SDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)"
    _SDDL_REVISION_1 = 1

    class _SECURITY_ATTRIBUTES(ctypes.Structure):  # noqa: N801  # mirrors the Win32 struct name
        _fields_ = (
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        )

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.ULONG),
    ]
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    _kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SECURITY_ATTRIBUTES),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    _kernel32.CloseHandle.restype = wintypes.BOOL

    @lru_cache(maxsize=None)
    def _owner_only_descriptor() -> int:
        # Converted once and never freed: the lock retries the open every poll interval while it waits.
        descriptor = ctypes.c_void_p()
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            _OWNER_ONLY_SDDL,
            _SDDL_REVISION_1,
            ctypes.byref(descriptor),
            None,
        ):  # pragma: no cover  # a constant string converts
            raise ctypes.WinError(ctypes.get_last_error())
        return cast(int, descriptor.value)

    def _open_owner_only(path: str, mode: int) -> int:
        """
        Open or create *path* for locking as ``os.open(path, O_RDWR | O_CREAT | O_TRUNC, mode)`` does, except that a
        file this call creates gets an owner-only DACL instead of the entries its directory hands down.

        :param path: the lock file path.
        :param mode: the permission mode; as ``os.open`` does on Windows, a cleared owner-write bit creates the file
            read-only. Both the attribute and the DACL only take effect when the file is created, not when an existing
            one is opened.
        :return: a file descriptor owning the opened handle.
        :raises OSError: carrying the Windows error, so it maps to the same ``errno`` ``os.open`` would report.
        """
        flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
        if hasattr(sys, "audit"):  # pragma: no branch  # Python 3.8+
            # Emit the audit event os.open would, so consumers watching "open" still see the open and can veto.
            sys.audit("open", path, None, flags)
        security_attributes = _SECURITY_ATTRIBUTES()
        security_attributes.nLength = ctypes.sizeof(_SECURITY_ATTRIBUTES)
        security_attributes.lpSecurityDescriptor = _owner_only_descriptor()
        security_attributes.bInheritHandle = False  # os.open descriptors are non-inheritable
        attributes = _FILE_ATTRIBUTE_NORMAL if mode & _OWNER_WRITE else _FILE_ATTRIBUTE_READONLY
        handle = _kernel32.CreateFileW(
            path,
            _GENERIC_READ | _GENERIC_WRITE,
            _FILE_SHARE_READ_WRITE,
            ctypes.byref(security_attributes),
            _CREATE_ALWAYS,
            attributes,
            None,
        )
        if handle is None or handle == _INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            raise OSError(0, ctypes.FormatError(error), path, error)
        try:
            return msvcrt.open_osfhandle(handle, os.O_RDWR)
        except BaseException:  # pragma: no cover  # only on running out of descriptors
            _kernel32.CloseHandle(handle)
            raise

    class WindowsFileLock(BaseFileLock):
        """Uses the :func:`msvcrt.locking` function to hard lock the lock file on Windows systems."""

        def _acquire(self) -> None:
            raise_on_not_writable_file(self.lock_file)

            # Security check: Refuse to open reparse points (symlinks, junctions)
            # This prevents TOCTOU symlink attacks (CVE-TBD)
            if _is_reparse_point(self.lock_file):
                msg = f"Lock file is a reparse point (symlink/junction): {self.lock_file}"
                raise OSError(msg)

            flags = (
                os.O_RDWR  # open for read and write
                | os.O_CREAT  # create file if not exists
                | os.O_TRUNC  # truncate file if not empty
            )
            try:
                if self._context.mode & _GROUP_AND_OTHERS:
                    # Group and other bits have no Windows counterpart: the file gets the entries its directory hands
                    # down.
                    fd = os.open(self.lock_file, flags, self._context.mode)
                else:
                    # A mode without group and other bits creates the file with an owner-only DACL, so it does not
                    # pick up the access the directory grants other users.
                    fd = _open_owner_only(self.lock_file, self._context.mode)
            except OSError as exception:
                if exception.errno != EACCES:  # has no access to this lock
                    raise
            else:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                except OSError as exception:
                    os.close(fd)  # close file first
                    if exception.errno != EACCES:  # file is already locked
                        raise
                else:
                    self._context.lock_file_fd = fd

        def _release(self) -> None:
            fd = cast(int, self._context.lock_file_fd)
            self._context.lock_file_fd = None
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            os.close(fd)

            with suppress(OSError):  # Probably another instance of the application hat acquired the file lock.
                Path(self.lock_file).unlink()

else:  # pragma: win32 no cover

    class WindowsFileLock(BaseFileLock):
        """Uses the :func:`msvcrt.locking` function to hard lock the lock file on Windows systems."""

        def _acquire(self) -> None:
            raise NotImplementedError

        def _release(self) -> None:
            raise NotImplementedError


__all__ = [
    "WindowsFileLock",
]
