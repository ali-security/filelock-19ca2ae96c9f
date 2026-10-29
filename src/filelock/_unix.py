from __future__ import annotations

import os
import sys
from contextlib import suppress
from errno import ENOSYS
from typing import cast

from ._api import BaseFileLock

#: a flag to indicate if the fcntl API is available
has_fcntl = False
if sys.platform == "win32":  # pragma: win32 cover

    class UnixFileLock(BaseFileLock):
        """Uses the :func:`fcntl.flock` to hard lock the lock file on unix systems."""

        def _acquire(self) -> None:
            raise NotImplementedError

        def _release(self) -> None:
            raise NotImplementedError

else:  # pragma: win32 no cover
    try:
        import fcntl
    except ImportError:
        pass
    else:
        has_fcntl = True

    class UnixFileLock(BaseFileLock):
        """Uses the :func:`fcntl.flock` to hard lock the lock file on unix systems."""

        def _acquire(self) -> None:
            # No O_TRUNC: a contender that loses the flock must not truncate the holder's file, and neither may the
            # winner, since a file renamed or hard-linked to the lock path is indistinguishable from a lock file.
            # O_EXCL tells whether this attempt created the inode: only then does it get the explicit mode.
            open_flags = os.O_RDWR
            o_nofollow = getattr(os, "O_NOFOLLOW", None)
            if o_nofollow is not None:
                open_flags |= o_nofollow
            opened = self._open_lock_file(open_flags)
            if opened is None:
                return
            fd, created = opened
            if created:
                # Before the flock: a peer may win it first, and only the creator may set the mode. Outside the flock
                # handler below: an fchmod that answers ENOSYS says nothing about flock.
                try:
                    with suppress(PermissionError):  # This locked is not owned by this UID
                        os.fchmod(fd, self._context.mode)
                except BaseException:
                    os.close(fd)
                    raise
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exception:
                os.close(fd)
                if exception.errno == ENOSYS:  # NotImplemented error
                    msg = "FileSystem does not appear to support flock; user SoftFileLock instead"
                    raise NotImplementedError(msg) from exception
            else:
                self._context.lock_file_fd = fd

        def _open_lock_file(self, open_flags: int) -> tuple[int, bool] | None:
            try:
                return os.open(self.lock_file, open_flags | os.O_CREAT | os.O_EXCL, self._context.mode), True
            except FileExistsError:
                pass
            try:
                return os.open(self.lock_file, open_flags), False
            except FileNotFoundError:
                return None  # unlinked since the create attempt; let the retry loop start over

        def _release(self) -> None:
            # Do not remove the lockfile:
            #   https://github.com/tox-dev/py-filelock/issues/31
            #   https://stackoverflow.com/questions/17708885/flock-removing-locked-file-without-race-condition
            fd = cast(int, self._context.lock_file_fd)
            self._context.lock_file_fd = None
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


__all__ = [
    "has_fcntl",
    "UnixFileLock",
]
