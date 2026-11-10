# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Abstraction of an SFTP file handle (for server mode).
"""

import os
from paramiko.sftp import SFTP_OP_UNSUPPORTED, SFTP_OK
from paramiko.util import ClosingContextManager


#: Handle may be used with ``read`` (``CMD_READ``).
HANDLE_READ = 0x01
#: Handle may be used with ``write`` (``CMD_WRITE``).
HANDLE_WRITE = 0x02
#: Handle may be used with ``stat`` (``CMD_FSTAT``).
HANDLE_FSTAT = 0x04
#: Handle may be used with ``chattr`` (``CMD_FSETSTAT``).
HANDLE_FSETSTAT = 0x08
#: A folder handle may be iterated with ``readdir`` (``CMD_READDIR``).
HANDLE_READDIR = 0x10
#: Handle may be used by the built-in ``check-file`` extended request.
HANDLE_CHECK_FILE = 0x20

#: Every operation a handle may be granted.
HANDLE_ALL = (
    HANDLE_READ
    | HANDLE_WRITE
    | HANDLE_FSTAT
    | HANDLE_FSETSTAT
    | HANDLE_READDIR
    | HANDLE_CHECK_FILE
)


class SFTPHandle(ClosingContextManager):
    """
    Abstract object representing a handle to an open file (or folder) in an
    SFTP server implementation.  Each handle has a string representation used
    by the client to refer to the underlying file.

    Server implementations can (and should) subclass SFTPHandle to implement
    features of a file handle, like `stat` or `chattr`.

    Instances of this class may be used as context managers.

    .. versionadded:: 5.2
        Trusted servers may optionally limit the operations a client may
        perform through a handle via `allow`, `deny`, and `allows`.  When no
        limit is configured, every operation is permitted exactly as in
        earlier versions, so existing `.SFTPServerInterface` subclasses remain
        compatible.
    """

    # operation capabilities documented on the class, so they are discoverable
    # as ``SFTPHandle.READ`` etc.
    READ = HANDLE_READ
    WRITE = HANDLE_WRITE
    FSTAT = HANDLE_FSTAT
    FSETSTAT = HANDLE_FSETSTAT
    READDIR = HANDLE_READDIR
    CHECK_FILE = HANDLE_CHECK_FILE
    ALL = HANDLE_ALL

    def __init__(self, flags=0):
        """
        Create a new file handle representing a local file being served over
        SFTP.  If ``flags`` is passed in, it's used to determine if the file
        is open in append mode.

        :param int flags: optional flags as passed to
            `.SFTPServerInterface.open`
        """
        self.__flags = flags
        self.__name = None
        # only for handles to folders:
        self.__files = {}
        self.__tell = None
        # ``None`` means the optional capability mechanism is not enabled and
        # every operation is allowed (the historical behavior).
        self.__allowed = None

    def allow(self, allowed):
        """
        Limit this handle to the given set of capabilities.

        The argument is a bitmask of the capability constants (``READ``,
        ``WRITE``, ``FSTAT``, ``FSETSTAT``, ``READDIR`` and/or
        ``CHECK_FILE``), or one of the convenience groups ``ALL``.  Once a
        limit has been set, only operations whose capability is included are
        accepted; the flags requested by the client when opening the file can
        never widen this server-approved scope.

        Subsequent calls replace the previous limit rather than adding to it.

        :param int allowed: bitmask of allowed capabilities.
        :return: this handle, so calls can be chained.
        :rtype: `.SFTPHandle`
        """
        self.__allowed = allowed & HANDLE_ALL
        return self

    def deny(self, denied):
        """
        Remove the given capabilities from those allowed on this handle.

        If no limit has been configured yet, every capability is treated as
        initially allowed, so this is equivalent to allowing
        ``SFTPHandle.ALL`` minus ``denied``.

        :param int denied: bitmask of capabilities to revoke.
        :return: this handle, so calls can be chained.
        :rtype: `.SFTPHandle`
        """
        if self.__allowed is None:
            self.__allowed = HANDLE_ALL
        self.__allowed &= ~denied
        return self

    def allows(self, capability):
        """
        Return ``True`` if ``capability`` (one of the capability constants) is
        permitted on this handle.

        Handles without a configured limit allow every capability so that
        servers which never opt into the mechanism keep their old behavior.
        """
        if self.__allowed is None:
            return True
        return bool(self.__allowed & capability & HANDLE_ALL)

    def close(self):
        """
        When a client closes a file, this method is called on the handle.
        Normally you would use this method to close the underlying OS level
        file object(s).

        The default implementation checks for attributes on ``self`` named
        ``readfile`` and/or ``writefile``, and if either or both are present,
        their ``close()`` methods are called.  This means that if you are
        using the default implementations of `read` and `write`, this
        method's default implementation should be fine also.
        """
        readfile = getattr(self, "readfile", None)
        if readfile is not None:
            readfile.close()
        writefile = getattr(self, "writefile", None)
        if writefile is not None:
            writefile.close()

    def read(self, offset, length):
        """
        Read up to ``length`` bytes from this file, starting at position
        ``offset``.  The offset may be a Python long, since SFTP allows it
        to be 64 bits.

        If the end of the file has been reached, this method may return an
        empty string to signify EOF, or it may also return ``SFTP_EOF``.

        The default implementation checks for an attribute on ``self`` named
        ``readfile``, and if present, performs the read operation on the Python
        file-like object found there.  (This is meant as a time saver for the
        common case where you are wrapping a Python file object.)

        :param offset: position in the file to start reading from.
        :param int length: number of bytes to attempt to read.
        :return: the `bytes` read, or an error code `int`.
        """
        readfile = getattr(self, "readfile", None)
        if readfile is None:
            return SFTP_OP_UNSUPPORTED
        try:
            if self.__tell is None:
                self.__tell = readfile.tell()
            if offset != self.__tell:
                readfile.seek(offset)
                self.__tell = offset
            data = readfile.read(length)
        except IOError as e:
            self.__tell = None
            return SFTPServer.convert_errno(e.errno)
        self.__tell += len(data)
        return data

    def write(self, offset, data):
        """
        Write ``data`` into this file at position ``offset``.  Extending the
        file past its original end is expected.  Unlike Python's normal
        ``write()`` methods, this method cannot do a partial write: it must
        write all of ``data`` or else return an error.

        The default implementation checks for an attribute on ``self`` named
        ``writefile``, and if present, performs the write operation on the
        Python file-like object found there.  The attribute is named
        differently from ``readfile`` to make it easy to implement read-only
        (or write-only) files, but if both attributes are present, they should
        refer to the same file.

        :param offset: position in the file to start reading from.
        :param bytes data: data to write into the file.
        :return: an SFTP error code like ``SFTP_OK``.
        """
        writefile = getattr(self, "writefile", None)
        if writefile is None:
            return SFTP_OP_UNSUPPORTED
        try:
            # in append mode, don't care about seeking
            if (self.__flags & os.O_APPEND) == 0:
                if self.__tell is None:
                    self.__tell = writefile.tell()
                if offset != self.__tell:
                    writefile.seek(offset)
                    self.__tell = offset
            writefile.write(data)
            writefile.flush()
        except IOError as e:
            self.__tell = None
            return SFTPServer.convert_errno(e.errno)
        if self.__tell is not None:
            self.__tell += len(data)
        return SFTP_OK

    def stat(self):
        """
        Return an `.SFTPAttributes` object referring to this open file, or an
        error code.  This is equivalent to `.SFTPServerInterface.stat`, except
        it's called on an open file instead of a path.

        :return:
            an attributes object for the given file, or an SFTP error code
            (like ``SFTP_PERMISSION_DENIED``).
        :rtype: `.SFTPAttributes` or error code
        """
        return SFTP_OP_UNSUPPORTED

    def chattr(self, attr):
        """
        Change the attributes of this file.  The ``attr`` object will contain
        only those fields provided by the client in its request, so you should
        check for the presence of fields before using them.

        :param .SFTPAttributes attr: the attributes to change on this file.
        :return: an `int` error code like ``SFTP_OK``.
        """
        return SFTP_OP_UNSUPPORTED

    # ...internals...

    def _set_files(self, files):
        """
        Used by the SFTP server code to cache a directory listing.  (In
        the SFTP protocol, listing a directory is a multi-stage process
        requiring a temporary handle.)
        """
        self.__files = files

    def _get_next_files(self):
        """
        Used by the SFTP server code to retrieve a cached directory
        listing.
        """
        fnlist = self.__files[:16]
        self.__files = self.__files[16:]
        return fnlist

    def _get_name(self):
        return self.__name

    def _set_name(self, name):
        self.__name = name


from paramiko.sftp_server import SFTPServer
