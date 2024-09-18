import os
import logging
import stat

from pyfuse3 import EntryAttributes
from crypt4gh import VERSION
from crypt4gh.lib import SEGMENT_SIZE, CIPHER_SEGMENT_SIZE, CIPHER_DIFF
from crypt4gh.header import MAGIC_NUMBER

LOG = logging.getLogger(__name__)

ENTRY_TIMEOUT = 300
ATTR_TIMEOUT = 300
HEADER_SIZE_HINT = None

def stat2entry(s):
    entry = EntryAttributes()
    for attr in ('st_ino', 'st_nlink', 'st_uid', 'st_gid',
                 'st_rdev', 'st_size', 'st_atime_ns', 'st_mtime_ns',
                 'st_ctime_ns'):
        setattr(entry, attr, getattr(s, attr))
    entry.generation = 0
    entry.entry_timeout = ENTRY_TIMEOUT
    entry.attr_timeout = ATTR_TIMEOUT
    entry.st_blksize = 512
    entry.st_blocks = ((entry.st_size+entry.st_blksize-1) // entry.st_blksize)
    entry.st_mode = s.st_mode & ~stat.S_IRWXO & ~stat.S_IRWXG # remove group and world access
    return entry

def _get_header_size(opath_fd):
    fd = os.open(f"/dev/fd/{opath_fd}", os.O_RDONLY)
    buf = bytearray(16)
    if os.readv(fd, [buf]) != 16:
        raise ValueError('Header too small')
    # Magic number, 8 bytes
    magic_number = bytes(buf[:8]) # 8 bytes
    if magic_number != MAGIC_NUMBER:
        raise ValueError('Not a CRYPT4GH formatted file')
    # Version, 4 bytes
    version = int.from_bytes(buf[8:12], byteorder='little')
    if version != VERSION: # only version 1, so far
        raise ValueError('Unsupported CRYPT4GH version')
    # Packets count
    packets_count = int.from_bytes(buf[12:16], byteorder='little')
    pos = 16
    # Jump over each packet
    pbuf = bytearray(4)
    for i in range(packets_count):
        os.lseek(fd, pos, os.SEEK_SET)
        os.readv(fd, [pbuf])
        pos += int.from_bytes(pbuf, byteorder='little') # include packet_len itself
    # os.lseek(fd, 0, os.SEEK_SET)
    # return os.read(fd, pos)
    os.close(fd)
    return pos


class Entry():
    __slots__ = ('refcount',
                 '_fd',
                 'parent_fd',
                 'underlying_name',
                 'display_name',
                 'extension',
                 'entry',
                 '_encrypted',
                 '_header_size')

    def __init__(self, parent_fd, underlying_name, s,
                 extension=None, header_size_hint=None, assume_same_size_headers: "bool" = True):
        self._fd = None
        self.refcount = 0
        self.parent_fd = parent_fd
        self.underlying_name = underlying_name
        self.display_name = underlying_name
        self.extension = extension
        self.entry = stat2entry(s)
        self._encrypted = None
        global HEADER_SIZE_HINT
        self._header_size = (HEADER_SIZE_HINT if assume_same_size_headers else None) or header_size_hint or None
        if stat.S_ISREG(s.st_mode) and self.is_c4gh():
            # correct the name
            if self.extension:
                self.display_name = self.underlying_name[:-len(self.extension)]
            # correct the size
            hlen = self.get_header_size()
            if assume_same_size_headers:
                HEADER_SIZE_HINT = hlen
            else:
                LOG.warning('Assuming different size headers might render directory listings slow')
            n_segments = self.entry.st_size // CIPHER_SEGMENT_SIZE;
            if self.entry.st_size % CIPHER_SEGMENT_SIZE != 0:
                n_segments += 1
            self.entry.st_size -= hlen + n_segments * CIPHER_DIFF

    def is_c4gh(self):
        if self._encrypted is None:
            self._encrypted = bool(self.extension and self.underlying_name.endswith(self.extension))
        return self._encrypted

    def get_header_size(self):
        if self._header_size is None:
            LOG.debug('Getting header size for %s', self.underlying_name)
            self._header_size = _get_header_size(self.fd)
            LOG.debug('Found header size: %s', self._header_size)
            self.close()
        return self._header_size


    def __repr__(self):
        encrypted = f" | C4GH | header {self.get_header_size()}" if self.is_c4gh() else ""
        return f'<Entry {self.display_name} refcount={self.refcount} fd={self._fd} ino={self.entry.st_ino}{encrypted}>'

    def encoded_name(self):
        return os.fsencode(self.display_name)

    @property
    def fd(self) -> "int":
        if self._fd is None:
            self.refcount = 1
            self._fd = os.open(self.underlying_name, os.O_PATH | os.O_NOFOLLOW, dir_fd=self.parent_fd)

        return self._fd

    def close(self, nlookup: "int" = 1):
        if self.refcount > 0:
            if nlookup < 0:
                self.refcount = 0
            else:
                self.refcount -= nlookup
        if self.refcount <= 0 and self._fd is not None and self._fd > 0:
            os.close(self._fd)
            self._fd = None

    def __del__(self):
        LOG.debug('Deleting %s', self)
        self.close(nlookup=-1)
