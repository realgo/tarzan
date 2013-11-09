import os
from Crypto import Random
from Crypto.Hash import SHA256
import uuid
import struct


def _make_seq_filename(sequence_id):
    keyspace = '0123456789abcdefghijklmnopqrstuvwxyz'
    top_level_count = len(keyspace) ** 2

    def get_key(keyspace, n):
        nl = len(keyspace)
        first_loop = True
        s = ''
        while n or first_loop:
            s += keyspace[n % nl]
            n = int(n / nl)
            first_loop = False
        return s

    top_level_name = get_key(keyspace, sequence_id % top_level_count)
    filename = get_key(keyspace, int(sequence_id / top_level_count))

    return os.path.join(top_level_name, filename)


class Dtar:
    def __init__(self, path):
        self.path = path

    def create(self):
        if os.path.exists(self.path):
            raise ValueError('Path already exists')
        os.mkdir(self.path)
        self.header_filename = os.path.join(self.path, 'header')

        self.header_fp = open(self.header_filename, 'wb')
        self._write_header()

    def index(self, name):
        return DtarIndex(self, name)

    def _write_header(self):
        self.aes_iv = Random.new().read(16)
        self.uuid = uuid.uuid1().bytes
        self.header_fp.write('dtar1\000')
        self.header_fp.write(self.aes_iv)
        self.header_fp.write(self.uuid)


class DtarIndex:
    def __init__(self, dtar, name):
        self.dtar = dtar
        self.name = name
        self.index_filename = os.path.join(dtar.path, 'idx_%s' % name)

    def create(self):
        if os.path.exists(self.index_filename):
            raise ValueError('Index already exists')

        self.index_fp = open(self.index_filename, 'wb')
        self._write_header()

    def _write_header(self):
        self.header_fp.write('dtaridx1')


class DtarFile:
    def __init__(self):
        pass

    def from_file(self, filename):
        self.filename = filename
        stat = os.stat(filename)
        self.mode = stat.st_mode
        self.uid = stat.st_uid
        self.gid = stat.st_gid
        self.mtime = stat.st_mtime
        self.symlink = ''
        self.hardlink = ''

        self.checksum = ''
        hash = SHA256.new()
        with open(filename, 'rb') as fp:
            while True:
                data = fp.read(10240)
                if not data:
                    break
                hash.update(data)
            self.checksum = hash.hexdigest()

    def format_header(self):
        s = '%o\0%d\0%d\0%d\0%s\0%s\0%s\0%s\0' % (
            self.mode, self.uid, self.gid, self.mtime, self.checksum,
            self.symlink, self.hardlink, self.filename)
        s = 'dtf1%s\0%s' % (struct.pack('!L', len(s)), s)
        return s
