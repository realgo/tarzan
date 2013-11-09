import os
from Crypto import Random
from Crypto.Hash import SHA256
import uuid
import struct
import stat
import pwd
import grp


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


def get_username(id):
    try:
        return pwd.getpwuid(id).pw_name
    except KeyError:
        return ''


def get_groupname(id):
    try:
        return grp.getgrgid(id).gr_name
    except KeyError:
        return ''


class DtarFile:
    def __init__(self):
        pass

    def from_file(self, filename):
        self.filename = filename
        fst = os.stat(filename)
        self.mode = stat.S_IMODE(fst.st_mode)
        self.uid = fst.st_uid
        self.user_name = get_username(fst.st_uid)
        self.gid = fst.st_gid
        self.group_name = get_groupname(fst.st_gid)
        self.mtime = fst.st_mtime
        self.symlink = ''
        self.hardlink = ''

        if stat.S_ISDIR(fst.st_mode):
            self.file_type = 'd'
        elif stat.S_ISREG(fst.st_mode):
            self.file_type = '-'
        #elif stat.S_ISLNK(fst.st_mode):
        #    self.file_type = 'l'
        else:
            raise NotImplementedError(
                'Unable to handle file type %o' % stat.S_IFMT(fst.st_mode))

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
        s = '%s\0%o\0%d\0%s\0%d\0%s\0%d\0%s\0%s\0%s\0%s\0' % (
            self.file_type, self.mode, self.uid, self.user_name,
            self.gid, self.group_name, self.mtime, self.checksum,
            self.filename, self.symlink, self.hardlink)
        s = 'dtf1%s\0%s' % (struct.pack('!L', len(s)), s)
        return s

    def read_header(self, fp):
        prefix = fp.read(9)
        if prefix[:4] != 'dtf1' or prefix[8] != '\0':
            raise ValueError('Invalid File header: "%s"' % repr(prefix[:4]))

        header_length = struct.unpack('!L', prefix[4:8])[0]
        fields = fp.read(header_length).split('\0')

        self.file_type = fields[0]
        self.mode = int(fields[1], 8)
        self.uid = int(fields[2])
        self.user_name = fields[3]
        self.gid = int(fields[4])
        self.group_name = fields[5]
        self.mtime = int(fields[6])
        self.checksum = fields[7]
        self.filename = fields[8]
        self.symlink = fields[9]
        self.hardlink = fields[10]

        if self.symlink != '':
            raise NotImplementedError('Symlinks are not yet supported')
        if self.hardlink != '':
            raise NotImplementedError('Hardlinks are not yet supported')
