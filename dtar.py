#!/usr/bin/env python

import os
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import uuid
import struct
import stat
import pwd
import grp
import zlib
import json
import bsddb


def gen_hashkey(block):
    '''Generate the hashkey for the specified block.
    A hashkey is the unique identifier for a block.  It consists of the
    32-byte binary SHA256 of the block data, followed by 4 bytes
    representing the block size, encoded in network format.
    '''
    hash = SHA256.new()
    hash.update(block)
    return hash.digest() + struct.pack('!L', len(block))


def encode_block(block, aes_key, hashkey=None):
    '''Given a block, encode it in the block-file format.

    If `hashkey` is not specified, one is generated.

    Header format:
        block magic number ("dt1z" for compressed+AWS or "dt1n" for just AES)
        payload length (4 bytes encoded network-format)
        hashkey (32 bytes SHA256 hash, 4 bytes raw length)
    Payload format:
        crypto IV: 16 random bytes
        block: Encrypted and possibly encoded

    Returns: Tuple of block header and payload
    '''
    block_magic = 'dt1n'
    compressed_block = zlib.compress(block)
    if len(compressed_block) < len(block):
        block = compressed_block
        block_magic = 'dt1z'

    if hashkey is None:
        hashkey = gen_hashkey(block)

    crypto_iv = Random.new().read(16)
    crypto = AES.new(aes_key, AES.MODE_CBC, crypto_iv)

    padding_remainder = len(block) % 16
    if padding_remainder != 0:
        block += Random.new().read(16 - padding_remainder)
    block = crypto.encrypt(block)

    header = (block_magic + struct.pack('!L', len(block)) + hashkey)
    return header, crypto_iv + block


class BlockStorage:
    def __init__(self, path, password):
        self.path = path
        self.password = password
        self.aes_key = PBKDF2(password, '', 32)
        self.blocks_map = None
        self._reset_blocks_file()

        if not os.path.exists(path):
            os.mkdir(path)
            self.next_brick = 0
            self.save()
        else:
            self.load()

        self._open_blocks_map()

    def _reset_blocks_file(self):
        self.blocks_file = None
        self.toc_file = None
        self.blocks_file_size = None

    def save(self):
        filename = os.path.join(self.path, 'info')
        tmp_filename = filename + '.tmp'
        with open(tmp_filename, 'w') as fp:
            json.dump(
                {
                    'format_version': 1,
                    'next_brick': self.next_brick,
                }, fp)
        os.rename(tmp_filename, filename)

        if self.blocks_file:
            self.blocks_file.flush()
        if self.toc_file:
            self.toc_file.flush()
        if self.blocks_map:
            self.blocks_map.sync()

    def load(self):
        filename = os.path.join(self.path, 'info')
        with open(filename, 'r') as fp:
            data = json.load(fp)
            if data['format_version'] != 1:
                raise ValueError(
                    'Unsupported format "%s"' % data['format_version'])
            self.next_brick = data['next_brick']
        self._open_blocks_map()

    def _open_blocks_map(self):
        if self.blocks_map is None:
            filename = os.path.join(self.path, 'blocks_map')
            self.blocks_map = bsddb.hashopen(filename, 'c')

    def new_brick(self):
        self.close_brick()

        self.current_brick = self.next_brick
        self.next_brick += 1
        self.save()

        brick_info = os.path.split(_make_seq_filename(self.current_brick))

        brick_directory = os.path.join(self.path, 'b-' + brick_info[0])
        if not os.path.exists(brick_directory):
            os.mkdir(brick_directory)
        blocks_filename = os.path.join(
            brick_directory, 'dt_d-%s-%s' % brick_info)
        toc_filename = os.path.join(
            brick_directory, 'dt_t-%s-%s' % brick_info)

        self.blocks_file = open(blocks_filename, 'a')
        self.toc_file = open(toc_filename, 'a')
        self.blocks_file_size = 0

    def close_brick(self):
        self.save()
        if self.blocks_file:
            self.blocks_file.close()
        if self.toc_file:
            self.toc_file.close()
        self._reset_blocks_file()

    def store_block(self, block, hashkey=None):
        if hashkey is None:
            hashkey = gen_hashkey(block)

        if hashkey in self.blocks_map:
            return
        self.blocks_map[hashkey] = '%d,%d' % (
            self.current_brick, self.blocks_file_size)

        header, payload = encode_block(block, self.aes_key)

        self.toc_file.write(hashkey + struct.pack('!L', self.blocks_file_size))
        self.blocks_file.write(header)
        self.blocks_file_size += len(header)
        self.blocks_file.write(payload)
        self.blocks_file_size += len(payload)


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
        self.major_number = ''
        self.minor_number = ''

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
        s = '%s\0%o\0%d\0%s\0%d\0%s\0%d\0%s\0%s\0%s\0%s\0%s\0%s\0' % (
            self.file_type, self.mode, self.uid, self.user_name,
            self.gid, self.group_name, self.mtime, self.checksum,
            self.major_number, self.minor_number,
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
        self.major_number = fields[8]
        self.minor_number = fields[9]
        self.filename = fields[10]
        self.symlink = fields[11]
        self.hardlink = fields[12]

        if self.symlink != '':
            raise NotImplementedError('Symlinks are not yet supported')
        if self.hardlink != '':
            raise NotImplementedError('Hardlinks are not yet supported')
