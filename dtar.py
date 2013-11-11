#!/usr/bin/env python
#
#  Support functions for dtar.
#
#  Author: Sean Reifschneider <jafo@jafo.ca>
#  Date: Sun Nov 10, 2013

import os
import sys
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import struct
import zlib
import json
import bsddb

import tarfp

default_blocks_size = 10240
default_blocks_file_size_max = 30 * 1000 * 1000


def make_seq_filename(sequence_id):
    '''Convert the sequence ID into a directory+file-name.

    The returned value is a directory joined to a file, name using
    `os.path.join()`.  The top level directory will have around 1296 entries
    in it, and files under it start off with a 1-byte filename, expanding
    to 2 when `sequence_id` is more than 1296, and 3 when`sequence_id`
    is more than 46656, etc...
    '''
    keyspace = '0123456789abcdefghijklmnopqrstuvwxyz'
    top_level_count = len(keyspace) ** 2

    def get_key(keyspace, n):
        nl = len(keyspace)
        first_loop = True
        s = ''
        while n or first_loop:
            s = keyspace[n % nl] + s
            n = int(n / nl)
            first_loop = False
        return s

    top_level_name = get_key(keyspace, sequence_id % top_level_count)
    filename = get_key(keyspace, int(sequence_id / top_level_count))

    return os.path.join(top_level_name, filename)


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
    def __init__(
            self, path, password,
            blocks_size=default_blocks_size,
            blocks_file_size_max=default_blocks_file_size_max):
        self.path = path
        self.password = password
        self.aes_key = PBKDF2(password, '', 32)
        self.blocks_map = None
        self.blocks_size = blocks_size
        self.blocks_file_size_max = blocks_file_size_max
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

    def have_active_brick(self):
        '''Do we have an active brick?'''
        return self.blocks_file is not None

    def new_brick(self):
        self.close_brick()

        self.current_brick = self.next_brick
        self.next_brick += 1
        self.save()

        brick_info = os.path.split(make_seq_filename(self.current_brick))

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


def filter_tar_file_body(
        input_file, input_length, output_file, block_storage, tar_header):
    file_hash = SHA256.new()
    while input_length:
        data = input_file.read(min(block_storage.blocks_size, input_length))
        input_length -= len(data)

        hashkey = gen_hashkey(data)
        if hashkey not in block_storage.blocks_map:
            if not block_storage.have_active_brick() or (
                    block_storage.blocks_file_size
                    and block_storage.blocks_file_size
                    > block_storage.blocks_file_size_max):
                block_storage.new_brick()
            block_storage.store_block(data)

        file_hash.update(data)

        output_file.write(hashkey)

    #  whole file hash
    hash_key = file_hash.digest() + struct.pack('!L', 0)
    output_file.write(hash_key)


def checksum_body_length(tar_header, blocks_size):
    blocks, block_leftover = divmod(tar_header.size, blocks_size)
    if block_leftover > 0:
        blocks += 1  # partial final block
    blocks += 1  # full file checksum
    return 36 * blocks


def size_of_padding(exiting_length):
    remainder = exiting_length % tarfp.BLOCKSIZE
    if remainder == 0:
        return 0
    return tarfp.BLOCKSIZE - remainder


def write_padding(fp, already_written):
    length = size_of_padding(already_written)
    if length:
        fp.write('\0' * length)


def read_padding(fp, already_read):
    padding_length = size_of_padding(already_read)
    if padding_length != 0:
        padding = fp.read(padding_length)
        if padding != '\0' * len(padding):
            raise ValueError(
                'Expecting NULs, got "%s"' % repr(padding[:32]))


def filter_tar(
        input_file, output_file, block_storage_path, password,
        blocks_size=default_blocks_size,
        blocks_file_size_max=default_blocks_file_size_max,
        verbose=False):
    block_storage = BlockStorage(
        block_storage_path, password, blocks_size, blocks_file_size_max)

    while True:
        try:
            tar_header = tarfp.TarInfo().fromfileobj(input_file)
        except tarfp.EOFHeaderError:
            break

        if verbose:
            sys.stderr.write(
                '%s size=%d\n' % (repr(tar_header), tar_header.size))

        if tar_header.size == 0:
            output_file.write(tar_header.tobuf())
            continue

        input_length = tar_header.size
        tar_header.size = checksum_body_length(
            tar_header, block_storage.blocks_size)
        output_file.write(tar_header.tobuf())

        filter_tar_file_body(
            input_file, input_length, output_file, block_storage, tar_header)

        read_padding(input_file, input_length)
        write_padding(output_file, tar_header.size)

    if block_storage.have_active_brick():
        block_storage.close_brick()


#  kept for reference for uuid and header information in the near term.
#import uuid
#class Dtar:
#    def __init__(self, path):
#        self.path = path
#
#    def create(self):
#        if os.path.exists(self.path):
#            raise ValueError('Path already exists')
#        os.mkdir(self.path)
#        self.header_filename = os.path.join(self.path, 'header')
#
#        self.header_fp = open(self.header_filename, 'wb')
#        self._write_header()
#
#    def index(self, name):
#        return DtarIndex(self, name)
#
#    def _write_header(self):
#        self.aes_iv = Random.new().read(16)
#        self.uuid = uuid.uuid1().bytes
#        self.header_fp.write('dtar1\000')
#        self.header_fp.write(self.aes_iv)
#        self.header_fp.write(self.uuid)
