#!/usr/bin/env python
#
#  Support functions for dtar.

__author__ = 'Sean Reifschneider <sean+opensource@realgo.com>'
__version__ = 'X.XX'
__copyright__ = 'Copyright (C) 2013 Sean Reifschneider, RealGo, Inc.'
__license__ = 'GPLv2'

import os
import sys
from Crypto import Random
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import struct
import zlib
import json
import bsddb
import uuid

import tarfp

default_blocks_size = 30000
default_brick_size_max = 30 * 1000 * 1000


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


class SequentialIV:
    '''An IV that can be incremented sequentially.
    This is used in the DTAR tar headers to prevent re-use of the IV for each
    file, but allow encrypting each file data-block separately.
    '''
    def __init__(self):
        self.base_iv = Random.new().read(16)
        self.sequence = 0

    def get_next_iv(self):
        next_value = struct.unpack('!Q', self.base_iv[-8:])[0] + self.sequence
        if next_value >= 1 << 64:
            next_value -= 1 << 64
        self.sequence += 1

        return self.base_iv[:-8] + struct.pack('!Q', next_value)


class BlockStorageDirectory:
    '''A block storage class that writes blocks to a directory.

    NOTE: This is not multi-process or multi-thread safe currently.
    '''
    def __init__(
            self, path, password,
            blocks_size=default_blocks_size,
            brick_size_max=default_brick_size_max):
        '''Create a block storage instance.

        :param path: Directory of block storage.
        :type path: str
        :param password: Encryption key.
        :type password: str
        :param blocks_size: Size of blocks in the storage.  Partial blocks
                may be smaller.  Defaults to `default_blocks_size.
        :type blocks_size: int
        :param brick_size_max: Size of the block storage files
                ("bricks").  The bricks will be split when they exceed this
                size.  Defaults to `default_brick_size_max`.
        :type brick_size_max: int
        '''
        self.path = path
        self.password = password
        self.aes_key = PBKDF2(password, '', 32)
        self.blocks_map = None
        self.blocks_size = blocks_size
        self.brick_size_max = brick_size_max
        self.prime_hash = PBKDF2(password, 'hash primer', 32)

        self._reset_brick()

        if not os.path.exists(path):
            os.mkdir(path)
            self.next_brick = 0
            self.uuid = str(uuid.uuid1())
            if len(self.uuid) != 36:
                raise ValueError(
                    'Expected 36 bytes of UUID, got %d' % len(self.uuid))

            self.save()
        else:
            self.load()

        self._open_blocks_map()

    def _reset_brick(self):
        '''Internal: Resets objects related to the blocks file.
        '''
        self.brick_file = None
        self.toc_file = None
        self.brick_size = None

    def save(self):
        '''Save the block storage status.
        This should be called regularly when the status of the block
        storage changes (new bricks created).
        '''
        filename = os.path.join(self.path, 'info')
        tmp_filename = filename + '.tmp'
        with open(tmp_filename, 'w') as fp:
            json.dump(
                {
                    'format_version': 1,
                    'next_brick': self.next_brick,
                    'uuid': self.uuid,
                }, fp)
        os.rename(tmp_filename, filename)

        if self.brick_file:
            self.brick_file.flush()
        if self.toc_file:
            self.toc_file.flush()
        if self.blocks_map:
            self.blocks_map.sync()

    def load(self):
        '''Load block storage information from disc.
        This loads the status from the block storage files and makes it
        ready for use.
        '''
        filename = os.path.join(self.path, 'info')
        with open(filename, 'r') as fp:
            data = json.load(fp)
            if data['format_version'] != 1:
                raise ValueError(
                    'Unsupported format "%s"' % data['format_version'])
            self.format_version = data['format_version']
            self.uuid = data['uuid']
            self.next_brick = data['next_brick']
        self._open_blocks_map()

    def _open_blocks_map(self):
        '''INTERNAL: Open the blocks map file.'''
        if self.blocks_map is None:
            filename = os.path.join(self.path, 'blocks_map')
            self.blocks_map = bsddb.hashopen(filename, 'c')

    def have_active_brick(self):
        '''Do we have an active brick?

        :returns: boolean -- Returns `True` if there is a brick open for
                writing.
        '''
        return self.brick_file is not None

    def gen_hashkey(self, block):
        '''Generate the hashkey for the specified block.
        A hashkey is the unique identifier for a block.  It consists of the
        64-byte binary SHA512 of the block data, followed by 4 bytes
        representing the block size, encoded in network format.

        :param block: The block to hash.
        :type block: str
        :returns: str -- The hashkey associated with this block data.
        '''
        hash = SHA512.new()
        hash.update(self.prime_hash)
        hash.update(block)
        return hash.digest() + struct.pack('!L', len(block))

    def encode_block(self, block, hashkey):
        '''Given a block, encode it in the block-file format.

        This takes a block, potentially compresses it, encrypts it, and
        creates a block header for storage in the brick.

        Header format:
            block magic number ("dt1z" for compressed+AWS or "dt1n" for
                    just AES)
            payload length (4 bytes encoded network-format)
            hashkey (64 bytes SHA512 hash, 4 bytes raw length)
        Payload format:
            crypto IV: 16 random bytes
            block: Encrypted and possibly encoded

        :param block: The block of data.
        :type block: str
        :param hashkey: The hashkey of the data block.
        :type hashkey: str
        :returns: (str,str) -- A tuple of the block header and payload data.
        '''
        block_magic = 'dt1n'
        compressed_block = zlib.compress(block)
        if len(compressed_block) < len(block):
            block = compressed_block
            block_magic = 'dt1z'

        crypto_iv = Random.new().read(16)
        crypto = AES.new(self.aes_key, AES.MODE_CBC, crypto_iv)

        padding_remainder = len(block) % 16
        if padding_remainder != 0:
            block += Random.new().read(16 - padding_remainder)
        block = crypto.encrypt(block)

        header = (block_magic + struct.pack('!L', len(block)) + hashkey)
        return header, crypto_iv + block

    def new_brick(self):
        '''Get a new brick for writing to.

        This closes the existing brick, if any, and opens a new one for
        writing to.
        '''
        self.close_brick()

        self.current_brick = self.next_brick
        self.next_brick += 1
        self.save()

        brick_info = os.path.split(make_seq_filename(self.current_brick))

        brick_directory = os.path.join(self.path, 'b-' + brick_info[0])
        if not os.path.exists(brick_directory):
            os.mkdir(brick_directory)
        brick_filename = os.path.join(
            brick_directory, 'dt_d-%s-%s' % brick_info)
        toc_filename = os.path.join(
            brick_directory, 'dt_t-%s-%s' % brick_info)

        self.brick_file = open(brick_filename, 'a')
        self.toc_file = open(toc_filename, 'a')
        self.brick_size = 0

    def close_brick(self):
        '''Close a brick and finalize it.

        Called when done with writing blocks to a brick.
        '''
        self.save()
        if self.brick_file:
            self.brick_file.close()
        if self.toc_file:
            self.toc_file.close()
        self._reset_brick()

    def store_block(self, block, hashkey=None):
        '''Store the given block in the current brick.

        If the block has already been stored to the BlockStorage, it is not
        written again.

        :param block: The data to store in the brick.
        :type block: str
        :param hashkey: (None) If specified, the hashkey for the block.
                If not specified, the hashkey is generated internally.
        :type hashkey: str
        '''
        if hashkey is None:
            hashkey = self.gen_hashkey(block)

        if hashkey in self.blocks_map:
            return
        self.blocks_map[hashkey] = '%d,%d' % (
            self.current_brick, self.brick_size)

        header, payload = self.encode_block(block, hashkey)

        self.toc_file.write(hashkey + struct.pack('!L', self.brick_size))
        self.brick_file.write(header)
        self.brick_file.write(payload)
        self.brick_size += len(header) + len(payload)

    def gen_index_header(self, sequential_iv):
        '''Format a DTAR index header.

        :param sequential_iv: The IV object to be used for this index.
        :type sequential_iv: str
        :returns: str -- DTAR index header

        Header format:
            block magic number ("dti1").
            uuid (36 bytes identifying the BlockStorage)
            base_iv (16 random bytes)
        '''
        return bytes('dti1' + self.uuid) + sequential_iv.base_iv


def filter_tar_file_body(
        input_file, input_length, output_file, block_storage):
    file_hash = SHA512.new()
    while input_length:
        data = input_file.read(min(block_storage.blocks_size, input_length))
        input_length -= len(data)

        hashkey = block_storage.gen_hashkey(data)
        if hashkey not in block_storage.blocks_map:
            if not block_storage.have_active_brick() or (
                    block_storage.brick_size
                    and block_storage.brick_size
                    > block_storage.brick_size_max):
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
    return 68 * blocks


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
        brick_size_max=default_brick_size_max,
        verbose=False):
    block_storage = BlockStorageDirectory(
        block_storage_path, password, blocks_size, brick_size_max)

    sequential_iv = SequentialIV()
    output_file.write(block_storage.gen_index_header(sequential_iv))

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
            input_file, input_length, output_file, block_storage)

        read_padding(input_file, input_length)
        write_padding(output_file, tar_header.size)

    if block_storage.have_active_brick():
        block_storage.close_brick()
