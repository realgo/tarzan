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
from Crypto.Hash import SHA512, HMAC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import struct
import zlib
import json
import bsddb
import uuid
import argparse
import ConfigParser

import tarfp

default_blocks_size = 30000
default_brick_size_max = 30 * 1000 * 1000


class InvalidDTARInputError(Exception):
    '''General error with encrypted input.
    '''
    pass


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
        self.aes_key = PBKDF2(password, '', 32)
        self.blocks_map = None
        self.blocks_size = blocks_size
        self.brick_size_max = brick_size_max

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

    def gen_hashkey(self, block, hmac_digest):
        '''Generate the hashkey for the specified block.
        A hashkey is the unique identifier for a block.  It consists of the
        64-byte binary SHA512 of the block data, followed by 4 bytes
        representing the block size, encoded in network format.

        :param block: The block to hash.
        :type block: str
        :param hmac_digest: HMAC digest to mix into hash.
        :type hmac_digest: str
        :returns: str -- The hashkey associated with this block data.
        '''
        hash = SHA512.new()
        hash.update(block)
        hash.update(hmac_digest)

        return hash.digest() + struct.pack('!L', len(block))

    def encode_block(self, block, hashkey, hmac):
        '''Given a block, encode it in the block-file format.

        This takes a block, potentially compresses it, encrypts it, and
        creates a block header for storage in the brick.

        Header format:
            block magic number ("dt1z" for compressed+AWS or "dt1n" for
                    just AES)
            payload length (4 bytes encoded network-format)
            hashkey (64 bytes SHA512 hash of block and HMAC,
                    4 bytes raw length)
            hmac (64 bytes SHA512 data signature)
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

        header = (block_magic + struct.pack('!L', len(block)) + hashkey + hmac)
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

    def store_block(self, block, hashkey=None, hmac_digest=None):
        '''Store the given block in the current brick.

        If the block has already been stored to the BlockStorage, it is not
        written again.

        :param block: The data to store in the brick.
        :type block: str
        :param hashkey: (None) If specified, the hashkey for the block.
                If not specified, the hashkey is generated internally.
        :type hashkey: str
        :param hmac_digest: (None) If specified, the hmac_digest for the block.
                If not specified, the hashkey is generated internally.
        :type hmac_digest: str
        '''
        if hmac_digest is None:
            mac512 = HMAC.new(self.aes_key, digestmod=SHA512)
            mac512.update(block)
            hmac_digest = mac512.digest()

        if hashkey is None:
            hashkey = self.gen_hashkey(block, hmac_digest)
        header, payload = self.encode_block(block, hashkey, hmac_digest)

        if hashkey in self.blocks_map:
            return
        self.blocks_map[hashkey] = '%d,%d' % (
            self.current_brick, self.brick_size)

        self.toc_file.write(hashkey + struct.pack('!L', self.brick_size))
        self.brick_file.write(header)
        self.brick_file.write(payload)
        self.brick_size += len(header) + len(payload)


class EncryptIndexClass:
    '''Encrypt the tar-format index output.

    This acts like a file and takes the tar-format index file and encrypts
    it with HMAC message digests and a sequential series of IVs
    (initialized to be random).
    '''
    def __init__(self, fp, blockstore, verbose=False):
        '''
        :param fp: The file to write encrypted output to.
        :type fp: file
        :param blockstore: The output blockstore (provides the aes_key
                and UUID).
        :type blockstore: BlockStore
        :param verbose: Display verbose information about it.
        :type verbose: Boolean
        '''
        self.fp = fp
        self.blockstore = blockstore
        self.verbose = verbose
        self.block = ''
        self.split_size = 102400
        self.bytes_written = 0

        self.sequential_iv = SequentialIV()
        fp.write(self.format_index_header())

    def format_index_header(self):
        '''Format a DTAR index header.

        Header format:
            block magic number ("dti1").
            uuid (36 bytes identifying the BlockStorage)
            base_iv (16 random bytes)

        :returns: str -- DTAR index header
        '''
        if self.verbose:
            sys.stderr.write(
                'Formatting index header: uuid: "%s", base_iv: "%s"\n'
                % (self.blockstore.uuid, repr(self.sequential_iv.base_iv)))

        return bytes(
            'dti1' + self.blockstore.uuid) + self.sequential_iv.base_iv

    def format_payload_header(
            self, compressed, crypto_iv, block_hmac, length):
        '''Format a header for each block of payload.

        :param compressed: If true, the block is compressed.
        :type compressed: boolean
        :param crypto_iv: The IV for this block.
        :type crypto_iv: str
        :param block_hmac: The HMAC of the plaintext block.
        :type block_hmac: str
        :param length: Length of the compressed block.
        :type length: int

        :returns: str -- The block header.
        '''
        magic = 'dtbz' if compressed else 'dtb1'

        if self.verbose:
            sys.stderr.write(
                'Format payload header: magic: "%s", length: %d, '
                'crypto_iv: "%s" block_hmac: "%s"\n'
                % (magic, length, repr(crypto_iv), repr(block_hmac)))

        return magic + crypto_iv + block_hmac + struct.pack('!L', length)

    def flush(self):
        '''Flush the current buffered data.

        Takes the current buffer and writes it out as a dtar block.
        The block length is rounded to 16 bytes (required by AES),
        it is compressed (if that reduces the block) and encrypted,
        and the result is written out.  In the event of being called
        without a full remainder block, it is considered to be the last
        block and a short block with trailing NUL padding is written.

        :returns: str -- The block header.
        '''
        if self.verbose:
            sys.stderr.write('Flush\n')

        is_last_block = False if len(self.block) >= 16 else True
        if is_last_block:
            block_to_write = self.block
            self.block = None
        else:
            remainder = len(self.block) % 16
            block_to_write = self.block[:len(self.block) - remainder]
            self.block = self.block[len(self.block) - remainder:]

        compressed = False
        hmac_digest = '\0' * 64
        crypto_iv = self.sequential_iv.get_next_iv()

        mac512 = HMAC.new(self.blockstore.aes_key, digestmod=SHA512)
        mac512.update(block_to_write)
        hmac_digest = mac512.digest()

        compressed_block = zlib.compress(block_to_write)
        if len(compressed_block) < len(block_to_write):
            block_to_write = compressed_block
            compressed = True

        block_to_write += '\0' * (16 - (len(block_to_write) % 16))

        crypto = AES.new(self.blockstore.aes_key, AES.MODE_CBC, crypto_iv)
        block_to_write = crypto.encrypt(block_to_write)

        header = self.format_payload_header(
            compressed, crypto_iv, hmac_digest, len(block_to_write))

        self.fp.write(header)
        self.fp.write(block_to_write)
        self.fp.flush()

    def beginning_of_file(self):
        '''Notify us that a new file header is starting.

        This is so that we can nicely split the encryption blocks on the
        output.  If the output buffer is larger than `split_size`, the buffer
        is flushed.
        '''
        if self.verbose:
            sys.stderr.write('beginning_of_file\n')

        if len(self.block) >= self.split_size:
            self.flush()

    def write(self, data):
        '''Write a block of data.

        This data is written to an internal buffer, so that it can be
        collected into and blocked for output encryption, MACing, and
        compression.

        :param data: Data to be written.
        :type data: str

        :returns: str -- The block header.
        '''
        if self.verbose:
            sys.stderr.write('write(length=%d)\n' % len(data))

        self.bytes_written += len(data)
        if len(self.block) >= 2 * self.split_size:
            self.flush()
        self.block += data

    def close(self):
        '''Finalize the output.

        All buffered data is written, and a closing block is written.  This
        object is no longer usable after this.
        '''
        if self.verbose:
            sys.stderr.write('Close\n')

        trailing_padding = 10240 - (self.bytes_written % 10240)
        if trailing_padding == 0:
            trailing_padding = 10240
        self.write('\0' * trailing_padding)

        if len(self.block) < 16:
            self.flush()
        self.flush()

        crypto_iv = self.sequential_iv.get_next_iv()
        mac512 = HMAC.new(self.blockstore.aes_key, digestmod=SHA512)
        hmac_digest = mac512.digest()
        header = self.format_payload_header(
            False, crypto_iv, hmac_digest, 0)
        self.fp.write(header)

        self.fp.close()
        self.fp = None


class DecryptIndexClass:
    '''Decrypt the dtar format file.

    This acts like a file and reads the dtar-format encrypted index file
    and decrypts it.
    '''
    def __init__(self, fp, blockstore, verbose=False):
        '''
        :param fp: The file to read encrypted dtar index from.
        :type fp: file
        :param blockstore: The output blockstore (provides the aes_key
                and UUID).
        :type blockstore: BlockStore
        :param verbose: Display verbose information about it.
        :type verbose: Boolean
        '''
        self.fp = fp
        self.blockstore = blockstore
        self.buffer = ''
        self.verbose = verbose
        self.eof = False
        self.read_index_header()

    def read(self, length):
        '''Read data from the encrypted stream.

        :param length: Number of bytes of input to read.
        :type length: int
        :returns: str -- Data that was read.
        '''
        if self.verbose:
            sys.stderr.write(
                'read(length=%d), existing buffer: %d\n'
                % (length, len(self.buffer)))

        while length > len(self.buffer) and not self.eof:
            self.read_next_payload()

        data = self.buffer[:length]
        self.buffer = self.buffer[length:]
        return data

    def read_index_header(self):
        '''Read the index header at the beginning of the dtar file.

        See :py:func:`EncryptIndexClass::format_index_header` for the
        layout.'''
        data = self.fp.read(4 + 36 + 16)
        if data[:4] != 'dti1':
            raise ValueError('Invalid header, did not find "dti1"')
        self.uuid = data[4:40]
        self.base_iv = data[40:56]

        if self.verbose:
            sys.stderr.write(
                'dtar header: magic: "%s", uuid: "%s", base_iv: "%s"\n'
                % (data[:4], self.uuid, repr(self.base_iv)))

    def read_next_payload(self):
        '''Read the next block of payload.

        See :py:func:`EncryptIndexClass::format_payload_header` for the
        layout of the header.'''

        if self.verbose:
            sys.stderr.write('read_next_payload()\n')

        data = self.fp.read(4 + 16 + 64 + 4)
        if not data:
            raise EOFError()

        magic = data[:4]
        if self.verbose:
            sys.stderr.write('Payload magic: %s\n' % repr(magic))

        if magic not in ['dtbz', 'dtb1']:
            raise ValueError('Invalid payload, did not find magic number')
        crypto_iv = data[4:20]
        block_hmac = data[20:84]
        payload_length = struct.unpack('!L', data[84:88])[0]

        if self.verbose:
            sys.stderr.write(
                'Read header: crypto_iv: "%s", block_hmac: "%s", '
                'payload_length: %d\n'
                % (repr(crypto_iv), repr(block_hmac), payload_length))

        payload = self.fp.read(payload_length)
        crypto = AES.new(self.blockstore.aes_key, AES.MODE_CBC, crypto_iv)
        payload = crypto.decrypt(payload)
        if magic.endswith('z'):
            try:
                payload = zlib.decompress(payload)
            except zlib.error:
                raise InvalidDTARInputError(
                    'Unable to decompress payload (password problem?)')

        if self.verbose:
            sys.stderr.write('Decrypted length: %d\n' % len(payload))

        mac512 = HMAC.new(self.blockstore.aes_key, digestmod=SHA512)
        mac512.update(payload)
        resulting_hmac = mac512.digest()

        if resulting_hmac != block_hmac:
            raise InvalidDTARInputError(
                'Block HMAC did not match decrypted data')

        if payload_length == 0:
            self.eof = True

        self.buffer += payload


def filter_tar_file_body(
        input_file, input_length, output_file, block_storage, verbose=False):
    '''Format a header for each block of payload.

    :param input_file: Where to read the source file data.
    :type input_file: file
    :param input_length: Original file size in bytes.
    :type input_length: int
    :param output_file: Where to write the detached block output.
    :type output_file: file
    :param block_storage: Where to look-up duplicates and store block data.
    :type block_storage: BlockStorage
    '''
    file_hash = SHA512.new()
    while input_length:
        data = input_file.read(min(block_storage.blocks_size, input_length))
        input_length -= len(data)

        mac512 = HMAC.new(block_storage.aes_key, digestmod=SHA512)
        mac512.update(data)
        hmac_digest = mac512.digest()

        hashkey = block_storage.gen_hashkey(data, hmac_digest)
        if hashkey not in block_storage.blocks_map:
            if not block_storage.have_active_brick() or (
                    block_storage.brick_size
                    and block_storage.brick_size
                    > block_storage.brick_size_max):
                block_storage.new_brick()
            block_storage.store_block(
                data, hashkey=hashkey, hmac_digest=hmac_digest)

        file_hash.update(data)

        output_file.write(hashkey)

    #  whole file hash
    hash_key = file_hash.digest() + struct.pack('!L', 0)
    output_file.write(hash_key)


def checksum_body_length(tar_header, blocks_size):
    '''Calculate the length of a body of detached hashkeys.

    :param tar_header: Tar header object for this file, this is where it
            gets the size of the original block.
    :type tar_header: int
    :param blocks_size: Size of the BlockStorage block size, used to
            calculate how many blocks the file is split up into.
    :type blocks_size: int

    :returns: int -- Size of the hashkey-only body.
    '''
    blocks, block_leftover = divmod(tar_header.size, blocks_size)
    if block_leftover > 0:
        blocks += 1  # partial final block
    blocks += 1  # full file checksum
    return 68 * blocks


def size_of_padding(exiting_length):
    '''Figure out how many NULs of padding are needed for tar block.

    This takes a size and figures out how many bytes of padding
    need to be added to make it an even tar block size.

    :param existing_length: Size of data that needs to be padded.
    :type existing_length: int

    :returns: int -- Number of bytes to pad out the block.
    '''
    remainder = exiting_length % tarfp.BLOCKSIZE
    if remainder == 0:
        return 0
    return tarfp.BLOCKSIZE - remainder


def write_padding(fp, already_written):
    '''Write out tar padding blocks.

    :param fp: Where to write padding.
    :type fp: file
    :param already_written: Size of data already written.
    :type already_written: int
    '''
    length = size_of_padding(already_written)
    if length:
        fp.write('\0' * length)


def read_padding(fp, already_read):
    '''Read tar padding bytes and verify.

    Figure out how many bytes of padding are needed to end this tar
    block, read them from `fp` and verify that they are all NUL bytes.
    If they are not NUL, :py:exc:`ValueError` is raised.

    :param fp: File to read blocks from.
    :type fp: file
    :param already_read: Number of bytes already read.
    :type already_read: int

    :raises: :py:exc:`ValueError`
    '''
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
    '''Read a tar file from `input_file`, and filter it into a DTAR file
    that is written to `output_file`.

    :param input_file: Where to read tar file from.
    :type input_file: file
    :param output_file: Where to write the encrypted DTAR file.
    :type output_file: file
    :param block_storage_path: Directory to store detached blocks into.
    :type block_storage_path: str
    :param password: String used to encrypt data.  This can be a password
            or passphrase, or it can be a binary key.  Either way, it is
            passed through a KDF.
    :type password: str
    :param blocks_size: Size that input files are broken down into.
            Smaller sizes result in better deduplication, but at the cost
            of more storage and encryption overhead and more random IOPS
            for creating and reading.
    :type blocks_size: int
    :param brick_size_max: The blocks are collected into bricks of this
            size.  The bricks can be slightly larger than this, by up to
            `blocks_size` bytes plus the lock header size.
    :type brick_size_max: int
    :param verbose: (False) Display operation information to stderr if True.
    :type verbose: bool
    '''
    block_storage = BlockStorageDirectory(
        block_storage_path, password, blocks_size, brick_size_max)

    encrypted_output = EncryptIndexClass(output_file, block_storage, verbose)

    while True:
        if verbose:
            sys.stderr.write('filter_tar loop\n')

        try:
            tar_header = tarfp.TarInfo().fromfileobj(input_file)
        except tarfp.EOFHeaderError:
            if verbose:
                sys.stderr.write('Got tar EOF\n')
            break

        if verbose:
            filetype = tar_header_to_filetype(tar_header)
            sys.stderr.write('%s %-10s %s\n' % (
                filetype, tar_header.size, tar_header.path))

        encrypted_output.beginning_of_file()
        if tar_header.size == 0:
            encrypted_output.write(tar_header.tobuf())
            continue

        input_length = tar_header.size
        tar_header.size = checksum_body_length(
            tar_header, block_storage.blocks_size)
        encrypted_output.write(tar_header.tobuf())

        filter_tar_file_body(
            input_file, input_length, encrypted_output, block_storage)

        read_padding(input_file, input_length)
        write_padding(encrypted_output, tar_header.size)

    encrypted_output.close()
    if block_storage.have_active_brick():
        block_storage.close_brick()


def list_dtar(
        input_file, output_file, block_storage_path, password,
        blocks_size=default_blocks_size,
        brick_size_max=default_brick_size_max,
        verbose=False):
    '''Read a dtar and list the file entries that it contains.

    :param input_file: Where to read encrypted dtar file from.
    :type input_file: file
    :param output_file: Where to write the contents list.
    :type output_file: file
    :param block_storage_path: Directory to store detached blocks into.
    :type block_storage_path: str
    :param password: String used to encrypt data.  This can be a password
            or passphrase, or it can be a binary key.  Either way, it is
            passed through a KDF.
    :type password: str
    :param blocks_size: Size that input files are broken down into.
            Smaller sizes result in better deduplication, but at the cost
            of more storage and encryption overhead and more random IOPS
            for creating and reading.
    :type blocks_size: int
    :param brick_size_max: The blocks are collected into bricks of this
            size.  The bricks can be slightly larger than this, by up to
            `blocks_size` bytes plus the lock header size.
    :type brick_size_max: int
    :param verbose: (False) Display operation information to stderr if True.
    :type verbose: bool
    '''
    block_storage = BlockStorageDirectory(
        block_storage_path, password, blocks_size, brick_size_max)

    encrypted_input = DecryptIndexClass(input_file, block_storage)

    while True:
        try:
            tar_header = tarfp.TarInfo().fromfileobj(encrypted_input)
        except tarfp.EOFHeaderError:
            break

        filetype = tar_header_to_filetype(tar_header)
        output_file.write('%s %-10s %s\n' % (
            filetype, tar_header.size, tar_header.path))

        if tar_header.size > 0:
            bytes_to_read = tar_header.size + size_of_padding(tar_header.size)
            while bytes_to_read:
                block_size = min(bytes_to_read, 102400)
                bytes_to_read -= block_size
                encrypted_input.read(block_size)


def decrypt_dtar(
        input_file, output_file, block_storage_path, password,
        blocks_size=default_blocks_size,
        brick_size_max=default_brick_size_max,
        verbose=False):
    '''Read a dtar and list the file entries that it contains.

    :param input_file: Where to read encrypted dtar file from.
    :type input_file: file
    :param output_file: Where to write the contents list.
    :type output_file: file
    :param block_storage_path: Directory to store detached blocks into.
    :type block_storage_path: str
    :param password: String used to encrypt data.  This can be a password
            or passphrase, or it can be a binary key.  Either way, it is
            passed through a KDF.
    :type password: str
    :param blocks_size: Size that input files are broken down into.
            Smaller sizes result in better deduplication, but at the cost
            of more storage and encryption overhead and more random IOPS
            for creating and reading.
    :type blocks_size: int
    :param brick_size_max: The blocks are collected into bricks of this
            size.  The bricks can be slightly larger than this, by up to
            `blocks_size` bytes plus the lock header size.
    :type brick_size_max: int
    :param verbose: (False) Display operation information to stderr if True.
    :type verbose: bool
    '''
    block_storage = BlockStorageDirectory(
        block_storage_path, password, blocks_size, brick_size_max)

    encrypted_input = DecryptIndexClass(input_file, block_storage, verbose)

    while True:
        data = encrypted_input.read(10240)
        if not data:
            break
        output_file.write(data)


def load_config_file(filename):
    '''Load configuration data from a file.

    This uses ConfigParser to read a Windows INI-style configuration file
    that specifies default information.  Quietly returns an empty
    configuration database if file does not exist.

    :param filename: Path name of configuration file to read.
    :type filename: str

    :returns: dict -- Dictionary with configuration information.
    '''
    config = ConfigParser.SafeConfigParser()
    filename = os.path.expanduser(filename)
    if not os.path.exists(filename):
        return {}
    config.read(filename)

    data = {}
    if config.has_option('main', 'password'):
        data['password'] = config.get('main', 'password')
    if config.has_option('main', 'keyfile'):
        data['keyfile'] = config.get('main', 'keyfile')

    if data.get('keyfile') and data.get('password'):
        raise ValueError('Config file specifies both password and keyfile')

    return data


def parse_args():
    '''Process command-line arguments.

    :returns: :py:class:`argparse.Namespace` -- Parsed argument information.
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d', '--blockstore-directory',
        help='The directory to place the blockstore data in.')
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Display information about what actions are taken to stderr.')

    parser.add_argument(
        '-c', '--config-file', default='~/.dtarrc',
        help='The configuration file to use')

    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        '-P', '--password',
        help='Password specified on the command-line (may be seen by other '
        'users or processes on the same system)')
    group.add_argument(
        '-p', '--password-file',
        help='Read password from this file, stripping trailing whitespace')
    group.add_argument(
        '-k', '--key-file',
        help='Read binary key from file')

    subparsers = parser.add_subparsers(help='DTAR sub-commands')

    command_parser = subparsers.add_parser(
        'create',
        help='Create a dtar file, reading the original tar '
        'file from stdin and writing the dtar index to stdout.')
    command_parser.set_defaults(command='create')
    command_parser.add_argument(
        '-i', '--in', dest='in_file',
        help='File to read original tar file data from (default=stdin)')
    command_parser.add_argument(
        '-o', '--out', dest='out_file',
        help='File to write dtar output to (default=stdout)')

    command_parser = subparsers.add_parser(
        'decrypt',
        help='Take a dtar file and do a simple decryption of it.'
        '  This is mostly for debugging.')
    command_parser.set_defaults(command='decrypt')
    command_parser.add_argument(
        '-i', '--in', dest='in_file',
        help='File to read original tar file data from (default=stdin)')
    command_parser.add_argument(
        '-o', '--out', dest='out_file',
        help='File to write dtar output to (default=stdout)')

    command_parser = subparsers.add_parser(
        'list',
        help='List the files in a dtar index, writing a list to '
        'stdout.')
    command_parser.set_defaults(command='list')
    command_parser.add_argument(
        '-i', '--in', dest='in_file',
        help='File to read original tar file data from (default=stdin)')
    command_parser.add_argument(
        '-o', '--out', dest='out_file',
        help='File to write dtar output to (default=stdout)')

    command_parser = subparsers.add_parser(
        'extract',
        help='Reconstruct the original tar file, given a dtar '
        'index the results are written to stdout.')
    command_parser.set_defaults(command='extract')

    args = parser.parse_args()

    return args


def get_password(args):
    '''Select a password based in arguments.

    :param args: Parsed arguments to process.
    :type args: :py:class:`argparse.Namespace`

    :returns: str or None -- The password from arguments, if any.
    '''
    if args.password:
        return args.password

    if args.password_file:
        with open(args.password_file, 'r') as fp:
            return fp.readline().rstrip()

    if args.key_file:
        with open(args.key_file, 'r') as fp:
            return fp.read()


def tar_header_to_filetype(tar_header):
    '''Convert a tar header file type into a string.

    This is one character representing the file type, as with "ls -l".

    :param tar_header: Tar header to get file type information from.
    :type tar_header: Tar Header

    :returns: str -- File type string.
    '''
    filetype = '?'
    if tar_header.isreg():
        filetype = '-'
    if tar_header.isdir():
        filetype = 'd'
    if tar_header.isblk():
        filetype = 'b'
    if tar_header.ischr():
        filetype = 'c'
    if tar_header.islnk() or tar_header.issym():
        filetype = 'l'
    if tar_header.isfifo():
        filetype = 'p'

    return filetype


def error(msg):
    '''Write an error from the command-line client and exit.

    Exits with code 1, after writing the `msg` string and a dtar identifying
    prefix.  Message is written to stderr.

    :param msg: Message to write to the user.
    :type msg: str
    '''
    sys.stderr.write('%s: %s\n' % (os.path.basename(sys.argv[0]), msg))
    sys.exit(1)
