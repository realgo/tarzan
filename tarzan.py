#!/usr/bin/env python
#
#  Support functions for tarzan.

__author__ = 'Sean Reifschneider <sean+opensource@realgo.com>'
__version__ = 'X.XX'
__copyright__ = (
    'Copyright (C) 2013, 2014, 2015 Sean Reifschneider, RealGo, Inc.')
__license__ = 'GPLv2'

import os
import sys
from Crypto import __version__ as Crypto_version
from Crypto import Random
from Crypto.Hash import SHA512, HMAC
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import struct
import zlib
import json
import bsddb
import uuid
import argparse
import ConfigParser
import collections
import logging
import logging.handlers
try:
    from distutils.version import LooseVersion
except ImportError:
    print (
        'WARNING: Unable to check Crypto library version.  '
        'Install distutils.')
else:
    if LooseVersion(Crypto_version) < LooseVersion('2.6.1'):
        print (
            'WARNING: Python Crypto should be 2.6.1 or higher.'
            '  CVE-2013-1445')

import tarfp

rsa_key_length = 3072
aes_key_length = 16      # RSA of 3072 matches AES of 128
default_blocks_size = 30000
default_brick_size_max = 30 * 1000 * 1000

#  loggers
debug = logging.getLogger(__name__ + '.debug')
debug.addHandler(logging.NullHandler())
log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())
verbose = logging.getLogger(__name__ + '.verbose')
verbose.addHandler(logging.NullHandler())


class InvalidTarzanInputError(Exception):
    '''General error with encrypted input.
    '''
    pass


#  for python3 compatibility, even though tarzan isn't
if hasattr(__builtins__, 'FileExistsError'):
    FileExistsError = __builtins__.FileExistsError
else:
    class FileExistsError(IOError):
        pass


def hashkey_to_hex(s):
    len_length = struct.calcsize('!L')
    return '{0}:{1}'.format(
        ''.join(['{0:0>2x}'.format(ord(x)) for x in s[:-len_length]]),
        struct.unpack('!L', s[-len_length:])[0])


def short_hashkey_to_hex(s):
    s = hashkey_to_hex(s)
    return '{0}..{1}'.format(s[:9], s[119:])


def make_seq_filename(sequence_id):
    '''Convert the sequence ID into a directory+file-name.

    The returned value is a directory joined to a file, name using
    `os.path.join()`.  The top level directory will have around 1296 entries
    in it, and files under it start off with a 1-byte filename, expanding
    to 2 when `sequence_id` is more than 1296, and 3 when`sequence_id`
    is more than 46656, etc...

    :param sequence_id: The numeric sequence identifier of the brick.
    :type sequence_id: int
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

BrickFileInfo = collections.namedtuple(
    'BrickFileInfo', ['directory', 'brick', 'toc'])


class SequentialIV:
    '''An IV that can be incremented sequentially.
    This is used in the Tarzan tar headers to prevent re-use of the IV for
    each file, but allow encrypting each file data-block separately.
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

    hashkey_length = 64 + struct.calcsize('!L')

    def get_brick_file(self, sequence_id):
        '''Format the paths of brick components.

        Given a sequene, this returns a namedtuple that identifies the brick
        with these attributes (in tuple order):

            - directory -- The location of the directory the brick is in.
            - brick -- Full path of the brick file.
            - toc -- Full path of the TOC file.

        :param sequence_id: The numeric sequence identifier of the brick.
        :type sequence_id: int
        :returns: :py:class:`BrickFileInfo` -- Namedtuple of brick paths.
        '''
        brick_info = os.path.split(make_seq_filename(sequence_id))

        brick_directory = os.path.join(self.path, 'b-' + brick_info[0])
        if not os.path.exists(brick_directory):
            os.mkdir(brick_directory)
        brick_filename = os.path.join(
            brick_directory, 'dt_d-%s-%s' % brick_info)
        toc_filename = os.path.join(
            brick_directory, 'dt_t-%s-%s' % brick_info)

        return BrickFileInfo(brick_directory, brick_filename, toc_filename)

    def encode_block(self, block, hashkey, hmac):
        '''Given a block, encode it in the block-file format.

        This takes a block, potentially compresses it, encrypts it, and
        creates a block header for storage in the brick.

        Header format:
            block magic number ("dt1z" for compressed+AWS or "dt1n" for
                    just AES)
            payload length (4 bytes encoded network-format)
            decoded length (4 bytes encoded network-format)
            hashkey (64 bytes SHA512 hash of block and HMAC,
                    4 bytes raw length)
            hmac (64 bytes SHA512 data signature)
            crypto IV: 16 random bytes
        Payload format:
            block: Encrypted and possibly encoded

        :param block: The block of data.
        :type block: str
        :param hashkey: The hashkey of the data block.
        :type hashkey: str
        :returns: (str,str) -- A tuple of the block header and payload data.
        '''
        decoded_length = len(block)
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

        header = (
            block_magic + struct.pack('!L', len(block)) +
            struct.pack('!L', decoded_length) + hashkey
            + hmac + crypto_iv)
        return header, block

    def new_brick(self):
        '''Get a new brick for writing to.

        This closes the existing brick, if any, and opens a new one for
        writing to.
        '''
        self.close_brick()

        self.current_brick = self.next_brick
        self.next_brick += 1
        self.save()

        brick_info = self.get_brick_file(self.current_brick)
        self.brick_file = open(brick_info.brick, 'a')
        self.toc_file = open(brick_info.toc, 'a')
        self.brick_size = 0

        debug.error(
            'Opening new brick: %s', os.path.basename(brick_info.brick))

    def close_brick(self):
        '''Close a brick and finalize it.

        Called when done with writing blocks to a brick.
        '''
        self.save()
        if self.brick_file:
            debug.warning('Finalizing brick')
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
            debug.error(
                'Duplicate block found: %s', short_hashkey_to_hex(hashkey))
            return

        if not self.have_active_brick() or (
                self.brick_size and self.brick_size > self.brick_size_max):
            self.new_brick()

        self.blocks_map[hashkey] = '%d,%d' % (
            self.current_brick, self.brick_size)

        debug.warning('Storing block {0} to {1} at {2}'.format(
            short_hashkey_to_hex(hashkey), self.current_brick,
            self.brick_file.tell()))

        self.toc_file.write(hashkey + struct.pack('!L', self.brick_size))
        self.brick_file.write(header)
        debug.info('Header: %s', repr(header))
        self.brick_file.write(payload)
        debug.info('Payload: %s', repr(payload[:32]))
        self.brick_size += len(header) + len(payload)

    def retrieve_block(self, hashkey):
        '''Grab a block from storage.

        :param hashkey: (None) If specified, the hashkey for the block.
        :type hashkey: str
        :returns: str -- Block payload.
        '''
        location = self.blocks_map[hashkey]
        brick_id, offset = map(int, location.split(','))

        brick_info = self.get_brick_file(brick_id)

        with open(brick_info.brick, 'rb') as fp:
            debug.warning('Retrieving block {0} from {1} offset {2}'.format(
                short_hashkey_to_hex(hashkey), brick_id, offset))
            fp.seek(offset)
            header = fp.read(4 + 4 + 4 + 68 + 64 + 16)
            debug.info('Header: %s', repr(header))

            header_magic = header[:4]
            header_payload_length = struct.unpack('!L', header[4:8])[0]
            header_decoded_length = struct.unpack('!L', header[8:12])[0]
            header_hashkey = header[12:80]
            header_hmac = header[80:144]
            header_crypto_iv = header[144:]

            if header_magic not in ['dt1z', 'dt1n']:
                raise ValueError('Invalid hashkey in read block')
            if hashkey != header_hashkey:
                raise ValueError('Hash key in block does not match expected.')

            payload = fp.read(header_payload_length)
            debug.info('Payload: %s', repr(payload[:32]))
            payload = decode_payload(
                payload, self.aes_key,
                header_crypto_iv, header_hmac, header_magic,
                header_decoded_length)

            return payload


class BlockStorageDirectoryNoBrick:
    '''A block storage class that writes blocks to a directory.
    This version does not store files in bricks, it uses the block
    hash to just write individual files.  This is largely for testing
    of an S3 back-end.

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

    hashkey_length = 64 + struct.calcsize('!L')

    def get_brick_file(self, sequence_id):
        '''Format the paths of brick components.

        Given a sequene, this returns a namedtuple that identifies the brick
        with these attributes (in tuple order):

            - directory -- The location of the directory the brick is in.
            - brick -- Full path of the brick file.
            - toc -- Full path of the TOC file.

        :param sequence_id: The numeric sequence identifier of the brick.
        :type sequence_id: int
        :returns: :py:class:`BrickFileInfo` -- Namedtuple of brick paths.
        '''
        brick_info = os.path.split(make_seq_filename(sequence_id))

        brick_directory = os.path.join(self.path, 'b-' + brick_info[0])
        if not os.path.exists(brick_directory):
            os.mkdir(brick_directory)
        brick_filename = os.path.join(
            brick_directory, 'dt_d-%s-%s' % brick_info)
        toc_filename = os.path.join(
            brick_directory, 'dt_t-%s-%s' % brick_info)

        return BrickFileInfo(brick_directory, brick_filename, toc_filename)

    def encode_block(self, block, hashkey, hmac):
        '''Given a block, encode it in the block-file format.

        This takes a block, potentially compresses it, encrypts it, and
        creates a block header for storage in the brick.

        Header format:
            block magic number ("dt1z" for compressed+AWS or "dt1n" for
                    just AES)
            payload length (4 bytes encoded network-format)
            decoded length (4 bytes encoded network-format)
            hashkey (64 bytes SHA512 hash of block and HMAC,
                    4 bytes raw length)
            hmac (64 bytes SHA512 data signature)
            crypto IV: 16 random bytes
        Payload format:
            block: Encrypted and possibly encoded

        :param block: The block of data.
        :type block: str
        :param hashkey: The hashkey of the data block.
        :type hashkey: str
        :returns: (str,str) -- A tuple of the block header and payload data.
        '''
        decoded_length = len(block)
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

        header = (
            block_magic + struct.pack('!L', len(block)) +
            struct.pack('!L', decoded_length) + hashkey
            + hmac + crypto_iv)
        return header, block

    def new_brick(self):
        '''Get a new brick for writing to.

        This closes the existing brick, if any, and opens a new one for
        writing to.
        '''
        self.close_brick()

        self.current_brick = self.next_brick
        self.next_brick += 1
        self.save()

        brick_info = self.get_brick_file(self.current_brick)
        self.brick_file = open(brick_info.brick, 'a')
        self.toc_file = open(brick_info.toc, 'a')
        self.brick_size = 0

        debug.error(
            'Opening new brick: %s', os.path.basename(brick_info.brick))

    def close_brick(self):
        '''Close a brick and finalize it.

        Called when done with writing blocks to a brick.
        '''
        self.save()
        if self.brick_file:
            debug.warning('Finalizing brick')
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
            debug.error(
                'Duplicate block found: %s', short_hashkey_to_hex(hashkey))
            return

        if not self.have_active_brick() or (
                self.brick_size and self.brick_size > self.brick_size_max):
            self.new_brick()

        self.blocks_map[hashkey] = '%d,%d' % (
            self.current_brick, self.brick_size)

        debug.warning('Storing block {0} to {1} at {2}'.format(
            short_hashkey_to_hex(hashkey), self.current_brick,
            self.brick_file.tell()))

        self.toc_file.write(hashkey + struct.pack('!L', self.brick_size))
        self.brick_file.write(header)
        debug.info('Header: %s', repr(header))
        self.brick_file.write(payload)
        debug.info('Payload: %s', repr(payload[:32]))
        self.brick_size += len(header) + len(payload)

    def retrieve_block(self, hashkey):
        '''Grab a block from storage.

        :param hashkey: (None) If specified, the hashkey for the block.
        :type hashkey: str
        :returns: str -- Block payload.
        '''
        location = self.blocks_map[hashkey]
        brick_id, offset = map(int, location.split(','))

        brick_info = self.get_brick_file(brick_id)

        with open(brick_info.brick, 'rb') as fp:
            debug.warning('Retrieving block {0} from {1} offset {2}'.format(
                short_hashkey_to_hex(hashkey), brick_id, offset))
            fp.seek(offset)
            header = fp.read(4 + 4 + 4 + 68 + 64 + 16)
            debug.info('Header: %s', repr(header))

            header_magic = header[:4]
            header_payload_length = struct.unpack('!L', header[4:8])[0]
            header_decoded_length = struct.unpack('!L', header[8:12])[0]
            header_hashkey = header[12:80]
            header_hmac = header[80:144]
            header_crypto_iv = header[144:]

            if header_magic not in ['dt1z', 'dt1n']:
                raise ValueError('Invalid hashkey in read block')
            if hashkey != header_hashkey:
                raise ValueError('Hash key in block does not match expected.')

            payload = fp.read(header_payload_length)
            debug.info('Payload: %s', repr(payload[:32]))
            payload = decode_payload(
                payload, self.aes_key,
                header_crypto_iv, header_hmac, header_magic,
                header_decoded_length)

            return payload


class EncryptIndexClass:
    '''Encrypt the tar-format index output.

    This acts like a file and takes the tar-format index file and encrypts
    it with HMAC message digests and a sequential series of IVs
    (initialized to be random).
    '''
    def __init__(self, fp, blockstore):
        '''
        :param fp: The file to write encrypted output to.
        :type fp: file
        :param blockstore: The output blockstore (provides the aes_key
                and UUID).
        :type blockstore: BlockStore
        '''
        self.fp = fp
        self.blockstore = blockstore
        self.block = ''
        self.split_size = 102400
        self.bytes_written = 0

        self.sequential_iv = SequentialIV()
        fp.write(self.format_index_header())

    def format_index_header(self):
        '''Format a Tarzan index header.

        Header format:
            block magic number ("dti1").
            uuid (36 bytes identifying the BlockStorage)
            base_iv (16 random bytes)

        :returns: str -- Tarzan index header
        '''
        debug.warning(
            'Formatting index header: uuid: "%s", base_iv: "%s"',
            self.blockstore.uuid, repr(self.sequential_iv.base_iv))

        return bytes(
            'dti1' + self.blockstore.uuid) + self.sequential_iv.base_iv

    def format_payload_header(
            self, compressed, crypto_iv, block_hmac, length, decoded_length):
        '''Format a header for each block of payload.

        :param compressed: If true, the block is compressed.
        :type compressed: boolean
        :param crypto_iv: The IV for this block.
        :type crypto_iv: str
        :param block_hmac: The HMAC of the plaintext block.
        :type block_hmac: str
        :param length: Length of the compressed block.
        :type length: int
        :param decoded_length: Length of the original data block.
        :type decoded_length: int

        :returns: str -- The block header.
        '''
        magic = 'dtbz' if compressed else 'dtb1'

        debug.warning(
            'Format payload header: magic: "%s", length: %d, '
            'crypto_iv: "%s" block_hmac: "%s"',
            magic, length, repr(crypto_iv), repr(block_hmac))

        return (
            magic + crypto_iv + block_hmac + struct.pack('!L', length)
            + struct.pack('!L', decoded_length))

    def flush(self):
        '''Flush the current buffered data.

        Takes the current buffer and writes it out as a tarzan block.
        The block length is rounded to 16 bytes (required by AES),
        it is compressed (if that reduces the block) and encrypted,
        and the result is written out.  In the event of being called
        without a full remainder block, it is considered to be the last
        block and a short block with trailing NUL padding is written.

        :returns: str -- The block header.
        '''
        debug.info('EncryptIndexClass.flush()')

        is_last_block = False if len(self.block) >= 16 else True
        if is_last_block:
            block_to_write = self.block
            self.block = None
        else:
            remainder = len(self.block) % 16
            block_to_write = self.block[:len(self.block) - remainder]
            self.block = self.block[len(self.block) - remainder:]
        decoded_length = len(block_to_write)
        decoded_length = len(block_to_write)

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
            compressed, crypto_iv, hmac_digest, len(block_to_write),
            decoded_length)

        self.fp.write(header)
        self.fp.write(block_to_write)
        self.fp.flush()

    def beginning_of_file(self):
        '''Notify us that a new file header is starting.

        This is so that we can nicely split the encryption blocks on the
        output.  If the output buffer is larger than `split_size`, the buffer
        is flushed.
        '''
        debug.info('EncryptIndexClass.beginning_of_file()')

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
        debug.info('EncryptIndexClass.write(length=%d)', len(data))

        self.bytes_written += len(data)
        if len(self.block) >= 2 * self.split_size:
            self.flush()
        self.block += data

    def close(self):
        '''Finalize the output.

        All buffered data is written, and a closing block is written.  This
        object is no longer usable after this.
        '''
        debug.info('EncryptIndexClass.close()')

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
            False, crypto_iv, hmac_digest, 0, 0)
        self.fp.write(header)

        self.fp.close()
        self.fp = None


class DecryptIndexClass:
    '''Decrypt the tarzan format file.

    This acts like a file and reads the tarzan-format encrypted index file
    and decrypts it.
    '''
    def __init__(self, fp, blockstore):
        '''
        :param fp: The file to read encrypted tarzan index from.
        :type fp: file
        :param blockstore: The output blockstore (provides the aes_key
                and UUID).
        :type blockstore: BlockStore
        '''
        self.fp = fp
        self.blockstore = blockstore
        self.buffer = ''
        self.eof = False
        self.read_index_header()

    def read(self, length):
        '''Read data from the encrypted stream.

        :param length: Number of bytes of input to read.
        :type length: int
        :returns: str -- Data that was read.
        '''
        debug.info(
            'DecryptIndexClass.read(length=%d), existing buffer: %d',
            length, len(self.buffer))

        while length > len(self.buffer) and not self.eof:
            self.read_next_payload()

        data = self.buffer[:length]
        self.buffer = self.buffer[length:]
        return data

    def read_index_header(self):
        '''Read the index header at the beginning of the tarzan file.

        See :py:func:`EncryptIndexClass::format_index_header` for the
        layout.'''
        data = self.fp.read(4 + 36 + 16)
        if data[:4] != 'dti1':
            raise ValueError('Invalid header, did not find "dti1"')
        self.uuid = data[4:40]
        self.base_iv = data[40:56]

        debug.warning(
            'tarzan header: magic: "%s", uuid: "%s", base_iv: "%s"',
            data[:4], self.uuid, repr(self.base_iv))

    def read_next_payload(self):
        '''Read the next block of payload.

        See :py:func:`EncryptIndexClass::format_payload_header` for the
        layout of the header.'''

        debug.info('DecryptIndexClass.read_next_payload()')

        data = self.fp.read(4 + 16 + 64 + 4 + 4)
        if not data:
            raise EOFError()

        magic = data[:4]
        debug.warning('Payload magic: %s', repr(magic))

        if magic not in ['dtbz', 'dtb1']:
            raise ValueError('Invalid payload, did not find magic number')
        crypto_iv = data[4:20]
        block_hmac = data[20:84]
        payload_length = struct.unpack('!L', data[84:88])[0]
        decoded_length = struct.unpack('!L', data[88:92])[0]

        debug.warning(
            'Read header: crypto_iv: "%s", block_hmac: "%s", '
            'payload_length: %d',
            repr(crypto_iv), repr(block_hmac), payload_length)

        payload = decode_payload(
            self.fp.read(payload_length),
            self.blockstore.aes_key, crypto_iv, block_hmac, magic,
            decoded_length)

        if len(payload) == 0:
            self.eof = True

        self.buffer += payload


def decode_payload(
        payload, aes_key, crypto_iv, block_hmac, magic, decoded_length):
    crypto = AES.new(aes_key, AES.MODE_CBC, crypto_iv)
    payload = crypto.decrypt(payload)
    if magic.endswith('z'):
        try:
            payload = zlib.decompress(payload)
        except zlib.error:
            raise InvalidTarzanInputError(
                'Unable to decompress payload (password problem?)')

    if len(payload) != decoded_length:
        payload = payload[:decoded_length]

    mac512 = HMAC.new(aes_key, digestmod=SHA512)
    mac512.update(payload)
    debug.warning('MAC data length: %d', len(payload))
    resulting_hmac = mac512.digest()

    if resulting_hmac != block_hmac:
        raise InvalidTarzanInputError(
            'Block HMAC did not match decrypted data')

    return payload


def filter_tar_file_body(
        input_file, input_length, output_file, block_storage):
    '''Convert payload into detached blocks.

    :param input_file: Where to read the source file data.
    :type input_file: file
    :param input_length: Original file size in bytes.
    :type input_length: int
    :param output_file: Where to write the detached block output.
    :type output_file: file
    :param block_storage: Where to look-up duplicates and store block data.
    :type block_storage: BlockStorage
    '''
    output_file.write(struct.pack('!Q', input_length))

    file_hash = SHA512.new()
    while input_length:
        data = input_file.read(min(block_storage.blocks_size, input_length))
        input_length -= len(data)

        mac512 = HMAC.new(block_storage.aes_key, digestmod=SHA512)
        mac512.update(data)
        file_hash.update(data)
        debug.warning('MAC data length: %d', len(data))
        hmac_digest = mac512.digest()

        hashkey = block_storage.gen_hashkey(data, hmac_digest)
        output_file.write(hashkey)

        block_storage.store_block(
            data, hashkey=hashkey, hmac_digest=hmac_digest)

    #  whole file hash
    hash_key = file_hash.digest() + struct.pack('!L', 0)
    output_file.write(hash_key)


def filter_tarzan_file_body(
        input_file, input_length, output_file, block_storage):
    '''Reconstitute payload from detached blocks.

    :param input_file: Where to read the detached file data.
    :type input_file: file
    :param input_length: Detached file data in bytes.
    :type input_length: int
    :param output_file: Where to write the reconstituted block output.
    :type output_file: file
    :param block_storage: Where to lookup blocks.
    :type block_storage: BlockStorage
    '''
    file_hash = SHA512.new()
    while True:
        hashkey = input_file.read(block_storage.hashkey_length)
        input_length -= len(hashkey)

        #  0-length terminating block
        payload_length = struct.unpack('!L', hashkey[-4:])[0]
        if payload_length == 0:
            if hashkey[:64] != file_hash.digest():
                raise ValueError('Reconstituted file digest mismatch')
            break

        payload = block_storage.retrieve_block(hashkey)
        file_hash.update(payload)
        output_file.write(payload)


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
    return struct.calcsize('!Q') + (68 * blocks)


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
        brick_size_max=default_brick_size_max):
    '''Read a tar file from `input_file`, and filter it into a Tarzan file
    that is written to `output_file`.

    :param input_file: Where to read tar file from.
    :type input_file: file
    :param output_file: Where to write the encrypted Tarzan file.
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
    '''
    block_storage = BlockStorageDirectory(
        block_storage_path, password, blocks_size, brick_size_max)

    output_file = EncryptIndexClass(output_file, block_storage)

    while True:
        debug.info('filter_tar loop')

        try:
            tar_header = tarfp.TarInfo().fromfileobj(input_file)
        except tarfp.EOFHeaderError:
            debug.warning('Got tar EOF')
            break

        if verbose.isEnabledFor(logging.INFO):
            filetype = tar_header_to_filetype(tar_header)
            verbose.info('%s %-10s %s' % (
                filetype, tar_header.size, tar_header.path))

        output_file.beginning_of_file()
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

    output_file.close()
    if block_storage.have_active_brick():
        block_storage.close_brick()


def filter_tarzan(
        input_file, output_file, block_storage_path, password,
        blocks_size=default_blocks_size,
        brick_size_max=default_brick_size_max):
    '''Read a Tarzan, decrypt and re-attach the payload blocks to it.

    This reconstructs the original tar file, putitng the data blocks back in
    place after decrypting the Tarzan.

    :param input_file: Where to read tar file from.
    :type input_file: file
    :param output_file: Where to write the encrypted Tarzan file.
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
    '''
    block_storage = BlockStorageDirectoryNoBrick(
        block_storage_path, password, blocks_size, brick_size_max)

    input_file = DecryptIndexClass(input_file, block_storage)

    while True:
        debug.info('filter_tarzan loop')

        try:
            tar_header = tarfp.TarInfo().fromfileobj(input_file)
        except tarfp.EOFHeaderError:
            debug.warning('Got tar EOF')
            break

        if verbose.isEnabledFor(logging.INFO):
            filetype = tar_header_to_filetype(tar_header)
            verbose.info('%s %-10s %s' % (
                filetype, tar_header.size, tar_header.path))

        if tar_header.size == 0:
            output_file.write(tar_header.tobuf())
            continue

        original_length = struct.unpack('!Q', input_file.read(8))[0]

        input_length = tar_header.size
        tar_header.size = original_length
        output_file.write(tar_header.tobuf())

        filter_tarzan_file_body(
            input_file, input_length, output_file, block_storage)

        read_padding(input_file, input_length)
        write_padding(output_file, tar_header.size)

    output_file.flush()


def list_tarzan(
        input_file, output_file, block_storage_path, password,
        blocks_size=default_blocks_size,
        brick_size_max=default_brick_size_max):
    '''Read a tarzan and list the file entries that it contains.

    :param input_file: Where to read encrypted tarzan file from.
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
    '''
    block_storage = BlockStorageDirectory(
        block_storage_path, password, blocks_size, brick_size_max)

    input_file = DecryptIndexClass(input_file, block_storage)

    while True:
        try:
            tar_header = tarfp.TarInfo().fromfileobj(input_file)
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
                input_file.read(block_size)


def decrypt_tarzan(
        input_file, output_file, block_storage_path, password,
        blocks_size=default_blocks_size,
        brick_size_max=default_brick_size_max):
    '''Read a tarzan and list the file entries that it contains.

    :param input_file: Where to read encrypted tarzan file from.
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
    '''
    block_storage = BlockStorageDirectory(
        block_storage_path, password, blocks_size, brick_size_max)

    input_file = DecryptIndexClass(input_file, block_storage)

    while True:
        data = input_file.read(10240)
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
    if config.has_option('main', 'keyfile'):
        data['keyfile'] = config.get('main', 'keyfile')

    return data


def parse_args():
    '''Process command-line arguments.

    :returns: :py:class:`argparse.Namespace` -- Parsed argument information.
    '''
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-v', '--verbose', action='count',
        help='Display information about what actions are taken to stderr.')
    parser.add_argument(
        '--debug', action='count',
        help='Display information useful for debugging tarzan.')
    parser.add_argument(
        '--syslog', action='store_true',
        help='Write log information to syslog.')
    parser.add_argument(
        '-k', '--keyfile', default='~/.tarzan-key',
        help='Backup public/private key file')

    parser.add_argument(
        '-c', '--config-file', default='~/.tarzanrc',
        help='The configuration file to use')

    subparsers = parser.add_subparsers(help='Tarzan sub-commands')

    command_parser = subparsers.add_parser(
        'genkey',
        help='Generate a public/private key-pair for backups')
    command_parser.set_defaults(command='genkey')

    command_parser = subparsers.add_parser(
        'create',
        help='Create a tarzan file, reading the original tar '
        'file from stdin and writing the tarzan index to stdout.')
    command_parser.set_defaults(command='create')
    command_parser.add_argument(
        '-i', '--in', dest='in_file',
        help='File to read original tar file data from (default=stdin)')
    command_parser.add_argument(
        '-o', '--out', dest='out_file',
        help='File to write tarzan output to (default=stdout)')
    command_parser.add_argument(
        '-d', '--blockstore-directory', required=True,
        help='The directory to place the blockstore data in.')

    command_parser = subparsers.add_parser(
        'decrypt',
        help='Take a tarzan file and do a simple decryption of it.'
        '  This is mostly for debugging.')
    command_parser.set_defaults(command='decrypt')
    command_parser.add_argument(
        '-i', '--in', dest='in_file',
        help='File to read original tar file data from (default=stdin)')
    command_parser.add_argument(
        '-o', '--out', dest='out_file',
        help='File to write tarzan output to (default=stdout)')

    command_parser = subparsers.add_parser(
        'list',
        help='List the files in a tarzan index, writing a list to '
        'stdout.')
    command_parser.set_defaults(command='list')
    command_parser.add_argument(
        '-i', '--in', dest='in_file',
        help='File to read original tar file data from (default=stdin)')
    command_parser.add_argument(
        '-o', '--out', dest='out_file',
        help='File to write tarzan output to (default=stdout)')

    command_parser = subparsers.add_parser(
        'extract',
        help='Reconstruct the original tar file, given a tarzan '
        'index the results are written to stdout.')
    command_parser.set_defaults(command='extract')
    command_parser.add_argument(
        '-i', '--in', dest='in_file',
        help='File to read original tar file data from (default=stdin)')
    command_parser.add_argument(
        '-o', '--out', dest='out_file',
        help='File to write tarzan output to (default=stdout)')
    command_parser.add_argument(
        '-d', '--blockstore-directory', required=True,
        help='The directory to place the blockstore data in.')

    args = parser.parse_args()

    setup_logging(args.verbose, args.debug, args.syslog)

    return args


def setup_logging(verbose_level, debug_level, syslog=False):
    '''
    Configure the logging settings, particularly based on verbosity settings
    from the command-line argument processing.
    '''
    if verbose_level == 1:
        log.setLevel(logging.ERROR)
    elif verbose_level == 2:
        log.setLevel(logging.WARNING)
    elif verbose_level >= 3:
        log.setLevel(logging.INFO)
    else:
        log.setLevel(logging.CRITICAL)

    if syslog:
        log.addHandler(logging.handlers.SysLogHandler(address='/dev/log'))
    else:
        verbose_console = logging.StreamHandler()
        formatter = logging.Formatter('%(message)s')
        verbose_console.setFormatter(formatter)
        log.addHandler(verbose_console)

    if debug_level == 1:
        debug.setLevel(logging.ERROR)
    elif debug_level == 2:
        debug.setLevel(logging.WARNING)
    elif debug_level >= 3:
        debug.setLevel(logging.INFO)
    else:
        debug.setLevel(logging.CRITICAL)

    if verbose_level:
        verbose.setLevel(logging.INFO)
    else:
        verbose.setLevel(logging.CRITICAL)


def get_password(args):
    '''Select a password based on command-line arguments.

    :param args: Parsed arguments from comand-line.
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

    Exits with code 1, after writing the `msg` string and a tarzan identifying
    prefix.  Message is written to stderr.

    :param msg: Message to write to the user.
    :type msg: str
    '''
    sys.stderr.write('%s: %s\n' % (os.path.basename(sys.argv[0]), msg))
    sys.exit(1)


class TarzanPublicKey:
    '''Public-key management functions.

    This class manages the public/private keys for tarzan backups.
    '''

    def __init__(self, private_filename, public_filename=None):
        '''Creator.

        :param private_filename: Name of private key file.
        :type private_filename: str
        :param public_filename: (Optional) Name of public key file.  If not
                specified, the private key file name is used with ".pub"
                appended.
        :type public_filename: str
        '''
        self.private_filename = os.path.expanduser(private_filename)
        if not public_filename:
            public_filename = private_filename + '.pub'
        self.public_filename = os.path.expanduser(public_filename)

    def generate_new_key(self):
        '''Generate a new public/private key-pair
        '''
        self.key = RSA.generate(rsa_key_length, Random.new().read)
        self.cipher = PKCS1_OAEP.new(self.key)

    def read_key(self):
        '''Load keys from the key-files.

        If the private key-file exists, load keys from it.  Otherwise, use
        the public key file.
        '''
        if os.path.exists(self.private_filename):
            with open(self.private_filename) as fp:
                self.key = RSA.importKey(fp.read())
        else:
            with open(self.public_filename) as fp:
                self.key = RSA.importKey(fp.read())
        self.cipher = PKCS1_OAEP.new(self.key)

    def write_key(self):
        '''Write the public and private key files.

        :raises: :py:exc:`FileExistsError`
        '''
        if os.path.exists(self.private_filename):
            raise FileExistsError(
                'Private key file "%s" exists' % self.private_filename)
        if os.path.exists(self.public_filename):
            raise FileExistsError(
                'Public key file "%s" exists' % self.public_filename)

        with open(self.private_filename, 'w') as fp:
            fp.write(self.key.exportKey())

        with open(self.public_filename, 'w') as fp:
            fp.write(self.key.publickey().exportKey())
