import os
from Crypto import Random
import uuid


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
        self.index_filename = os.path.join(self.path, 'index')

        self.index_fp = open(self.index_filename, 'wb')
        self._write_index_header()

    def _write_index_header(self):
        self.aes_iv = Random.new().read(16)
        self.uuid = uuid.uuid1().bytes
        self.index_fp.write('dtar1')
        self.index_fp.write(self.aes_iv)
        self.index_fp.write(self.uuid)
