#!/usr/bin/env python
#
#  Functional test of dtar.
#
#===============
#  This is based on a skeleton test file, more information at:
#
#     https://github.com/linsomniac/python-unittest-skeleton

import unittest

import os
import tempfile
from StringIO import StringIO
import md5
import tarfile
import sys
sys.path.append('..')
import dtar


class test_DTarBasic(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix='dtar_test')
        self.blockstore_directory = os.path.join(self.temp_dir, 'blockstore')
        self.test_file = os.path.join(self.temp_dir, 'file1.tar')
        self.test_file2 = os.path.join(self.temp_dir, 'file2.tar')
        self.test_filed = os.path.join(self.temp_dir, 'file.dtar')
        self.dev_null = open('/dev/null', 'w')

    def tearDown(self):
        os.system('rm -rf "%s"' % self.temp_dir)

    def make_big_dir(self):
        self.big_dir = os.path.join(self.temp_dir, 'big_dir')
        os.mkdir(self.big_dir)
        for file_id in range(200):
            file_name = os.path.join(self.big_dir, str(file_id))
            with open(file_name, 'w') as fp:
                fp.write(str(file_id) * file_id)

    def test_TarPipeEmpty(self):
        os.system('tar cfT "%s" /dev/null' % self.test_file)
        with open(self.test_file, 'rb') as in_fp, open(
                self.test_filed, 'wb') as out_fp:
            dtar.filter_tar(
                in_fp, out_fp, self.blockstore_directory, 'test_password')

        with self.assertRaises(dtar.InvalidDTARInputError):
            with open(self.test_filed, 'rb') as in_fp:
                dtar.list_dtar(
                    in_fp, self.dev_null, self.blockstore_directory,
                    'bad_password')

        output_file = StringIO()
        with open(self.test_filed, 'rb') as in_fp:
            dtar.list_dtar(
                in_fp, output_file, self.blockstore_directory,
                'test_password')
        self.assertEqual(output_file.getvalue(), '')

        self.compare_source_and_decrypted()

    def test_TarSimple(self):
        os.system('tar cf "%s" .' % self.test_file)
        with open(self.test_file, 'rb') as in_fp, open(
                self.test_filed, 'wb') as out_fp:
            dtar.filter_tar(
                in_fp, out_fp, self.blockstore_directory, 'test_password')

        self.basic_dtar_comparison()

    def test_TarBig(self):
        self.make_big_dir()

        os.system('tar cf "%s" -C "%s" .' % (self.test_file, self.big_dir))
        with open(self.test_file, 'rb') as in_fp, open(
                self.test_filed, 'wb') as out_fp:
            dtar.filter_tar(
                in_fp, out_fp, self.blockstore_directory, 'test_password')

        self.basic_dtar_comparison()

    def basic_dtar_comparison(self):
        with open(self.test_file, 'rb') as fp:
            source_file_list = sorted(tarfile.open(fileobj=fp).getnames())

        output_file = StringIO()
        with open(self.test_filed, 'rb') as in_fp:
            dtar.list_dtar(
                in_fp, output_file, self.blockstore_directory,
                'test_password')

        output = output_file.getvalue()
        self.assertEqual(
            sorted([x.split()[-1] for x in output.split('\n') if x]),
            source_file_list)

        output_file = StringIO()
        with open(self.test_filed, 'rb') as in_fp:
            dtar.decrypt_dtar(
                in_fp, output_file, self.blockstore_directory,
                'test_password')

        #  decrypted dtar has appropriate file names (payload still detached)
        output_file.seek(0)
        tf = tarfile.open(fileobj=output_file)
        self.assertEqual(
            sorted(tf.getnames()),
            source_file_list)

    def compare_source_and_decrypted(self):
        '''Verify that the source and decrypted tar are the same.

        This only works for tar files that have no payload blocks (either
        empty or only containing directories, etc...).
        '''
        with open(self.test_file, 'rb') as fp:
            sum = md5.new()
            sum.update(fp.read())
            orig_sum = sum.hexdigest()

        output_file = StringIO()
        with open(self.test_filed, 'rb') as in_fp:
            dtar.decrypt_dtar(
                in_fp, output_file, self.blockstore_directory,
                'test_password')
        sum = md5.new()
        sum.update(output_file.getvalue())
        result_sum = sum.hexdigest()

        self.assertEqual(orig_sum, result_sum)

unittest.main()
