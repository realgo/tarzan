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

    def test_TarPipeEmpty(self):
        os.system('tar cfT "%s" /dev/null' % self.test_file)
        with open(self.test_file, 'rb') as in_fp, open(
                self.test_filed, 'wb') as out_fp:
            dtar.filter_tar(
                in_fp, out_fp, self.blockstore_directory, 'test_password',
                verbose=False)

        with self.assertRaises(dtar.InvalidDTARInputError):
            with open(self.test_filed, 'rb') as in_fp:
                dtar.list_dtar(
                    in_fp, self.dev_null, self.blockstore_directory,
                    'bad_password', verbose=False)

        with open(self.test_filed, 'rb') as in_fp:
            dtar.list_dtar(
                in_fp, self.dev_null, self.blockstore_directory,
                'test_password', verbose=False)

    def test_TarSimple(self):
        os.system('tar cf "%s" .' % self.test_file)
        with open(self.test_file, 'rb') as in_fp, open(
                self.test_filed, 'wb') as out_fp:
            dtar.filter_tar(
                in_fp, out_fp, self.blockstore_directory, 'test_password',
                verbose=False)

        with open(self.test_filed, 'rb') as in_fp:
            dtar.list_dtar(
                in_fp, self.dev_null, self.blockstore_directory,
                'test_password', verbose=False)

unittest.main()
