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
import sys
sys.path.append('..')
import dtar

verbose = False


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
                verbose=verbose)

        with self.assertRaises(dtar.InvalidDTARInputError):
            with open(self.test_filed, 'rb') as in_fp:
                dtar.list_dtar(
                    in_fp, self.dev_null, self.blockstore_directory,
                    'bad_password', verbose=verbose)

        output_file = StringIO()
        with open(self.test_filed, 'rb') as in_fp:
            dtar.list_dtar(
                in_fp, output_file, self.blockstore_directory,
                'test_password', verbose=verbose)
        self.assertEqual(output_file.getvalue(), '')

        with open(self.test_file, 'rb') as fp:
            sum = md5.new()
            sum.update(fp.read())
            orig_sum = sum.hexdigest()

        output_file = StringIO()
        with open(self.test_filed, 'rb') as in_fp:
            dtar.decrypt_dtar(
                in_fp, output_file, self.blockstore_directory,
                'test_password', verbose=verbose)
        sum = md5.new()
        sum.update(output_file.getvalue())
        result_sum = sum.hexdigest()

        self.assertEqual(orig_sum, result_sum)

    def test_TarSimple(self):
        os.system('tar cf "%s" .' % self.test_file)
        with open(self.test_file, 'rb') as in_fp, open(
                self.test_filed, 'wb') as out_fp:
            dtar.filter_tar(
                in_fp, out_fp, self.blockstore_directory, 'test_password',
                verbose=verbose)

        output_file = StringIO()
        with open(self.test_filed, 'rb') as in_fp:
            dtar.list_dtar(
                in_fp, output_file, self.blockstore_directory,
                'test_password', verbose=verbose)

        output = output_file.getvalue()
        self.assertEqual(
            sorted([x.split()[-1] for x in output.split('\n') if x]),
            ['.', './Makefile', './test_basic.py', './test_functional.py'])

unittest.main()
