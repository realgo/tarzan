#!/usr/bin/env python
#
#  Test of basic tarzan functionality.
#
#===============
#  This is based on a skeleton test file, more information at:
#
#     https://github.com/linsomniac/python-unittest-skeleton

import unittest

import os
import sys
sys.path.append('..')
import tarzan


class test_TarzanBasic(unittest.TestCase):
    def test_MakeSeqFilename(self):
        for file_id, results in [
                (0, ('0', '0')),
                (1, ('1', '0')),
                (2, ('2', '0')),
                (1294, ('zy', '0')),
                (1295, ('zz', '0')),
                (1296, ('0', '1')),
                (1297, ('1', '1')),
                (1679616, ('0', '100')),
                (1679617, ('1', '100')), ]:
            self.assertEqual(
                tarzan.make_seq_filename(file_id), os.path.join(*results))

    def test_BlockStorageDirectory(self):
        testdir = '/tmp/testblockstorage'
        os.system('rm -rf "%s"' % testdir)

        bs = tarzan.BlockStorageDirectory(testdir, 'TEST_PASSWORD')
        self.assertTrue(os.path.exists(os.path.join(testdir, 'info')))
        self.assertEqual(bs.next_brick, 0)

        bs.new_brick()
        size_1 = bs.brick_size
        bs.store_block('foo')
        size_2 = bs.brick_size
        self.assertNotEqual(size_1, size_2)
        bs.store_block('bar')
        size_3 = bs.brick_size
        self.assertNotEqual(size_2, size_3)
        bs.store_block('foo')
        size_4 = bs.brick_size
        self.assertEqual(size_3, size_4)
        bs.close_brick()

        bs2 = tarzan.BlockStorageDirectory(testdir, 'TEST_PASSWORD')
        self.assertEqual(bs2.next_brick, 1)

    def test_SequentialIV(self):
        niv = tarzan.SequentialIV()
        iv1 = niv.get_next_iv()
        niv.sequence += (1 << 64) - 2
        iv2 = niv.get_next_iv()
        self.assertNotEqual(iv1, iv2)
        iv3 = niv.get_next_iv()
        self.assertNotEqual(iv2, iv3)
        self.assertEqual(iv1, iv3)
        iv4 = niv.get_next_iv()
        self.assertNotEqual(iv1, iv4)
        self.assertNotEqual(iv2, iv4)
        self.assertNotEqual(iv3, iv4)

unittest.main()
