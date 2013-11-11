#!/usr/bin/env python
#
#  Test of basic dtar functionality.
#
#===============
#  This is based on a skeleton test file, more information at:
#
#     https://github.com/linsomniac/python-unittest-skeleton

import unittest

import os
import sys
sys.path.append('..')
import dtar


class test_XXX_Test_Group_Name(unittest.TestCase):
    def setUp(self):
        ###  XXX code to do setup
        pass

    def tearDown(self):
        ###  XXX code to do tear down
        pass

    def test_MakeSeqFilename(self):
        for file_id, results in [
                (0, ('0', '0')),
                (1, ('1', '0')),
                (2, ('2', '0')),
                (1294, ('yz', '0')),
                (1295, ('zz', '0')),
                (1296, ('0', '1')),
                (1297, ('1', '1')),
                (1679616, ('0', '001')),
                (1679617, ('1', '001')), ]:
            self.assertEqual(
                dtar._make_seq_filename(file_id), os.path.join(*results))

    def test_GetUID(self):
        self.assertEqual(dtar.get_username(0), 'root')
        self.assertEqual(dtar.get_username(30123), '')
        self.assertEqual(dtar.get_groupname(0), 'root')
        self.assertEqual(dtar.get_groupname(30123), '')

    def test_BlockStorage(self):
        testdir = '/tmp/testblockstorage'
        os.system('rm -rf "%s"' % testdir)

        bs = dtar.BlockStorage(testdir, 'TEST_PASSWORD')
        self.assertTrue(os.path.exists(os.path.join(testdir, 'info')))
        self.assertEqual(bs.next_brick, 0)

        bs.new_brick()
        size_1 = bs.blocks_file_size
        bs.store_block('foo')
        size_2 = bs.blocks_file_size
        self.assertNotEqual(size_1, size_2)
        bs.store_block('bar')
        size_3 = bs.blocks_file_size
        self.assertNotEqual(size_2, size_3)
        bs.store_block('foo')
        size_4 = bs.blocks_file_size
        self.assertEqual(size_3, size_4)
        bs.close_brick()

        bs2 = dtar.BlockStorage(testdir, 'TEST_PASSWORD')
        self.assertEqual(bs2.next_brick, 1)

unittest.main()
