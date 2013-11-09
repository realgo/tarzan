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

        #  Examples:
        # self.assertEqual(fp.readline(), 'This is a test')
        # self.assertFalse(os.path.exists('a'))
        # self.assertTrue(os.path.exists('a'))
        # self.assertTrue('already a backup server' in c.stderr)
        # self.assertIn('fun', 'disfunctional')
        # self.assertNotIn('crazy', 'disfunctional')
        # with self.assertRaises(Exception):
        #	raise Exception('test')
        #
        # Unconditionally fail, for example in a try block that should raise
        # self.fail('Exception was not raised')

unittest.main()
