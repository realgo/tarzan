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
import sys
sys.path.append('..')
import dtar


class test_DTarBasic(unittest.TestCase):
    def test_TarPipeEmpty(self):
        testdir = '/tmp/testdtarbs'
        os.system('rm -rf "%s"' % testdir)

        testfile = '/tmp/testtarfile1.tar'
        testfile2 = '/tmp/testtarfile2.tar'
        testfiled = '/tmp/testdtarfile.tar'
        os.system('rm -rf "%s"' % testfile)
        os.system('rm -rf "%s"' % testfile2)
        os.system('rm -rf "%s"' % testfiled)

        os.system('tar cfT "%s" /dev/null' % testfile)
        with open(testfile, 'rb') as in_fp, open(testfiled, 'wb') as out_fp:
            dtar.filter_tar(
                in_fp, out_fp, testdir, 'test_password', verbose=False)

        with self.assertRaises(dtar.InvalidDTARInputError):
            with open(testfiled, 'rb') as in_fp:
                dtar.list_dtar(
                    in_fp, sys.stdout, testdir, 'bad_password', verbose=False)

        with open(testfiled, 'rb') as in_fp:
            dtar.list_dtar(
                in_fp, sys.stdout, testdir, 'test_password', verbose=False)

    def test_TarSimple(self):
        testdir = '/tmp/testdtarbs'
        os.system('rm -rf "%s"' % testdir)

        testfile = '/tmp/testtarfile1.tar'
        testfile2 = '/tmp/testtarfile2.tar'
        testfiled = '/tmp/testdtarfile.tar'
        os.system('rm -rf "%s"' % testfile)
        os.system('rm -rf "%s"' % testfile2)
        os.system('rm -rf "%s"' % testfiled)

        os.system('tar cf "%s" .' % testfile)
        with open(testfile, 'rb') as in_fp, open(testfiled, 'wb') as out_fp:
            dtar.filter_tar(
                in_fp, out_fp, testdir, 'test_password', verbose=False)

        with open(testfiled, 'rb') as in_fp:
            dtar.list_dtar(
                in_fp, sys.stdout, testdir, 'test_password', verbose=False)

unittest.main()
