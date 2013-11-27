Tarzan De-Duplicated TAR Backups for Amazon Glacier
===================================================

Tarzan is a backup tool meant for use with Amazon Glacier and other similar
types of cloud storage.  It will de-duplicate, encrypt, and authenticate
the backup data for storage in a cloud storage service.

It is specifically designed to work with Amazon Glacier, because of
their $0.01/GB/month storage pricing, while preserving the privacy and
authenticity of the data.

Status
------

This code is fairly young (started work in Nov 2013), but is complete to
the point where I have done a full system backup to it and extracted it and
compared the results to the original system backup tar file, with no
differences.

At this point I'm considering the file formats to be stable and putting the
code into beta.

Integrated upload to S3/Glacier is not yet started, but can be run as an
external process with "s3cmd sync".

Features
--------

   * Takes a tar file on stdin and deduplicates/compresses/encrypts the file
     body data.

   * Writes data "bricks" in an Amazon Glacier-compatible format.

Getting Started
---------------

Currently, the "bricks" (files containing the data blocks for upload to S3)
are written to "/dev/shm/test.bs".  So you need to have enough space there to
write the payload data, or you need to change it by modifying the "tarzan" file.

Then, just pipe "tar" output through "tarzan" and save the output:

    tar c . | python tarzan >local-index.tar

This writes a bunch of data files to the block storage ("/dev/shm/test.bs"),
and writes out an index tar file to "local-index.tar".  This is still a tar
file, but the file payload is replaced with checksums of every 100KB, and then
a final checksum of the whole input file.

Contact Information
-------------------

Author: Sean Reifschneider <sean+opensource@realgo.com>  
Date: Mon Nov 11, 2013  
License: GPLv2
License: tarfp.py: Modified from Python source code to handle file object.
Code/Bugs: https://github.com/realgo/tarzan
