Detached Tar
============

Detached TAR (dtar) is a tool for TAR and PAX archives (as created by the
Unix "tar" command) to compress, encrypt, and de-duplicate the file data in
the tar file.

In particular, it is meant for backing up systems with Amazon S3 and Glacier.
Being Glacier-compatible means off-site backups for $0.01/GB/month or
$10/TB/month.

Status
------

This is a fairly early set of code, I just started writing it Nov 10.  It
currently has a proof of concept local storage, and *no* recovery program or
upload to S3.  Upload to S3/Glacier can be done using "s3cmd sync" at the
moment.

However, it's all pretty simple code so I expect it should come quickly.

Currently it is just a "proof of concept".

Features
--------

   * Takes a tar file on stdin and deduplicates/compresses/encrypts the file
     body data.

   * Writes data "bricks" in an Amazon Glacier-compatible format.

Getting Started
---------------

Currently, the "bricks" (files containing the data blocks for upload to S3)
are written to "/dev/shm/test.bs".  So you need to have enough space there to
write the payload data, or you need to change it by modifying the "dtar" file.

Then, just pipe "tar" output through "dtar" and save the output:

    tar c . | python dtar >local-index.tar

This writes a bunch of data files to the block storage ("/dev/shm/test.bs"),
and writes out an index tar file to "local-index.tar".  This is still a tar
file, but the file payload is replaced with checksums of every 100KB, and then
a final checksum of the whole input file.

Contact Information
-------------------

Author: Sean Reifschneider <sean+opensource@realgo.com>  
Date: Mon Nov 11, 2013  
License: GPLv2
Code/Bugs: https://github.com/realgo/dtar
