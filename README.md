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

This code has done a full round-trip that had the extracted files from the
reconstituted tar file match the checksums of the original tar file,
though the tar files had some slight differences that I need to hand check
to ensure they are ok.  I may be missing some padding, but I wouldn't have
expected tar to extract properly in that case.

More testing is needed, but I'm expecting it to be fairly close to usable
with the final file formats in place.

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
License: tarfp.py: Modified from Python source code to handle file object.
Code/Bugs: https://github.com/realgo/dtar
