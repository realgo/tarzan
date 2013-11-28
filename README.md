TARzan De-Duplicated TAR Backups for Amazon Glacier
===================================================

TARzan is a backup tool meant for use with Amazon Glacier and other similar
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

   * Takes a tar file (or output piped from tar).  In other words,
     delegates the backup function to the "tar" command.

   * Encrypts, de-duplicates, and authenticates the data payload in the tar
     files.

   * Allows for full and future backups by only uploading changed data.

   * Writes data "bricks" in an Amazon Glacier-compatible format.

Getting Started
---------------

Basic usage information is available by running `tarzan --help`.

You need a "block storage" directory, which is the location that the file
data is written to.  These files need to be uploaded to the storage server
(Amazon Glacier or S3, storage server) for "deep freezing".  There is also
a `blocks_map` and `info` files that need to remain on the backup client
machine, which identifies the block-store and the already uploaded blocks.

You use "tar" to backup the files, and send that output into "tarzan" for
storage.  For example, to backup the current directory into a local
"blocks" block storage:

    tar c --exclude=./blocks . | \
    tarzan -d blocks -P MY_PASSWORD create --out=backup1.tarzan

This creates a `blocks` directory which stores the file data, and a
"backup1.tarzan" file which is the backup meta-data (files, permissions,
and links to the payload).  All of this is encrypted and protected against
tampering.

Now, to restore the data you need to can use the "extract" command, like
this:

    mkdir recovery
    tarzan -d blocks -P MY_PASSWORD extract --in=backup1.tarzan | \
    tar x -C recovery

The recovered data is stored in the "recovery" sub-directory.

The index file (`backup1.tarzan` in the above example) and any of the files
starting with `dt_d` (data blocks) are required for recovery.  All other
files (those starting with `dt_t`, `blocks_map`, and `index`) are all
just duplicate data, for optimization purposes.

Contact Information
-------------------

Author: Sean Reifschneider <sean+opensource@realgo.com>  
Date: Mon Nov 11, 2013  
License: GPLv2
License: tarfp.py: Modified from Python source code to handle file object.
Code/Bugs: https://github.com/realgo/tarzan
