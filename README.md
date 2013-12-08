TARzan -- Cloud Backups with TAR
================================

TARzan is a backup tool meant for use with Amazon S3/Glacier and other
similar types of cloud storage.  It will de-duplicate, encrypt, and
authenticate the backup data for storage in a cloud storage service.

It is specifically designed to work with Amazon Glacier, because of
their $0.01/GB/month storage pricing, while preserving the privacy and
authenticity of the data.

Features
--------

   * Takes a tar file (or output piped from tar).  In other words,
     delegates the backup function to the `tar` command.

   * Encrypts, de-duplicates, and authenticates the data payload in the tar
     files.

   * Allows for full and future backups by only uploading changed data.

   * Writes data "bricks" in an Amazon Glacier-compatible format.

Requirements
------------

   * Python 2.7, largely for a pycrypto that supports AES and PBKDF.

   * python and python-crypto packages on Debian/Ubuntu.

   * tar

   * s3cmd package and Amazon S3 or Glacier account for remote storage.

   * For Python 2.6 and earlier, you have to download "pycrypto" and
     "argparse" from the Python package index, and put them into the tarzan
     program directory.  You then need to comment out the "NullHandler"
     lines from tarzan.py, and in the tarzan file do `sys.insert(0,
     '/path/to/tarzan')` after the `import sys` line.

Status
------

This code is fairly young (started work in Nov 2013), but is complete to
the point where I have done a full system backup to it and extracted it and
compared the results to the original system backup tar file, with no
differences.

At this point I'm considering the file formats to be stable and putting the
code into beta.

Integrated upload to S3/Glacier is not yet started, but can be run as an
external process with `s3cmd sync`.

Getting Started
---------------

Basic usage information is available by running `tarzan --help`.

You need a "block storage" directory, which is the location that the file
data is written to.  These files need to be uploaded to the storage server
(Amazon Glacier or S3, storage server) for "deep freezing".  There is also
a "blocks\_map" and "info" files that need to remain on the backup client
machine, which identifies the block-store and the already uploaded blocks.

You use `tar` to backup the files, and send that output into `tarzan` for
storage.  For example, to backup the current directory into a local
"blocks" block storage directory:

    tar c --exclude=./blocks . | \
    tarzan -d blocks -P MY_PASSWORD create --out=backup1.tarzan

This creates a "blocks" directory which stores the file data, and a
"backup1.tarzan" file which is the backup meta-data (files, permissions,
and links to the payload).  All of this is encrypted and protected against
tampering.

Now, to restore the data you need to can use the `extract` sub-command, like
this:

    mkdir recovery
    tarzan -d blocks -P MY_PASSWORD extract --in=backup1.tarzan | \
    tar x -C recovery

The recovered data is stored in the "recovery" sub-directory.

The index file ("backup1.tarzan" in the above example) and any of the files
starting with "dt\_d" (data blocks) are required for recovery.  All other
files (those starting with "dt\_t", "blocks\_map", and "index") are all
just duplicate data, for optimization purposes.

To copy these up to Amazon, currently, is an external step using the
`s3cmd` program:

    s3cmd sync --exclude 'blocks_map' blocks s3://my-backups/blocks
    s3cmd sync backup1.tarzan s3://my-backups/

This requires creating an S3 bucket, above named "my-backups", and then
configuring s3cmd with your credentials using:

    s3cmd --configure

Alternately, you could use the s3fs project to mount up an S3 bucket as a
file-system and specify that with the "-d" argument.  I haven't tested
this, but you'd probably want to use a symlink to place the "blocks\_map"
file on the local file-system.

Once you are sure all the data has been uploaded to S3, you no longer need
the local copies of any "dt\_d-\*" files.  You can also configure S3 via the
management console to automatically migrate those files and possibly also the
"dt\_t-\*" files to Glacier to reduce storage costs.

Alternatives
------------

It bears a resemblance, it was mentioned by an early reviewer, to the
[tarsnap backup system](http://www.tarsnap.com/), without the proprietary
closed-source server component, and enabling backup storage for a thirtieth
the cost.

It also resembles [version 2 (currently in beta) of the Duplicati backup
system](http://www.duplicati.com/).  Duplicati is more polished, including
integrated upload to S3.  However, in my testing of the pre-release of
version 2, the backups were extremely slow (an hour to backup 1GB to
local storage), and the recovery errored out.  I found Duplicati while I
was in the early implementation stages of tarzan.  I had already decided on
the "tar filter with detached blocks" architecture, but do feel that
Duplicati did lend some ideas and validation to the design.

Contact Information
-------------------

Author: Sean Reifschneider <sean+opensource@realgo.com>  
Date: Mon Nov 11, 2013  
License: GPLv2
License: tarfp.py: Modified from Python source code to handle file object.
Code/Bugs: https://github.com/realgo/tarzan
