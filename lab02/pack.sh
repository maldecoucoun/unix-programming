#!/bin/bash

# Check if the 'rootfs' directory exists
if [ ! -d "rootfs" ]; then
    echo "Error: 'rootfs' directory not found."
    exit 1
fi

# Compress the 'rootfs' directory into a CPIO archive
(cd rootfs && find * | cpio -o -H newc | bzip2 > ../rootfs.cpio.bz2)

echo "Compression complete: rootfs.cpio.bz2"
