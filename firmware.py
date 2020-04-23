#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
import struct
import zlib
import lzma
from seama import SEAMA
from dlink_utils import lzma_compress, warn, tohex

UIMAGE_KERNEL_OFFSET = 0x0
#UIMAGE_ROOTFS_OFFSET = 0xaa000 # original offset in GORTN150B1 firmware

class uImage(object):
    UIMAGE_MAGIC = 0x27051956
    HEADER_SIZE = 0x40
    
    HEADER_CRC_OFFSET = 0x4
    SIZE_OFFSET = 0xc
    DATA_CRC_OFFSET = 0x18
    IMAGE_NAME_OFFSET = 0x20
    NAME_SIZE = 0x20
    
    def _get_world_at(self, offset):
        return struct.unpack(">L", self.data[offset:offset+4])[0]
    
    def _set_world_at(self, offset, value):
        self.data[offset:offset+4] = struct.pack(">L", value)
    
    def __init__(self, data):
        self.data = bytearray(data)
        self.correct = True
        
        if self._get_world_at(0x0) != self.UIMAGE_MAGIC:
            warn("Wrong uImage magic number")
            self.correct = False
        self.size = self._get_world_at(self.SIZE_OFFSET)
        if len(self.data) < self.size + self.HEADER_SIZE:
            warn("image shorter than size from header")
            self.correct = False
        self.name = self.data[self.IMAGE_NAME_OFFSET:self.IMAGE_NAME_OFFSET + self.NAME_SIZE]
    
    def get_content(self):
        return self.data[self.HEADER_SIZE:self.HEADER_SIZE+self.size]
    
    def update_content(self, new_data):
        data_crc = zlib.crc32(new_data)
        self.size = len(new_data)
        self._set_world_at(self.DATA_CRC_OFFSET, data_crc)
        self._set_world_at(self.SIZE_OFFSET, self.size)
        self._set_world_at(self.HEADER_CRC_OFFSET, 0x0)
        hcrc = zlib.crc32(self.data[:self.HEADER_SIZE])
        self._set_world_at(self.HEADER_CRC_OFFSET, hcrc)
        self.data = self.data[:self.HEADER_SIZE] + new_data

def locate_rootfs_uImage(binary):
    """returns rootfs data offset"""
    l = len(binary)
    i = 0
    mbytes = struct.pack(">L", uImage.UIMAGE_MAGIC)
    while i <= l-len(mbytes):
        if binary[i:i+len(mbytes)] == mbytes:
            print("Found uImage candidate at %x" % i)
            uim = uImage(binary[i:])
            if uim.correct:
                if uim.name.find(b"rootfs") != -1:
                    print("This probably is rootfs image")
                    return i
                else:
                    print("Skipping image with %d bytes of data" % uim.size)
                    i += uImage.HEADER_SIZE + uim.size
                    continue
        i += 1
    return -1
    

if __name__ == "__main__":
    try:
        command = sys.argv[1]
        if "extract".startswith(command):
            command = "extract"
            infile, outfile = sys.argv[2], sys.argv[3]
        elif "replace".startswith(command):
            command = "replace"
            infile, original, outfile = sys.argv[2], sys.argv[3], sys.argv[4]
        else:
            raise
    except Exception:
        print("Firmware rootfs modifier usage:\n"+
            " %s e[xtract] <infw.bin> <outrootfs.bin>\n" % sys.argv[0] + 
            " %s r[eplace] <inrootfs.bin> <originalfw.bin> <outfw.bin>" % sys.argv[0] )
        sys.exit(1)
    
    if command == "extract":
        with open(infile, "rb") as binf:
            b = binf.read()
        s = SEAMA()
        s.decode(b)
        s.print()
        offset = locate_rootfs_uImage(s.data)
        if offset == -1:
            print("Could not find rootfs image")
            sys.exit(1)
        uimg = uImage(s.data[offset:])
        rootfs_data = lzma.decompress(uimg.get_content())
        with open(outfile, 'xb') as outf:
            outf.write(rootfs_data)

    elif command == "replace":
        with open(infile, "rb") as rootfs_f:
            rootfs = rootfs_f.read()
        lzrootfs = lzma_compress(rootfs, dict_bits=23)
        
        with open(original, "rb") as originalf:
            b = originalf.read()
        s = SEAMA()
        s.decode(b)
        
        offset = locate_rootfs_uImage(s.data)
        if offset == -1:
            print("Could not find rootfs image")
            sys.exit(1)

        meta = s.meta
        uimg = uImage(s.data[offset:])
        uimg.update_content(lzrootfs)
        
        new_data = s.data[:offset] + uimg.data # FIXIT: some data may be orginally after rootfs
        
        with open(outfile, 'xb') as outf:
            outf.write(s.encode(new_data, meta))


