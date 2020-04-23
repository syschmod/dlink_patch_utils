#!/usr/bin/python3
# -*- coding: utf-8 -*-
import struct
import hashlib
import os
import sys
from dlink_utils import warn, tohex

class SEAMA:
    
    MAGIC = 0x5ea3_a417
    
    def __init__(self):
        pass

    def decode(self, b):
        magic, meta_len, data_len = struct.unpack('!III', b[:0xc])
        md5sum = b[0xc:0x1c]
        self.magic = magic
        self.meta_len = meta_len
        self.data_len = data_len
        self.md5 = md5sum
        self.full_seama_header = b[:(0x1c+meta_len)]
        self.meta = b[0x1c:(0x1c+meta_len)]
        self.data = b[(0x1c+meta_len):(0x1c+meta_len+data_len)]
        self.surplus_data = b[(0x1c+meta_len+data_len):]
        return self.verify()

    def verify(self):
        correct = True
        if self.magic != 0x5ea3_a417:
            warn("Wrong SEAMA magic number")
            correct = False
        if 0 != len(self.surplus_data):
            warn("Surplus data after SEAMA data length found")
            correct = False
        if len(self.data) < self.data_len:
            warn("Data length is {}, but SEAMA's data length is {}".format(
                len(self.data), self.data_len
                ))
            correct = False
        
        h = hashlib.md5(self.data).digest()
        if h != self.md5:
            warn("MD5 checksum does not match")
            correct = False
        return correct
    
    def print(self):
        fields = [ 'magic', 'meta_len', 'data_len', 'md5', 'meta' ]
        for k in fields:
            v = getattr(self, k)
            if k == "md5" or type(v)== int:
                print("{:15s}: {}".format(k,tohex(v)))
            else:
                print("{:15s}: {}".format(k,v))
    
    def encode(self, data, meta):
        self.data = data
        self.meta = meta
        
        self.magic = self.MAGIC
        self.meta_len = len(meta)
        self.data_len = len(data)
        self.md5 = hashlib.md5(self.data).digest()
        self.full_seama_header = struct.pack('!LLL', self.magic, 
                                            self.meta_len, self.data_len)
        self.full_seama_header += self.md5 + self.meta
        self.surplus_data = b''
        
        return self.full_seama_header + self.data


if __name__ == "__main__":
    try:
        infile = sys.argv[1]
    except IndexError:
        print("Usage: %s <infile> [outfile]" % sys.argv[0])
        sys.exit(1)
    with open(infile, "rb") as f:
        b = f.read()
    s = SEAMA()
    s.decode(b)
    s.print()
    if len(sys.argv) > 2:
        with open(sys.argv[2], 'xb') as fdata:
            fdata.write(s.data)
