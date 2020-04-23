#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import sys
import tempfile
import subprocess

if os.name == 'posix' and sys.stderr.isatty():
    WARN_BEGIN = '\033[93;40m'
    WARN_END = '\033[0m'
else:
    WARN_BEGIN = ''
    WARN_END = ''

def warn(*args, **kwargs):
    print(WARN_BEGIN + "Warning: ", *args, WARN_END, file=sys.stderr, **kwargs)

def tohex(value):
    if type(value) == int:
        return hex(value)
    elif type(value) == bytes or type(value) == bytearray:
        return value.hex()


# Command used here is from https://packages.debian.org/stable/lzma-alone
# python lzma library compress data as stream with unknown size (0xFFFFFFFFFFFFFFFF)
# Fix it if possible to do with standard lzma library
def lzma_compress(data, dict_bits=19):
    REBUILD_LZMA_COMMAND = ['lzma_alone', '-d%d' % dict_bits, '-so', 'e']
    with tempfile.TemporaryDirectory() as tmpdirname:
        inpath = os.path.join(tmpdirname, "in.bin")
        with open(inpath, 'wb') as infile:
            infile.write(data)
        p = subprocess.Popen(REBUILD_LZMA_COMMAND + [inpath], stdout=subprocess.PIPE)
        outs, _ = p.communicate()
        return outs

def align_bytes(b, alignment):
    l = len(b)
    rem = l % alignment
    if rem != 0:
        pad = b'\0' * (l-rem)
