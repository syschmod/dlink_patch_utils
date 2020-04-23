#!/usr/bin/python3
# -*- coding: utf-8 -*-
from seama import SEAMA
import gzip
import sys
import io

if __name__ == "__main__":
    try:
        command = sys.argv[1]
        if "extract".startswith(command):
            command = "extract"
            infile, outfile = sys.argv[2], sys.argv[3]
        elif "rebuild".startswith(command):
            command = "rebuild"
            infile, original, outfile = sys.argv[2], sys.argv[3], sys.argv[4]
        else:
            raise
    except Exception:
        print("Usage:\n %s e[xtract] <infile.bin> <outfile.xml>\n" % sys.argv[0] + 
            " %s r[ebuild] <infile.xml> <original.bin> <outfile.bin>" % sys.argv[0] )
        sys.exit(1)
    
    if command == "extract":
        with open(infile, "rb") as binf:
            b = binf.read()
        s = SEAMA()
        s.decode(b)
        s.print()
        with open(outfile, 'xb') as outf:
            outf.write(gzip.decompress(s.data))

    elif command == "rebuild":
        with open(infile, "rb") as xmlf:
            xml = xmlf.read()
        with io.BytesIO() as gzio:
            with gzip.GzipFile(fileobj=gzio, mode="wb", mtime=0) as gzf:
                gzf.write(xml)
            xmlgz = bytearray(gzio.getvalue())
            if xmlgz[0x8] in {0x2,0x4}: # XFL
                xmlgz[0x8] = 0x0
            xmlgz[0x9] = 0x3 # Unix Operating System
        with open(original, "rb") as binoriginalf:
            b = binoriginalf.read()
        s = SEAMA()
        s.decode(b)
        meta = s.meta
        with open(outfile, 'xb') as outf:
            outf.write(s.encode(xmlgz, meta))

