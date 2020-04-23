#!/usr/bin/python3
# -*- coding: utf-8 -*-
import hashlib
import struct

# i18n() in embedded PHP computes MD5 sum of text and searches
#   it in /var/sealpac/sealpac.slp
# That file is also stored gzipped in langpack part of flash

def gen_sealpac_from_hashed(md5dict, langcode=b'en'):
    """ Generates binary content of sealpac.slp
    md5dict:
        keys have to be md5 (bytes, len 16)
        values have to be utf-8 encoded translations
    langcode:
        language code: e.g. de, en, es, fr, it, pl, pt
    """
    magic = b'\x05\xea\x19\xac'
    header_size = 0x30
    entry_size = 0x14
    transl_block = b''
    entries = b''
    offset = header_size + len(md5dict)*entry_size
    for md5, translation in sorted(md5dict.items()):
        transl_block += translation + b'\0'
        entries += md5 + struct.pack('>L', offset)
        offset += len(translation) + 1
    
    header = magic + struct.pack(">L", len(md5dict)) + (8*b'\0')
    header += langcode[:15].ljust(16, b'\0')
    body = entries + transl_block
    h = hashlib.md5(body).digest()
    header += h
    return header + body
    
def gen_sealpac(dictionary, langcode=b'en'):
    md5dict = {}
    for original, translation in dictionary.items():
        h = hashlib.md5(original.encode('utf-8')).digest()
        md5dict[h] = translation.encode('utf-8')
    return gen_sealpac_from_hashed(md5dict)



if __name__ == "__main__":
    import sys
    try:
        infile, outfile = sys.argv[1], sys.argv[2]
        try:
            langcode = sys.argv[3].encode('ascii')
        except IndexError:
            langcode = 'en'
    except Exception:
        print("Generate langpack/sealpac (for i18n):\n" +
            " %s <translations.txt> <outlangpack.lng> [langcode]\n" % sys.argv[0]+
            "Each line in translations.txt should contain tab separated:\n" +
            "<original>\t<translation>")
        sys.exit(1)
    with open(infile, 'r') as sfile:
        data = sfile.read()
    dictionary = dict( line.split('\t') for line in data.split('\n') if len(line) > 0 )
    with open(outfile, 'xb') as ofile:
        ofile.write(gen_sealpac(dictionary, langcode))
    
