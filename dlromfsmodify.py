#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import struct
# This script is based on modified version of binwalk extraction script
# https://github.com/ReFirmLabs/binwalk/blob/ff34b1219e9b34bcd47251f63ba99e12d01bfc74/src/binwalk/plugins/dlromfsextract.py
import time
import subprocess
import tempfile
from dlink_utils import warn, lzma_compress

try:
    import lzma
except ImportError as e:
    pass

class RomFSCommon(object):

    def _read_next_halfword(self):
        value = struct.unpack("%sH" % self.endianness, self.data[self.index:self.index + 2])[0]
        self.index += 2
        return value

    def _read_next_word(self):
        value = struct.unpack("%sL" % self.endianness, self.data[self.index:self.index + 4])[0]
        self.index += 4
        return value

    def _read_next_uid(self):
        uid = int(self.data[self.index:self.index + 4])
        self.index += 4
        return uid

    def _read_next_block(self, size):
        size = int(size)
        data = self.data[self.index:self.index + size]
        self.index += size
        return data

    def _read_next_string(self):
        data = ""
        while True:
            byte = self.data[self.index]
            try:
                byte = chr(byte)
            except TypeError as e:
                pass

            if byte == "\x00":
                break
            else:
                data += byte
                self.index += 1
        return data
    
    def _write_world_at(self, offset, value):
        self.data[offset:offset+4] = struct.pack("%sL" % self.endianness, value)


class RomFSEntry(RomFSCommon):

    DIR_STRUCT_MASK = 0x00000001
    DATA_MASK = 0x00000008
    COMPRESSED_MASK = 0x005B0000 # This is wrong - probably these are permissions

    def __init__(self, data, endianness="<"):
        self.data = data
        self.endianness = endianness
        self.index = 0

        self.type = self._read_next_word()
        self.nlink = self._read_next_word()
        self.user_id = self._read_next_halfword()
        self.group_id = self._read_next_halfword()
        self.size = self._read_next_word()
        self.ctime = self._read_next_word()
        self.offset = self._read_next_word()
        self.size_decompressed = self._read_next_word() # 0 means no compression
        self.uid = self._read_next_uid()
    
    def update(self):
        self._write_world_at(0x0, self.type)
        self._write_world_at(0x4, self.nlink)
        # TODO update user and group id
        self._write_world_at(0xc, self.size)
        self._write_world_at(0x10, self.ctime)
        self._write_world_at(0x14, self.offset)
        self._write_world_at(0x18, self.size_decompressed)
        # TODO update uid string


class RomFSDirStruct(RomFSCommon):

    SIZE = 0x20

    def __init__(self, data, endianness="<"):
        self.index = 0
        self.data = data
        self.endianness = endianness
        self.directory = False
        self.uid = None
        self.ls = []

        for (uid, entry) in self.next():
            if self.uid is None:
                self.uid = uid

            if entry in ['.', '..']:
                self.directory = True
                continue

            self.ls.append((uid, entry))

    def next(self):
        while self.index < len(self.data):
            uid = self._read_next_word()
            dont_care = self._read_next_word()
            entry = self._read_next_string()

            total_size = int(4 + 4 + len(entry))
            count = int(total_size / self.SIZE)
            if count == 0:
                mod = self.SIZE - total_size
            else:
                mod = self.SIZE - int(total_size - (count * self.SIZE))

            if mod > 0:
                remainder = self._read_next_block(mod)

            yield (uid, entry)


class FileContainer(object):

    def __init__(self):
        pass

class RomFSSuperblock(RomFSCommon):
    
    def __init__(self, data, endianness):
        self.data = data
        self.endianness = endianness
        self.index = 0
        
        self.magic = self._read_next_word()
        self.entry_count = self._read_next_word()
        self.max_size = self._read_next_word()
        self.dev_id = self._read_next_word() # D-Link puts 0x01020304 here
        self.signature = self._read_next_block(16)
    

class RomFS(object):

    SUPERBLOCK_SIZE = 0x20
    FILE_ENTRY_SIZE = 0x20
    ALIGNMENT = 0x20
    PAD_BYTE = b'\0'

    def __init__(self, fname, endianness="<"):
        self.endianness = endianness
        self.data = open(fname, "rb").read()
        
        self.superblock = RomFSSuperblock(self.data[:self.SUPERBLOCK_SIZE], self.endianness)
        self.entries = self._process_all_entries()
        if len(self.entries) != self.superblock.entry_count:
            warn("entry count not equal to value stored in header")

    def get_data(self, uid, uncompress=True):
        start = self.entries[uid].offset
        end = start + self.entries[uid].size

        data = self.data[start:end]

        if uncompress:
            try:
                data = lzma.decompress(data)
                if len(data) != self.entries[uid].size_decompressed:
                    warn("[lzma] Wrong decompressed size! %s (%d)" % (repr(self.entries[uid]), uid))
            except KeyboardInterrupt as e:
                raise e
            except Exception as e:
                warn("Could not uncompress! %s (%d)" % (repr(self.entries[uid]), uid))
                pass

        return data

    def build_path(self, uid):
        path = self.entries[uid].name

        while uid != 0:
            uid = self.entries[uid].parent
            path = os.path.join(self.entries[uid].name, path)

        return path.replace("..", "")

    def _process_all_entries(self):
        entries = {}
        offset = self.SUPERBLOCK_SIZE
        counter = 0
        while counter < self.superblock.entry_count:
            try:
                entry = RomFSEntry(self.data[offset:offset + self.FILE_ENTRY_SIZE], endianness=self.endianness)
            except ValueError as e:
                warn("entry (%d) could not be read " % counter);
                break

            if not entry.uid in entries:
                entries[entry.uid] = FileContainer()

            entries[entry.uid].offset = entry.offset
            entries[entry.uid].size = entry.size
            entries[entry.uid].type = entry.type
            entries[entry.uid].raw_type = entry.type
            entries[entry.uid].size_decompressed = entry.size_decompressed
            entries[entry.uid].ctime = entry.ctime
            entries[entry.uid].nlink = entry.nlink
            if entry.uid == 0:
                entries[entry.uid].name = os.path.sep

            if entry.type & entry.DIR_STRUCT_MASK:
                entries[entry.uid].type = "directory"
                ds = RomFSDirStruct(self.data[entry.offset:entry.offset + entry.size], endianness=self.endianness)
                for (uid, name) in ds.ls:
                    if not uid in entries:
                        entries[uid] = FileContainer()
                    else:
                        warn('Multiple links to one file:', self.build_path(uid), name) # DEBUG
                    entries[uid].parent = ds.uid
                    entries[uid].name = name
            else:
                entries[entry.uid].type = "data"

            offset += self.FILE_ENTRY_SIZE
            counter += 1

        return entries
    
    def modify_entry(self, uid, info):
        offset = self.SUPERBLOCK_SIZE + uid*self.FILE_ENTRY_SIZE
        try:
            entry = RomFSEntry(self.data[offset:offset + self.FILE_ENTRY_SIZE], endianness=self.endianness)
        except ValueError as e:
            warn("entry (%d) could not be read " % uid);
            return False
        if entry.uid != uid:
            warn("entry uid not equal to it's number");

        for param in {'offset','size','size_decompressed'}:
            if hasattr(info, param):
                setattr(entry, param, getattr(info, param))

        entry.update()
        self.data[offset:offset + self.FILE_ENTRY_SIZE] = entry.data
        return True
    
    MAX_NOTCOMPRESSED = 512 
    
    def rebuild(self):
        self.data = bytearray(self.data)
        new_data_block = b''
        data_offset = self.SUPERBLOCK_SIZE + len(self.entries)*self.FILE_ENTRY_SIZE
        for uid, info in self.entries.items():
            # guarantee alignment of data
            rem = data_offset % self.ALIGNMENT
            if rem != 0:
                padlen = self.ALIGNMENT - rem
                new_data_block += self.PAD_BYTE * padlen
                data_offset += padlen
            
            data = None
            if hasattr(info, 'new_data'):
                data = info.new_data
                if len(data) > self.MAX_NOTCOMPRESSED:
                    info.size_decompressed = len(data)
                    data = lzma_compress(data)
                else:
                    info.size_decompressed = 0
                del info.new_data
            else:
                data = self.get_data(uid, uncompress=False)
            info.size = len(data)
            info.offset = data_offset
            self.modify_entry(uid, info)
            
            new_data_block += data
            data_offset += info.size
        
        new_size = len(new_data_block) + self.SUPERBLOCK_SIZE + len(self.entries)*self.FILE_ENTRY_SIZE
        if new_size%32 != 0: # max size should be aligned to 32 byte blocks
            new_size += 32 - (new_size%32)
        if new_size > self.superblock.max_size:
            warn("RomFS larger than max_size in header! Increasing max_size to %d" % new_size)
            self.superblock.max_size = new_size
            self.data[0x8:0xc] = struct.pack("%sL" % self.endianness, new_size)
        
        self.data = bytes(self.data[:self.SUPERBLOCK_SIZE + len(self.entries)*self.FILE_ENTRY_SIZE]) + new_data_block


    def inspect_compression_threshold(self):
        max_notcompressed = 0
        min_compressed = float('inf')
        for (uid, info) in self.entries.items():
            if hasattr(info, 'name') and hasattr(info, 'parent'):
                path = self.build_path(uid).strip(os.path.sep)
                if info.type != "directory":
                    if info.size_decompressed == 0 and info.size > max_notcompressed:
                        max_notcompressed = info.size
                    elif info.size_decompressed != 0 and info.size_decompressed < min_compressed:
                        min_compressed = info.size_decompressed
                elif info.size_decompressed != 0:
                    print("Compressed directory: %s" % path) #DEBUG
        return max_notcompressed, min_compressed
    
    def modify_file(self, data, mpath):
        mpath = mpath.strip(os.path.sep)
        muid = None
        for (uid, info) in self.entries.items():
            if hasattr(info, 'name') and hasattr(info, 'parent'):
                path = self.build_path(uid).strip(os.path.sep)
                if mpath == path:
                    if info.type == "directory":
                        print("This script can only modify regular files")
                    else:
                        muid = uid
                    break
        if muid is None:
            print("no such regular file in RomFS")
            return False
        self.entries[muid].new_data = data
        return True
    
    def inspect_data_layout(self):
        layout = []
        max_gapsize = 0
        for (uid, info) in self.entries.items():
            if hasattr(info, 'name') and hasattr(info, 'parent'):
                path = self.build_path(uid).strip(os.path.sep)
            else:
                path = ''
            layout.append((info.offset, info.size, uid, path))
        layout = sorted(layout)
        for i, (offset, size, uid, path) in enumerate(layout):
            if i!=0:
                prevoffset, prevsize, prevuid, prevpath = layout[i-1]
                if prevoffset + prevsize > offset:
                    print("%d %s and %d %s overlap!" % (prevuid,prevpath,uid,path))
                elif prevoffset + prevsize < offset:
                    gapsize = offset - (prevoffset + prevsize)
                    value = self.data[prevoffset + prevsize:prevoffset + prevsize+gapsize]
                    if all(b == value[0] for b in value):
                        value = "%d times 0x%02x" % (gapsize, value[0])
                    else:
                        value = repr(value)
                    print("%d bytes gap between %d %s and %d %s at offset %x (%s)"
                        % (gapsize, prevuid, prevpath, uid, path, prevoffset + prevsize, value))
                    if gapsize > max_gapsize:
                        max_gapsize = gapsize
        offset, size, uid, path = layout[len(layout)-1]
        if offset + size > len(self.data):
            print("%d %s data after end of file!" % (uid,path))
        elif offset + size < len(self.data):
            gapsize = len(self.data) - (offset + size)
            print("%d bytes gap between %d %s and end of file at offset %x"
                % (gapsize, uid,path, prevoffset + prevsize))
            if gapsize > max_gapsize:
                max_gapsize = gapsize
        print("Maximal gap size is %d bytes" % max_gapsize)
        
    def test_alignment(self, alignment):
        print("Testing alignment: %d byte" % alignment)
        count = 0
        for (uid, info) in self.entries.items():
            if hasattr(info, 'name') and hasattr(info, 'parent'):
                path = self.build_path(uid).strip(os.path.sep)
            else:
                path = ''
            if info.offset % alignment == 0:
                count += 1
            else:
                print("at %x %d bytes (%d, %s) not aligned" % (info.offset, info.size, uid, path))
        print("%d entries aligned" % count)


if __name__ == '__main__':
    import sys

    try:
        infile = sys.argv[1]
    except IndexError as e:
        print ("Usage: %s <input file>" % sys.argv[0])
        sys.exit(1)

    # TODO: Support big endian targets.
    fs = RomFS(infile)
    
    cmd = ['']
    while cmd[0] != 'q':
        try:
            cmd=input('> ').split(' ',1)
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if cmd[0] in { 'l','ls' }:
            for (uid, info) in fs.entries.items():
                if hasattr(info, 'name') and hasattr(info, 'parent'):
                    path = fs.build_path(uid).strip(os.path.sep)
                    if info.type != "directory":
                        print(uid, path, info.size, info.size_decompressed)
        elif cmd[0] == 'i':
            fs.inspect_data_layout()
            max_notcompressed, min_compressed = fs.inspect_compression_threshold()
            print("Maximal not compressed size: %d bytes" % max_notcompressed)
            print("Minimal compressed size: %d bytes" % min_compressed)
            fs.test_alignment(RomFS.ALIGNMENT)
        elif cmd[0] in { 'm','mv' }:
            try:
                mfile, mpath = cmd[1].split(' ',1)
            except (ValueError, IndexError) as e:
                print ("%s <input modified file> <path in RomFS>"%cmd[0])
                continue
            data = None
            try:
                with open(mfile,'rb') as mf:
                    data = mf.read()
            except KeyboardInterrupt as e:
                raise e
            except Exception as e:
                pass
            if data is None:
                print ("Could not read <input modified file>")
            else:
                if fs.modify_file(data, mpath):
                    print("Replacing /%s with %s" % (mpath, mfile))
        elif cmd[0] == 'w':
            try:
                outpath = cmd[1]
            except IndexError as e:
                print ("w <new RomFs file>")
                continue
            fs.rebuild()
            with open(outpath, 'xb') as outfile:
                print("Writing modified RomFS to %s" % outpath)
                outfile.write(fs.data)
        elif cmd[0] != 'q':
            print("""Available commands:
l[s]                                  list RomFS modifiable files
m[v] <input modified file> <path in RomFS>  read replacing file
w <new RomFs file>                    write modified RomFS to new file
q                                     quit
i                                     inspect RomFS
""")

