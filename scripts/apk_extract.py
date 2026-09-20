#!/usr/bin/env python3
"""Bounded ZIP/DEX static observation. No extracted file is executed or written.

Class definitions are read from DEX class_defs, strings from string_ids.
Presence is not reachability, provider functionality, or signature verification.
"""
import hashlib
import io
import json
import struct
import sys
import zipfile
import zlib

MAX_INPUT = 32 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024


def dex_surface(data):
    if len(data) < 112 or data[:8] not in (b'dex\n035\0', b'dex\n037\0', b'dex\n038\0', b'dex\n039\0'):
        raise ValueError('unsupported_dex')
    def u32(offset):
        if offset < 0 or offset + 4 > len(data):
            raise ValueError('dex_bounds')
        return struct.unpack_from('<I', data, offset)[0]
    if u32(32) != len(data) or u32(36) != 112 or u32(40) != 0x12345678:
        raise ValueError('dex_header')
    if u32(8) != zlib.adler32(data[12:]) & 0xffffffff or data[12:32] != hashlib.sha1(data[32:]).digest():
        raise ValueError('dex_integrity')
    def table(count_offset, width):
        count, offset = u32(count_offset), u32(count_offset + 4)
        if count > 200000 or offset + count * width > len(data):
            raise ValueError('dex_table_bounds')
        return range(offset, offset + count * width, width)
    strings = []
    for at in table(56, 4):
        pos = u32(at)
        # Bounded ULEB128 UTF-16 length, followed by NUL-terminated MUTF-8.
        size = 0
        for i in range(5):
            if pos >= len(data):
                raise ValueError('dex_string_bounds')
            byte = data[pos]; pos += 1
            size |= (byte & 127) << (7 * i)
            if not byte & 128:
                break
        else:
            raise ValueError('dex_uleb128')
        end = data.find(b'\0', pos)
        if end < 0 or end - pos > 1024 * 1024:
            raise ValueError('dex_string_bounds')
        raw = data[pos:end].replace(b'\xc0\x80', b'\x00')
        value = raw.decode('utf-8', errors='surrogatepass')
        if len(value.encode('utf-16-le', errors='surrogatepass')) // 2 != size:
            raise ValueError('dex_string_length')
        strings.append(value)
    types = []
    for at in table(64, 4):
        index = u32(at)
        if index >= len(strings):
            raise ValueError('dex_type_bounds')
        types.append(strings[index])
    classes = []
    for at in table(96, 32):
        index = u32(at)
        if index >= len(types):
            raise ValueError('dex_class_bounds')
        classes.append(types[index])
    return {'classes': sorted(set(classes)), 'strings': sorted(set(strings))}


def extract(data):
    if len(data) > MAX_INPUT:
        raise ValueError('apk_input_limit')
    members, dex = [], {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        names = [i.filename for i in infos]
        if len(infos) > 4096 or len(set(names)) != len(names):
            raise ValueError('zip_duplicate_or_member_limit')
        if sum(i.file_size for i in infos) > MAX_TOTAL:
            raise ValueError('zip_expansion_limit')
        for info in infos:
            name = info.filename
            if name.startswith('/') or '\\' in name or '..' in name.split('/') or info.flag_bits & 1:
                raise ValueError('zip_unsafe_member')
            if info.file_size > MAX_INPUT:
                raise ValueError('zip_member_limit')
            with archive.open(info) as entry:
                content = entry.read(MAX_INPUT + 1)
            if len(content) != info.file_size:
                raise ValueError('zip_size_mismatch')
            members.append({'name': name, 'byte_length': len(content),
                            'sha256': hashlib.sha256(content).hexdigest()})
            if name.endswith('.dex'):
                dex[name] = dex_surface(content)
    if 'AndroidManifest.xml' not in names or 'classes.dex' not in names:
        raise ValueError('apk_required_members_missing')
    return {'format': 'apk-static-v1', 'members': sorted(members, key=lambda m: m['name']), 'dex': dex}


if __name__ == '__main__':
    try:
        print(json.dumps(extract(sys.stdin.buffer.read(MAX_INPUT + 1)), sort_keys=True, ensure_ascii=True))
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
