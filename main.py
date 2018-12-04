#coding=utf-8

import re
import os
import idc
import sqlite3
from idaapi import *
from msymbol import MSymbol
from binary import MachO


#  macho_path 为当前IDA解析的macho文件路径
def find_symbol_usage_in_macho(symbol_name, macho_path, database=False):

    macho = MachO(macho_path)
    macho.parse_bind_info()

    s = MSymbol(symbol_name, macho.bind_indexed_by_symbol[symbol_name])
    s.find_usage()

    usage = set()
    for f in s.xrefs:
        fn = idc.GetFunctionName(f)
        m = re.search('(?P<type>[-+]?)\[(?P<receiver>\S+?) (?P<selector>[\w:]+)\]', fn)
        print hex(f), fn
        fi = get_func(f)
        if fi:
            usage.add(hex(fi.startEA))

    if database:
        conn = sqlite3.connect(database)
        c = conn.cursor()
        c.execute("UPDATE DYLIB_USAGE set USAGE='{}' where SYMBOL='{}' and APP='{}'".format(
            ';'.join(list(usage)), symbol_name, os.path.basename(macho_path)
        ))
        conn.commit()
        conn.close()


symbol_name = '_kSecClassGenericPassword'
macho_path = '/Users/gjy/Documents/git_workspace/MachOA/samples/AppJobber_arm64'
find_symbol_usage_in_macho(symbol_name, macho_path)
