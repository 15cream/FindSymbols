#coding=utf-8
import commands
import re
import os


class MachO:

    def __init__(self, fp):

        self.root = os.path.split(fp)[0]
        os.chdir(self.root)
        self.fp = os.path.split(fp)[1]
        self.filetype = self.check_filetype()
        self.bind_indexed_by_symbol = dict()
        self.bind_indexed_by_dylib = dict()
        self.exports = set()
        self.except_libs = [
            'libswiftCore',
        ]
        self.except_symbols = [
            '_swift_deletedMethodError',
            '___CFConstantStringClassReference',
            '__NSConcreteGlobalBlock',
            '__objc_empty_cache',
            '_OBJC_METACLASS_$_NSObject',
            '_OBJC_CLASS_$_NSObject',
            '___cxa_pure_virtual',
            '__T0BOWV',
        ]

    def check_filetype(self):
        if os.path.exists(os.path.join(self.root, self.fp + '_arm64')):
            self.fp += '_arm64'
            return 'arm64'
        else:
            fp = self.fp.replace(' ', '\ ')
            filetype = commands.getstatusoutput("file {}".format(fp))[1]
            if 'armv7' in filetype or 'arm_v7' in filetype:
                if 'arm64' in filetype:
                    cmd = "lipo -thin arm64 {} -o {}".format(fp, fp + '_arm64')
                    if commands.getstatusoutput(cmd)[0] != 0:
                        print 'LIPO CMD ERROR'
                    else:
                        self.fp += '_arm64'
                        return 'arm64'
                return 'armv7'
            elif 'arm64' in filetype:
                self.fp += '_arm64'
                return 'arm64'
            elif 'arm_v6' in filetype:
                return 'arm_v6'
            else:
                print 'UNKNOWN FILE TYPE ({}).'.format(self.root)
                return None

    # deprecated
    def parse_dylib_info(self):
        cmd = "objdump -dylibs-used -macho {}".format(self.fp)
        output = commands.getstatusoutput(cmd)
        dylib_info = output[1].split("\n")[1:]
        for dylib in dylib_info:
            dylib_path = dylib.split()[0]
            dylib_name = MachO.define_dylib_name(dylib_path)
            if dylib_name not in self.bind_indexed_by_dylib:
                self.bind_indexed_by_dylib[dylib_name] = {
                    'path': dylib_path,
                    'symbols': set()
                }

    @staticmethod
    def define_dylib_name(dylib_path):
        if '/usr/lib/' in dylib_path:
            return dylib_path.split('/')[-1]
        elif '/System/Library/Frameworks/' in dylib_path:
            return dylib_path.replace('/System/Library/Frameworks/', '')
        elif '@rpath/' in dylib_path:
            return dylib_path
        else:
            'CHECK DYLIB CATEGORY HERE.'

    def parse_bind_info(self):
        cmds = ["objdump -bind {}".format(self.fp.replace(' ', '\ ')),
                "objdump -lazy-bind {}".format(self.fp.replace(' ', '\ '))]
        for cmd in cmds:
            output = commands.getstatusoutput(cmd)
            bind_info = output[1].split("\n")[5:]
            for bi in bind_info:
                bi = bi.split()
                if '(weak_import)' in bi:
                    bi.remove('(weak_import)')
                d = {
                    'segment': bi[0],
                    'section': bi[1],
                    'address': int(bi[2], 16),
                    # 'type': bi[3],
                    # 'addend': bi[4],
                    'dylib': bi[-2],
                    'symbol': bi[-1]
                }
                if d['symbol'] in self.except_symbols or 'OBJC_METACLASS' in d['symbol']:
                    continue
                if d['symbol'] in self.bind_indexed_by_symbol:
                    self.bind_indexed_by_symbol[d['symbol']].append(d)
                else:
                    self.bind_indexed_by_symbol[d['symbol']] = [d, ]

                if d['dylib'] not in self.bind_indexed_by_dylib:
                    self.bind_indexed_by_dylib[d['dylib']] = set([d['symbol']])
                else:
                    self.bind_indexed_by_dylib[d['dylib']].add(d['symbol'])

    def parse_exports_trie(self):
        cmd = "objdump -exports-trie {}".format(self.fp.replace(' ', '\ '))
        output = commands.getstatusoutput(cmd)
        exports = output[1].split("\n")[4:]
        for symbol in exports:
            self.exports.add(symbol.split()[-1])

if __name__ == '__main__':
    m = MachO('/Users/gjy/Desktop/L实验室相关/2017-12-毕设/z_samples/pp_apps/出行导航/地图/20170307_60521_190183763700_Where To Go/WTG2')
    m.parse_bind_info()
    print m.bind_indexed_by_symbol['_OBJC_CLASS_$_MKMapItem']





