import idc
import idaapi
import idautils
from types import *


class MSymbol:

    def __init__(self, symbol, bind):
        self.symbol = symbol
        self.bind_info = bind
        self.xrefs = set()
        self.processed = set()
        self.to_find = set()

    # for each bind, find the ref in code segment if exists
    def find_usage(self):
        # print self.symbol
        for bind in self.bind_info:
            ea = bind['address']
            print self.symbol, idc.SegName(ea)
            # print Symbol.check_type(ea)
            for r in MSymbol.check_type(ea):
                type = r['type']
                ea = r['ea']
                if type == 'class':
                    print "Mark the ({})class's methods.".format(hex(ea))
                elif type in ['classref', 'stub', 'got']:
                    self.to_find.add(ea)
                    self.find_xref(ea, self.xrefs, self.to_find, self.processed)
                    pass
                elif 'category' in type:
                    print "Mark the ({})category's methods.".format(hex(ea))
                elif type == 'data':
                    print 'UNDEF.'
                elif type == 'const':
                    print 'UNDEF.'

    #  Find the possible usage in all methods
    @staticmethod
    def find_xref(ea, found, to_find, processed):
        to_find.remove(ea)
        processed.add(ea)
        # print 'Find xrefs of {}, found:{}, to_find:{}'.format(hex(ea), found, to_find)

        if len(list(idautils.XrefsTo(ea))) == 0:
            found.add(ea)
            return
        else:
            for xref in idautils.XrefsTo(ea):
                if idc.SegName(xref.frm) == '__text':
                    fi = idaapi.get_func(xref.frm)
                    if fi and fi.startEA != ea:  # no loop
                        fname = idc.GetFunctionName(xref.frm)
                        if 'sub_' in fname:
                            # if sub in found, means it has been processed and it has no xrefs
                            to_find.add(fi.startEA) if fi.startEA not in processed else None
                        else:
                            found.add(fi.startEA)
                elif idc.SegName(xref.frm) == '__const':
                    print 'CHECK BLOCK. ADD THIS BLOCK TO TO_FIND'
                else:
                    # to_find.add(xref.frm)
                    pass

            if type(to_find) is not NoneType:
                for tf in list(to_find):  # to_find could change during iteration
                    if tf in to_find:
                        MSymbol.find_xref(tf, found, to_find, processed)
                        if type(to_find) is NoneType:
                            return

    @staticmethod
    def check_type(ea):
        seg = idc.SegName(ea)
        asm = idc.GetDisasm(ea)
        ret = []
        if seg == '__objc_const':
            if '__objc2_category' in asm:
                for xref in idautils.XrefsTo(ea-8):
                    if idc.SegName(xref.frm) == '__objc_catlist':
                        ret.append({
                            'type': 'category',
                            'ea': xref.frm  # in __objc_catlist
                        })
                    elif idc.SegName(xref.frm) == '__objc_nlcatlist':
                        ret.append({
                            'type': 'nlcategory',
                            'ea': xref.frm  # in __objc_nlcatlist
                        })

        elif seg == '__objc_classrefs':
            ret.append({
                'type': 'classref',
                'ea': ea  # in __objc_classrefs
            })

        elif seg == '__objc_data':
            if '__objc2_class' in asm:
                for xref in idautils.XrefsTo(ea-8):
                    if idc.SegName(xref.frm) == '__objc_classlist':
                        ret.append({
                            'type': 'class',
                            'ea': xref.frm  # in __objc_classlist
                        })
                    elif idc.SegName(xref.frm) == '__objc_classrefs':
                        ret.append({
                            'type': 'classref',
                            'ea': xref.frm  # __objc_classrefs
                        })

        elif seg == '__got':
            ret.append({
                'type': 'got',
                'ea': ea  # in __got
            })

        elif seg == '__la_symbol_ptr':
            xrefs = list(idautils.XrefsTo(ea))
            if len(xrefs) == 2:
                if xrefs[0].frm == xrefs[1].frm - 4:
                    ret.append({
                        'type': 'stub',
                        'ea': xrefs[0].frm  # in __stubs
                    })
            else:
                print 'LAZY_BIND_PTR ERROR HERE.'

        elif seg == '__data':
            ret.append({
                'type': 'data',
                'ea': ea  # in __data
            })

        elif seg == '__const':
            ret.append({
                'type': 'const',
                'ea': ea  # in __const
            })

        return ret






