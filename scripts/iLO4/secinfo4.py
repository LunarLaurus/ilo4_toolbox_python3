import idaapi
import idc
from ctypes import *

# struct MAP_ENTRY
# {
#   MAP_ENTRY *next;
#   int ptr_name;
#   int base;
#   int size;
#   int access;
#   int field_14;
# };

class MapEntry(LittleEndianStructure):

    _fields_ = [
        ("next", c_uint32),
        ("name_addr", c_uint32),
        ("base", c_uint32),
        ("size", c_uint32),
        ("access", c_uint32),
        ("field_14", c_uint32),
    ]

    def to_str(self, ea):
        max_len = idaapi.get_max_ascii_length(ea, idaapi.ASCSTR_C, 0)
        idaapi.make_ascii_string(ea, max_len, idaapi.ASCSTR_C)
        return idc.get_strlit_contents(ea, max_len, idaapi.ASCSTR_C).decode("utf-8")

    def dump(self):
        print("  {:20s} - base 0x{:08X} - size 0x{:08X} - access : 0x{:X}".format(
            self.to_str(self.name_addr), self.base, self.size, self.access))

    def name(self):
        return "{}".format(self.to_str(self.name_addr))


print("> parsing .secinfo entries:\n")

sid = idc.get_struc_id_by_name('MAP_ENTRY')
ssize = idc.get_struc_size(sid)

# for v 2.44.7 19-Jul-2016
SEC_INFO_LINKED_LIST = 0x200B6A3C

ea = SEC_INFO_LINKED_LIST
entries = []

while True:
    idc.del_items(ea, idc.DOUNK_DELNAMES, ssize)
    idaapi.doStruct(ea, ssize, sid)
    buf = idc.get_bytes(ea, ssize)

    entry = MapEntry.from_buffer_copy(buf)
    entries.append(entry)
    entry.dump()

    if entry.next == 0:
        break

    ea = entry.next


print("\n> setting-up segments:\n")

for entry in [e for e in entries if e.size != 0]:
    idaapi.add_segm(0, entry.base, entry.base + entry.size, entry.name(), "DATA")


bss_list = [e for e in entries if e.name() == '.secinfo']

if len(bss_list) == 1:
    print("\n> parsing BSS entries:\n")

    secinfo = bss_list[0]
    ea = secinfo.base
    sid = idc.get_struc_id_by_name('BSS_ENTRY')
    ssize = idc.get_struc_size(sid)

    while True:
        idc.del_items(ea, idc.DOUNK_DELNAMES, ssize)
        idaapi.doStruct(ea, ssize, sid)
        buf = idc.get_bytes(ea, ssize)
        bsse = BssEntry.from_buffer_copy(buf)

        elist = [e for e in entries if (e.base == bsse.base and e.size != 0)]
        if len(elist) == 1:
            bsse.dump(elist[0].name())
        else:
            bsse.dump()

        ea += ssize
        if ea >= SEC_INFO_LINKED_LIST:
            break


print("\n[+] job done captain!\n")
