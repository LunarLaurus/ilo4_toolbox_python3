import idc

def dump_memory_region(ea):

    idc.create_struct(ea, "MEMORY_REGION")

    id_val = idc.get_wide_dword(ea)
    low = idc.get_wide_dword(ea + 8)
    high = idc.get_wide_dword(ea + 0xC)
    intv = idc.get_wide_dword(ea + 0x14)
    name_ptr = idc.get_wide_dword(ea + 0x20)

    mem_bytes = idc.get_strlit_contents(name_ptr, -1, idc.ASCSTR_C)
    memory_region = mem_bytes.decode("utf-8") if mem_bytes else "<unknown>"

    print("    flags: 0x{:04X} - int 0x{:X} - reg: {:10s} - low 0x{:08X} / high 0x{:08X}".format(
        id_val, intv, memory_region, low, high
    ))

    if memory_region.startswith("MR"):
        idc.set_name(ea, memory_region, idc.SN_PUBLIC)


# for v 2.44.7 19-Jul-2016
START_ADDR = 0x200BCA00

ea = START_ADDR

print("> parsing memory region entries:\n")

while True:
    idc.create_dword(ea)
    struct_addr = idc.get_wide_dword(ea)
    if struct_addr == 0:
        break

    idc.set_type(ea, "MEMORY_REGION *")
    dump_memory_region(struct_addr)
    ea += 4

print("[+] job done captain!")
