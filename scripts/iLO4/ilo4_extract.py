#!/usr/bin/env python3

# Extract binaries from HPIMAGE update file
# Blackbox analysis, might be inaccurate

import os
import sys
import json
import uuid
import binascii
from struct import unpack_from
from collections import OrderedDict
from ilo4lib import *

BEGIN_SIGN = b"--=</Begin HP Signed File Fingerprint\\>=--\n"
END_SIGN = b"--=</End HP Signed File Fingerprint\\>=--\n"
BEGIN_CERT = b"-----BEGIN CERTIFICATE-----\n"
END_CERT = b"-----END CERTIFICATE-----\n"

IMG_LIST = ["elf", "kernel_main", "kernel_recovery"]

HPIMAGE_HDR_SIZE = 0x4A0
BOOTLOADER_HDR_SIZE = 0x440
IMG_HDR_SIZE = 0x440


if len(sys.argv) != 3:
    print("usage: {} <filename> <outdir>".format(sys.argv[0]))
    sys.exit(1)

filename = sys.argv[1]
outdir = sys.argv[2]

os.makedirs(outdir, exist_ok=True)

with open(filename, "rb") as fff:
    data = fff.read()

offsets_map = OrderedDict()
global_offset = 0

#------------------------------------------------------------------------------
# extract certificates

if not data.startswith(BEGIN_SIGN):
    print(f"[-] Bad file format\n    No '{BEGIN_SIGN.decode()}' signature")
    sys.exit(1)

off = data.find(END_SIGN) + len(END_SIGN)
data = data[off:]
offsets_map["HP_SIGNED_FILE"] = 0
global_offset = off

cert_num = 0
while data.startswith(BEGIN_CERT):
    off = data.find(END_CERT) + len(END_CERT)
    cert_data = data[:off]
    data = data[off:]
    offsets_map[f"HP_CERT{cert_num}"] = global_offset
    global_offset += off
    print(f"[+] Extracting certificate {cert_num}")
    with open(os.path.join(outdir, f"cert{cert_num}.x509"), "wb") as fff:
        fff.write(cert_data)
    cert_num += 1


#------------------------------------------------------------------------------
# extract HP images: userland, kernel and bootloader

if not data.startswith(b"HPIMAGE"):
    print("[-] Bad file format\n    HPIMAGE magic not found")
    sys.exit(1)

hpimage_header = data[:HPIMAGE_HDR_SIZE]
data = data[HPIMAGE_HDR_SIZE:]
offsets_map["HPIMAGE_HDR"] = global_offset
global_offset += HPIMAGE_HDR_SIZE

print("[+] iLO HPIMAGE header :")
with open(os.path.join(outdir, "hpimage.hdr"), "wb") as fff:
    fff.write(hpimage_header)

img_hdr = HpImageHeader.from_buffer_copy(hpimage_header)
img_hdr.dump()


#------------------------------------------------------------------------------
# extract target info

targetListsize = unpack_from("<L", data)[0]
print(f"\n[+] iLO target list: {targetListsize:X} element(s)")

data = data[4:]
global_offset += 4

for i in range(targetListsize):
    raw = data[:0x10]
    dev = ""
    id = uuid.UUID(binascii.hexlify(raw).decode())
    if id in TARGETS:
        dev = TARGETS[id]

    print(f"    target 0x{i:X} ({dev})")
    print(hexdump(raw))

    if dev == "":
        print("[x] unknown target")
        sys.exit(0)

    data = data[0x10:]
    global_offset += 0x10

data = data[4:]
global_offset += 4


#------------------------------------------------------------------------------
# get signature: should be iLO3, iLO4 or iLO5

ilo_sign = data[:4]
ilo_bootloader_header = data[:BOOTLOADER_HDR_SIZE]
ilo_bootloader_footer = data[-0x40:]

data = data[BOOTLOADER_HDR_SIZE:]
offsets_map["BOOTLOADER_HDR"] = global_offset
global_offset += BOOTLOADER_HDR_SIZE

print(f"[+] iLO bootloader header : {ilo_bootloader_header[:0x1a]}")
with open(os.path.join(outdir, "bootloader.hdr"), "wb") as fff:
    fff.write(ilo_bootloader_header)

bootloader_header = BootloaderHeader.from_buffer_copy(ilo_bootloader_header)
bootloader_header.dump()

with open(os.path.join(outdir, "bootloader.sig"), "wb") as fff:
    fff.write(bootloader_header.to_str(bootloader_header.signature))


#------------------------------------------------------------------------------
# extract Bootloader footer and cryptographic parameters

print(f"[+] iLO Bootloader footer : {ilo_bootloader_footer[:0x1a]}")
bootloader_footer = BootloaderFooter.from_buffer_copy(ilo_bootloader_footer)
bootloader_footer.dump()

total_size = bootloader_header.total_size
print(f"\ntotal size:    0x{total_size:08X}")
print(f"payload size:  0x{len(data):08X}")
print(f"kernel offset: 0x{bootloader_footer.kernel_offset:08X}\n")

offsets_map["BOOTLOADER"] = global_offset + total_size - bootloader_footer.kernel_offset - BOOTLOADER_HDR_SIZE
ilo_bootloader = data[-bootloader_footer.kernel_offset:-BOOTLOADER_HDR_SIZE]

with open(os.path.join(outdir, "bootloader.bin"), "wb") as fff:
    fff.write(ilo_bootloader)

data = data[:total_size-BOOTLOADER_HDR_SIZE]

ilo_crypto_params = data[len(data)-((~bootloader_footer.sig_offset + 1) & 0xFFFF): len(data)-0x40]
with open(os.path.join(outdir, "sign_params.raw"), "wb") as fff:
    fff.write(ilo_crypto_params)

crypto_params = SignatureParams.from_buffer_copy(ilo_crypto_params)
crypto_params.dump()


#------------------------------------------------------------------------------
# extract images

ilo_num = 0
off = data.find(ilo_sign)

while off >= 0:

    # skip padding
    if data[:off] != b"\xff" * off:
        with open(os.path.join(outdir, "failed_assert.bin"), "wb") as fff:
            fff.write(data)
    assert(data[:off] == b"\xff" * off)
    data = data[off:]
    global_offset += off

    # extract header
    ilo_header = data[:IMG_HDR_SIZE]
    data = data[IMG_HDR_SIZE:]

    with open(os.path.join(outdir, f"{IMG_LIST[ilo_num]}.hdr"), "wb") as fff:
        fff.write(ilo_header)

    print(f"[+] iLO Header {ilo_num}: {ilo_header[:0x1a]}")
    img_header = ImgHeader.from_buffer_copy(ilo_header)
    img_header.dump()

    with open(os.path.join(outdir, f"{IMG_LIST[ilo_num]}.sig"), "wb") as fff:
        fff.write(img_header.to_str(img_header.signature))

    payload_size = img_header.raw_size - IMG_HDR_SIZE
    data1 = data[:payload_size]
    data = data[payload_size:]

    # insert img into offsets map
    offsets_map[f"{IMG_LIST[ilo_num].upper()}_HDR"] = global_offset
    global_offset += IMG_HDR_SIZE
    offsets_map[f"{IMG_LIST[ilo_num].upper()}"] = global_offset
    global_offset += payload_size

    psz, = unpack_from("<L", data1)
    data1 = data1[4:]
    assert(psz == payload_size-4)
    assert(psz == len(data1))

    window = [b'\0'] * 0x1000
    wchar = 0

    with open(os.path.join(outdir, f"{IMG_LIST[ilo_num]}.raw"), "wb") as fff:
        fff.write(data1)

    print("[+] Decompressing")
    output_size = decompress_all(data1, os.path.join(outdir, f"{IMG_LIST[ilo_num]}.bin"))
    print(f"    decompressed size : 0x{output_size:08X}\n")
    print(f"[+] Extracted {IMG_LIST[ilo_num]}.bin")

    off = data.find(ilo_sign)
    ilo_num += 1
    if ilo_num == 3:
        break


#------------------------------------------------------------------------------
# output offsets map

print("[+] Firmware offset map")
for part, offset in offsets_map.items():
    print(f"  > {part:20s} at 0x{offset:08X}")

with open(os.path.join(outdir, "firmware.map"), "w", encoding="utf-8") as fff:
    json.dump(offsets_map, fff, sort_keys=True, indent=4, separators=(',', ': '))

print("\n> done\n")
