#!/usr/bin/env python3

import sys

# Patch signature check : BNE XX -> MOV R0, #0
PATCH = {"offset": 0x38BC, "size": 4, "prev_data": "4000001A", "patch": "0000A0E1"}

if len(sys.argv) < 2:
    print("usage: {} <bootloader.bin>".format(sys.argv[0]))
    sys.exit(1)

with open(sys.argv[1], "rb") as f:
    data = f.read()

check_data = data[PATCH["offset"]:PATCH["offset"] + PATCH["size"]]
expected_data = bytes.fromhex(PATCH["prev_data"])

if check_data != expected_data:
    print("[-] Error, bad file content at offset 0x{:X}".format(PATCH["offset"]))
    print("\t Expected:\t{}".format(PATCH["prev_data"]))
    print("\t Got:\t{}".format(check_data.hex()))
    sys.exit(1)

patched_data = bytes.fromhex(PATCH["patch"])
data = data[:PATCH["offset"]] + patched_data + data[PATCH["offset"] + PATCH["size"]:]

with open(sys.argv[1] + ".patched", "wb") as f:
    f.write(data)

print("[+] Patch applied to {}.patched".format(sys.argv[1]))
