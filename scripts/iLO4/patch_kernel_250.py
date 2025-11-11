#!/usr/bin/env python3

import sys

# Patch signature check : BEQ XX -> B XX
PATCH = {
    "offset": 0x1FB1C,
    "size": 4,
    "prev_data": "0400000A",
    "patch": "040000EA"
}

if len(sys.argv) < 2:
    print("usage: {} <kernel.bin>".format(sys.argv[0]))
    sys.exit(1)

# read kernel
with open(sys.argv[1], "rb") as f:
    data = f.read()

# verify existing bytes
check_data = data[PATCH["offset"]:PATCH["offset"] + PATCH["size"]]
expected_bytes = bytes.fromhex(PATCH["prev_data"])
if check_data != expected_bytes:
    print("[-] Error, bad file content at offset 0x{:X}".format(PATCH["offset"]))
    print("\tExpected:\t{}".format(PATCH["prev_data"]))
    print("\tGot:     \t{}".format(check_data.hex()))
    sys.exit(1)

# apply patch
patched_bytes = bytes.fromhex(PATCH["patch"])
data = data[:PATCH["offset"]] + patched_bytes + data[PATCH["offset"] + PATCH["size"]:]

# write patched file
out_file = sys.argv[1] + ".patched"
with open(out_file, "wb") as f:
    f.write(data)

print("[+] Patch applied to {}".format(out_file))
