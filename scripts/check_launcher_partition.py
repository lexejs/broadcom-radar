#!/usr/bin/env python3
"""Read-only compatibility check against an exported ESP partition table or CSV."""
import argparse
import csv
import pathlib
import struct
import sys


def entries(path):
    if path.suffix.lower() == ".csv":
        for row in csv.reader(line for line in path.read_text().splitlines() if line.strip() and not line.lstrip().startswith("#")):
            label, kind, subtype, offset, size = [part.strip() for part in row[:5]]
            number = lambda value: int(value[:-1], 0) * 1024 if value.lower().endswith("k") else int(value[:-1], 0) * 1024**2 if value.lower().endswith("m") else int(value, 0)
            yield label, 0 if kind == "app" else 1, subtype, number(offset), number(size)
    else:
        data = path.read_bytes()
        for pos in range(0, len(data) - 31, 32):
            magic, kind, subtype, offset, size, label, flags = struct.unpack_from("<HBBII16sI", data, pos)
            if magic in (0xffff, 0xebeb):
                break
            if magic != 0x50aa:
                raise ValueError("Expected a raw ESP partition table (not a whole flash dump)")
            yield label.split(b"\0")[0].decode("ascii"), kind, subtype, offset, size


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("table", type=pathlib.Path)
    parser.add_argument("--label", help="Check only this existing OTA app partition")
    args = parser.parse_args()
    image = args.binary.read_bytes()
    if len(image) < 24 or image[0] != 0xe9 or struct.unpack_from("<H", image, 12)[0] != 9:
        raise ValueError("Expected an ESP32-S3 application image")
    required = (len(image) + 65535) & ~65535
    compatible = []
    for label, kind, subtype, offset, size in entries(args.table):
        ota = isinstance(subtype, int) and 0x10 <= subtype <= 0x1f or isinstance(subtype, str) and subtype.startswith("ota_")
        if kind == 0 and ota and (not args.label or label == args.label):
            fits = size >= required and offset % 65536 == 0 and offset + size <= 8 * 1024**2
            print(f"{label}: offset=0x{offset:x}, size={size}, required={required}, fits={fits}")
            if fits:
                compatible.append(label)
    if not compatible:
        raise SystemExit("No existing compatible OTA slot. Stop; do not repartition automatically.")
    print("Compatible existing slot(s): " + ", ".join(compatible) + ". Installation will overwrite the selected app; back it up first.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(str(error))
