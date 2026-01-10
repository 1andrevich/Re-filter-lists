#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import ipaddress
from pathlib import Path


def _sort_key(value: str):
    try:
        net = ipaddress.ip_network(value, strict=False)
        return (0, int(net.network_address), net.prefixlen)
    except ValueError:
        return (1, value)


def read_unique_lines(path: Path):
    counts = {}
    ordered = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            value = line.strip()
            if not value:
                continue
            counts[value] = counts.get(value, 0) + 1
            if counts[value] == 1:
                ordered.append(value)
    return ordered, counts


def main():
    parser = argparse.ArgumentParser(description="Remove duplicate IP/CIDR lines.")
    parser.add_argument(
        "--input",
        default="ip_raw.lst",
        help="Input file with duplicates (default: ip_raw.lst)",
    )
    parser.add_argument(
        "--output",
        default="ip.lst",
        help="Output file without duplicates (default: ip.lst)",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    unique_lines, counts = read_unique_lines(input_path)
    unique_lines.sort(key=_sort_key)
    with output_path.open("w", encoding="utf-8") as f:
        for line in unique_lines:
            f.write(f"{line}\n")

    log_path = output_path.with_name("ip_duplicate.log")
    with log_path.open("w", encoding="utf-8") as f:
        removed = 0
        dup_items = [(value, counts[value] - 1) for value in counts if counts[value] > 1]
        dup_items.sort(key=lambda item: (-item[1], _sort_key(item[0])))
        for value, dupes in dup_items:
            removed += dupes
            f.write(f"{value} duplicates_removed={dupes}\n")

    print(f"Wrote {len(unique_lines)} unique lines to {output_path}")
    print(f"Logged {log_path}")


if __name__ == "__main__":
    main()
