import json
import sys
from pathlib import Path


def convert_to_amnezia_records(lines):
    for raw in lines:
        s = raw.strip()
        if s:
            yield {"hostname": s, "ip": ""}


def main():
    if len(sys.argv) != 3:
        sys.exit("Usage: python convert.py <input_path> <output_path>")

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    if not input_path.exists():
        sys.exit(f"Input file not found: {input_path}")

    with input_path.open("r", encoding="utf-8") as f:
        records = list(convert_to_amnezia_records(f))

    json_text = json.dumps(records, ensure_ascii=True, separators=(",", ":"))
    output_path.write_text(json_text, encoding="utf-8")


if __name__ == "__main__":
    main()
