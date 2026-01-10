import argparse
import fnmatch
from pathlib import Path
from typing import Iterable, List, Tuple

PRIORITY_RULES: List[Tuple[str, str]] = [
    ("suffix", ".media"),
    ("suffix", ".fi"),
    ("pattern", "*news.com"),
    ("suffix", ".dk"),
    ("suffix", ".lt"),
    ("suffix", ".ee"),
    ("suffix", ".eu"),
    ("suffix", ".live"),
    ("suffix", ".de"),
    ("suffix", ".pl"),
    ("suffix", ".io"),
    ("prefix", "www."),
    ("suffix", ".tv"),
    ("suffix", ".ua"),
    ("suffix", ".app"),
    ("suffix", ".com"),
    ("suffix", ".ru"),
]


def read_domains(path: Path) -> List[str]:
    """Return cleaned domain names from the input file, skipping empty lines."""
    with path.open("r", encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip()]


def write_domains(path: Path, domains: Iterable[str]) -> None:
    """Write domains to the given path, one per line."""
    with path.open("w", encoding="utf-8") as handle:
        for domain in domains:
            handle.write(f"{domain}\n")


def reprioritize(domains: List[str]) -> List[str]:
    """Reorder domains so preferred rules appear first followed by the remainder."""
    remaining = domains[:]
    prioritized: List[str] = []

    for rule_type, rule_value in PRIORITY_RULES:
        if rule_type == "suffix":
            predicate = lambda value, suffix=rule_value: value.lower().endswith(suffix)
        elif rule_type == "pattern":
            lowered = rule_value.lower()
            predicate = lambda value, expected=lowered: fnmatch.fnmatch(
                value.lower(), expected
            )
        elif rule_type == "prefix":
            lowered = rule_value.lower()
            predicate = lambda value, expected=lowered: value.lower().startswith(
                expected
            )
        else:
            # Unknown rule types are ignored.
            continue

        selected, remaining = _extract_matching(remaining, predicate)
        prioritized.extend(selected)
    prioritized.extend(remaining)

    return prioritized


def _extract_matching(
    values: Iterable[str], predicate
) -> tuple[List[str], List[str]]:
    """Partition values based on predicate, preserving order."""
    matching: List[str] = []
    remainder: List[str] = []

    for value in values:
        if predicate(value):
            matching.append(value)
        else:
            remainder.append(value)

    return matching, remainder


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Reorder a list of domains so that specific TLDs and www-prefixed "
            "domains appear first."
        )
    )
    parser.add_argument(
        "--file",
        required=True,
        type=Path,
        help="Path to the input file of domain names.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "Optional output file. When omitted, the reordered domains are "
            "printed to stdout."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    domains = read_domains(args.file)
    reordered = reprioritize(domains)

    if args.output:
        write_domains(args.output, reordered)
    else:
        for domain in reordered:
            print(domain)


if __name__ == "__main__":
    main()
