// Author: William Selby

#!/usr/bin/env python3
"""
encodo_summary.py — non-interactive summary CLI for encodoscope.

Usage:
    python3 encodo_summary.py path/to/file
    python3 encodo_summary.py path/to/file --head 65536
"""

import argparse
import sys
from typing import Optional

from encodo_core import analyze_bytes, load_sample


def bar(label: str, count: int, total: int, width: int = 40) -> None:
    if total <= 0:
        ratio = 0.0
    else:
        ratio = count / total
    bar_len = int(round(ratio * width))
    bar_str = "#" * bar_len
    print(f"{label:20}: {count:8d} ({ratio*100:5.1f}%) {bar_str}")


def print_summary(path: str, file_size: int, sample_len: int, stats) -> None:
    print(f"Encodoscope — {path}")
    print("-" * max(30, len(path) + 14))
    print(f"File size           : {file_size} bytes")
    print(f"Sampled bytes       : {sample_len} bytes")

    fmt = stats["format"] or "None"
    family = stats["family"] or "None"
    print(f"Detected format     : {fmt}")
    print(f"Format family       : {family}")

    enc = stats["text_encoding"] or "None"
    conf = stats["text_confidence"]
    flags = stats["text_flags"]
    print(f"Text encoding guess : {enc} (confidence {conf*100:5.1f}%)")
    print(
        "Text flavor flags   : "
        f"json={flags.get('is_json')}, xml/html={flags.get('is_xml_html')}, urlencoded={flags.get('is_urlencoded')}"
    )
    print()

    print("Basic stats")
    print("-----------")
    print(f"Entropy (Shannon)   : {stats['entropy']:.3f} bits/byte")
    print(f"Printable ratio     : {stats['printable_ratio']*100:5.1f}%")
    print(f"ASCII ratio         : {stats['ascii_ratio']*100:5.1f}%")
    print(f"Null bytes          : {stats['nulls']} ({stats['null_ratio']*100:5.3f}%)")
    print(f"Base64 alphabet use : {stats['base64_ratio']*100:5.1f}% (pure={stats['base64_pure']})")
    print(f"Hex-like use        : {stats['hex_ratio']*100:5.1f}% (pure={stats['hex_pure']}, even_hex={stats['hex_even_length']})")
    print()

    print("Byte class histogram (within sampled bytes)")
    print("-------------------------------------------")
    total = stats["total"]
    bar("Control (0-31,127)", stats["control"], total)
    bar("Printable (text)", stats["printable"], total)
    bar("Extended (>=128)", stats["extended"], total)
    print()

    print("Guesses (higher % = more likely)")
    print("--------------------------------")
    scores = stats["scores"]
    for name, value in sorted(scores.items(), key=lambda kv: kv[1], reverse=True):
        print(f"{name:20}: {value*100:5.1f}%")
    print()

    print("Notes")
    print("-----")
    print("• Plain text: high printable ratio, decodes as UTF, moderate entropy.")
    print("• Base64: only A–Z a–z 0–9 + / = and line breaks; often decodes to another format.")
    print("• Hex dump: only 0–9 A–F a–f plus whitespace; even number of hex digits.")
    print("• URL-encoded: many %xx sequences, with '&' and '=' separators.")
    print("• Compressed: gzip/zip/bzip2/xz/etc. — high entropy, low printable, known magic bytes.")
    print("• Archive: zip/7z/rar/tar — containers for multiple files.")
    print("• Image/audio/video/executable: common binary formats.")
    print("• Random/encrypted: very high entropy, low printable, no known signature or structure.")


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Encodoscope summary — inspect a file's bytes and print a text summary."
    )
    parser.add_argument("path", help="Path to the file to analyze.")
    parser.add_argument(
        "--head",
        type=int,
        default=65536,
        help="Maximum number of bytes to sample from the start of the file (default: 65536).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> None:
    args = parse_args(argv)
    try:
        data, file_size = load_sample(args.path, args.head)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"error: could not read file '{args.path}': {e}", file=sys.stderr)
        sys.exit(1)

    stats = analyze_bytes(data)
    print_summary(args.path, file_size, len(data), stats)


if __name__ == "__main__":
    main()
