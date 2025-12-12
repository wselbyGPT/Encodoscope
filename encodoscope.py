// Author: William Selby

#!/usr/bin/env python3
"""
encodoscope.py — quick file-encoding/intensity analyzer for the terminal.

Usage:
    python3 encodoscope.py path/to/file
    python3 encodoscope.py path/to/file --head 65536

It:
  - Reads the first N bytes of the file (default 64 KiB)
  - Computes byte statistics (printable vs non-printable, null bytes, etc.)
  - Checks for known file signatures (PNG, ZIP, GZIP, PDF, ELF, ...)
  - Checks if the bytes look like:
        * plain text
        * base64 text
        * hex dump
        * compressed data
        * random / encrypted-like
  - Prints a summary with ASCII histograms and classification guesses.
"""

import argparse
import math
import os
import sys
from typing import Dict, Any, List, Optional


# --- Signature detection ----------------------------------------------------


def detect_magic(prefix: bytes) -> Optional[str]:
    """
    Look at the first few bytes and try to recognize a known format.

    Returns a short string like 'gzip', 'zip', 'png', 'jpeg', 'gif', 'pdf', 'elf',
    or None if nothing matches.
    """
    signatures = [
        (b"\x1f\x8b\x08", "gzip"),              # gzip
        (b"PK\x03\x04", "zip"),                # zip
        (b"PK\x05\x06", "zip"),                # empty zip archive
        (b"PK\x07\x08", "zip"),
        (b"BZh", "bzip2"),                     # bzip2
        (b"\xfd7zXZ\x00", "xz"),               # xz
        (b"\x89PNG\r\n\x1a\n", "png"),         # PNG
        (b"\xff\xd8\xff", "jpeg"),             # JPEG
        (b"GIF87a", "gif"),                    # GIF
        (b"GIF89a", "gif"),
        (b"%PDF-", "pdf"),                     # PDF
        (b"\x7fELF", "elf"),                   # Linux executable
    ]

    for sig, name in signatures:
        if prefix.startswith(sig):
            return name
    return None


# --- Core analysis ----------------------------------------------------------


def shannon_entropy(counts: List[int], total: int) -> float:
    """
    Compute Shannon entropy (bits per byte) from a 256-element count array.
    """
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def analyze_bytes(data: bytes) -> Dict[str, Any]:
    """
    Inspect the raw bytes and compute statistics + category scores.
    """
    total = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    # Basic categories: printable vs control vs extended
    printable_set = set(range(32, 127)) | {9, 10, 13}  # space..~ plus tab/newline/CR

    printable = 0
    control = 0
    extended = 0
    nulls = counts[0]
    ascii_bytes = 0

    for i, c in enumerate(counts):
        if i < 128:
            ascii_bytes += c
        if i in printable_set:
            printable += c
        elif i < 32 or i == 127:
            # Control characters (excluding the printable ones above)
            control += c
        else:
            # Bytes >= 128
            extended += c

    ascii_ratio = ascii_bytes / total if total else 0.0
    printable_ratio = printable / total if total else 0.0
    null_ratio = nulls / total if total else 0.0

    # Base64 "alphabet" check: A-Z a-z 0-9 + / = and newlines
    b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    b64_set = {ord(c) for c in b64_chars}
    # Newlines allowed as line breaks in base64 streams
    b64_allowed_extra = {10, 13}  # \n, \r

    b64_allowed = 0
    for i, c in enumerate(counts):
        if i in b64_set or i in b64_allowed_extra:
            b64_allowed += c

    base64_ratio = b64_allowed / total if total else 0.0
    base64_pure = (b64_allowed == total and total > 0)

    # Hex dump check: 0-9 A-F a-f plus whitespace (space, tab, newline, CR)
    hex_digits = "0123456789abcdefABCDEF"
    hex_set = {ord(c) for c in hex_digits}
    whitespace_set = {ord(c) for c in " \t\r\n"}

    hex_allowed = 0
    for i, c in enumerate(counts):
        if i in hex_set or i in whitespace_set:
            hex_allowed += c

    hex_ratio = hex_allowed / total if total else 0.0
    hex_pure = (hex_allowed == total and total > 0)

    # For hex we also want to know if the number of hex characters is even
    clean_hex_chars = ""
    if hex_pure:
        # Keep only hex digits, drop whitespace
        clean_hex_chars = "".join(
            chr(b)
            for b in data
            if b in hex_set
        )
    hex_even_length = (len(clean_hex_chars) % 2 == 0) if clean_hex_chars else False

    # Entropy
    entropy = shannon_entropy(counts, total)

    # Magic / signature
    signature = detect_magic(data[:16])

    # Category scores (rough, for ranking & display)
    scores = {
        "plain_text": 0.0,
        "base64_text": 0.0,
        "hex_text": 0.0,
        "compressed_data": 0.0,
        "known_binary": 0.0,
        "random_or_encrypted": 0.0,
    }

    # Plain text: mostly printable bytes
    scores["plain_text"] = printable_ratio

    # Base64: all bytes in base64 alphabet (plus newlines)
    if base64_pure:
        scores["base64_text"] = 1.0

    # Hex dump: all bytes are hex digits or whitespace AND even number of hex chars
    if hex_pure and hex_even_length:
        scores["hex_text"] = 1.0

    # Known compressed formats
    if signature in {"gzip", "zip", "bzip2", "xz"}:
        scores["compressed_data"] = 1.0

    # Known binary formats (images, executables, PDFs, etc.)
    if signature in {"png", "jpeg", "gif", "pdf", "elf"}:
        scores["known_binary"] = 1.0

    # High-entropy, low-printable, no known signature: looks like random/encrypted
    if (
        signature is None
        and entropy >= 7.5
        and printable_ratio < 0.3
        and not base64_pure
        and not hex_pure
    ):
        # Scale score loosely with entropy between 7.5 and 8.0
        scores["random_or_encrypted"] = min(1.0, (entropy - 7.5) / 0.5)

    # If everything is zero (e.g., empty file), give a soft default
    if all(v == 0.0 for v in scores.values()):
        if total == 0:
            scores["plain_text"] = 1.0  # empty file is at least "not binary noise"
        elif printable_ratio > 0.5:
            scores["plain_text"] = 0.5
        else:
            scores["known_binary"] = 0.5

    # Normalize scores to sum to 1.0 (so they look like probabilities)
    total_score = sum(scores.values())
    if total_score > 0:
        probs = {k: v / total_score for k, v in scores.items()}
    else:
        probs = {k: 0.0 for k in scores.keys()}

    return {
        "total": total,
        "counts": counts,
        "printable": printable,
        "control": control,
        "extended": extended,
        "nulls": nulls,
        "ascii_bytes": ascii_bytes,
        "ascii_ratio": ascii_ratio,
        "printable_ratio": printable_ratio,
        "null_ratio": null_ratio,
        "base64_ratio": base64_ratio,
        "base64_pure": base64_pure,
        "hex_ratio": hex_ratio,
        "hex_pure": hex_pure,
        "hex_even_length": hex_even_length,
        "entropy": entropy,
        "signature": signature,
        "scores": probs,
    }


# --- Pretty-printing --------------------------------------------------------


def bar(label: str, count: int, total: int, width: int = 40) -> None:
    """
    Print a simple ASCII bar for proportion of 'count' out of 'total'.
    """
    if total <= 0:
        ratio = 0.0
    else:
        ratio = count / total

    bar_len = int(round(ratio * width))
    bar_str = "#" * bar_len
    print(f"{label:20}: {count:8d} ({ratio*100:5.1f}%) {bar_str}")


def print_summary(path: str, file_size: int, sample_len: int, stats: Dict[str, Any]) -> None:
    """
    Print a human-friendly summary of the analysis.
    """
    print(f"Encodoscope — {path}")
    print("-" * max(30, len(path) + 14))
    print(f"File size           : {file_size} bytes")
    print(f"Sampled bytes       : {sample_len} bytes")

    sig = stats["signature"] or "None"
    print(f"Detected signature  : {sig}")
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
    print("• Plain text: high printable ratio, low entropy, ASCII-heavy.")
    print("• Base64: only A–Z a–z 0–9 + / = and line breaks; often decodes to something else.")
    print("• Hex dump: only 0–9 A–F a–f plus whitespace; even number of hex digits.")
    print("• Compressed: recognized signatures (gzip/zip/etc.), high entropy, low printables.")
    print("• Random/encrypted: very high entropy, low printable, no known signature.")


# --- CLI glue ---------------------------------------------------------------


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Inspect a file's bytes to guess encoding/compression characteristics."
    )
    parser.add_argument(
        "path",
        help="Path to the file to analyze.",
    )
    parser.add_argument(
        "--head",
        type=int,
        default=65536,
        help="Maximum number of bytes to sample from the start of the file (default: 65536).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> None:
    args = parse_args(argv)
    path = args.path

    if not os.path.isfile(path):
        print(f"error: '{path}' is not a regular file or does not exist.", file=sys.stderr)
        sys.exit(1)

    file_size = os.path.getsize(path)

    try:
        with open(path, "rb") as f:
            data = f.read(args.head)
    except OSError as e:
        print(f"error: could not read file '{path}': {e}", file=sys.stderr)
        sys.exit(1)

    stats = analyze_bytes(data)
    print_summary(path, file_size, len(data), stats)


if __name__ == "__main__":
    main()
