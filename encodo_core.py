// Author: William Selby

#!/usr/bin/env python3
"""
encodo_core.py — core analysis logic for encodoscope.

Provides:
    - detect_file_format(data)
    - detect_text_flavor(data)
    - analyze_bytes(data)
    - load_sample(path, head)
"""

import math
import os
import re
from typing import Dict, Any, List, Optional, Tuple


# --- Format / magic detection ------------------------------------------------


def detect_file_format(data: bytes) -> Dict[str, Optional[str]]:
    """
    Inspect the byte prefix (and some known offsets) to detect a specific format
    and a broader family category.

    Returns dict with:
        format: 'gzip', 'zip', 'png', 'jpeg', 'tar', 'mp3', 'sqlite3', ...
        family: 'compressed', 'archive', 'image', 'audio', 'video',
                'executable', 'document', 'database', or None
    """
    fmt = None
    family = None
    n = len(data)

    def starts(prefix: bytes) -> bool:
        return n >= len(prefix) and data.startswith(prefix)

    # --- Compressed / archive formats ---
    if starts(b"\x1f\x8b\x08"):
        fmt, family = "gzip", "compressed"
    elif starts(b"PK\x03\x04") or starts(b"PK\x05\x06") or starts(b"PK\x07\x08"):
        fmt, family = "zip", "archive"
    elif starts(b"BZh"):
        fmt, family = "bzip2", "compressed"
    elif starts(b"\xfd7zXZ\x00"):
        fmt, family = "xz", "compressed"
    elif starts(b"\x37\x7A\xBC\xAF\x27\x1C"):
        fmt, family = "7z", "archive"
    elif starts(b"Rar!\x1A\x07\x00") or starts(b"Rar!\x1A\x07\x01"):
        fmt, family = "rar", "archive"
    elif starts(b"\x28\xB5\x2F\xFD"):
        fmt, family = "zstd", "compressed"
    elif starts(b"\x04\x22\x4D\x18"):
        fmt, family = "lz4", "compressed"
    else:
        # Tar: "ustar" magic at offset 257
        if n >= 262:
            magic = data[257:262]
            if magic in (b"ustar", b"ustar\x00"):
                fmt, family = "tar", "archive"

    # --- Images ---
    if fmt is None:
        if starts(b"\x89PNG\r\n\x1a\n"):
            fmt, family = "png", "image"
        elif starts(b"\xff\xd8\xff"):
            fmt, family = "jpeg", "image"
        elif starts(b"GIF87a") or starts(b"GIF89a"):
            fmt, family = "gif", "image"
        elif starts(b"BM"):
            fmt, family = "bmp", "image"
        elif starts(b"\x00\x00\x01\x00"):
            fmt, family = "ico", "image"
        elif starts(b"RIFF") and n >= 12 and data[8:12] == b"WEBP":
            fmt, family = "webp", "image"
        elif starts(b"II*\x00") or starts(b"MM\x00*"):
            fmt, family = "tiff", "image"

    # --- Audio / video ---
    if fmt is None:
        if starts(b"RIFF") and n >= 12:
            typ = data[8:12]
            if typ == b"WAVE":
                fmt, family = "wav", "audio"
            elif typ == b"AVI ":
                fmt, family = "avi", "video"
        elif starts(b"fLaC"):
            fmt, family = "flac", "audio"
        elif starts(b"OggS"):
            fmt, family = "ogg", "audio"
        elif starts(b"ID3"):
            fmt, family = "mp3", "audio"
        elif n >= 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
            fmt, family = "mp3", "audio"
        elif n >= 12 and data[4:8] == b"ftyp":
            fmt, family = "mp4_family", "video"
        elif starts(b"\x1A\x45\xDF\xA3"):
            fmt, family = "mkv", "video"

    # --- Executables / libraries ---
    if fmt is None:
        if starts(b"\x7fELF"):
            fmt, family = "elf", "executable"
        elif starts(b"MZ"):
            fmt, family = "pe", "executable"

    # --- Documents / databases ---
    if fmt is None:
        if starts(b"%PDF-"):
            fmt, family = "pdf", "document"
        elif starts(b"SQLite format 3\x00"):
            fmt, family = "sqlite3", "database"

    return {"format": fmt, "family": family}


# --- Text / encoding detection ----------------------------------------------


def detect_text_flavor(data: bytes) -> Tuple[Optional[str], str, float, Dict[str, bool]]:
    """
    Try to treat the bytes as text and detect encoding & structure.

    Returns:
        encoding: 'utf-8', 'utf-16-le', 'utf-16-be', 'utf-32-le', 'utf-32-be',
                  'latin-1', 'utf-8-sig', or None.
        text: decoded string (possibly empty)
        confidence: rough 0..1 how text-like it looks
        flags: dict of booleans: is_json, is_xml_html, is_urlencoded
    """
    if not data:
        return None, "", 1.0, {"is_json": False, "is_xml_html": False, "is_urlencoded": False}

    encoding = None
    decoded = None

    if data.startswith(b"\xff\xfe\x00\x00"):
        candidate_enc = "utf-32-le"
    elif data.startswith(b"\x00\x00\xfe\xff"):
        candidate_enc = "utf-32-be"
    elif data.startswith(b"\xff\xfe"):
        candidate_enc = "utf-16-le"
    elif data.startswith(b"\xfe\xff"):
        candidate_enc = "utf-16-be"
    elif data.startswith(b"\xef\xbb\xbf"):
        candidate_enc = "utf-8-sig"
    else:
        candidate_enc = "utf-8"

    tried = set()

    def try_decode(enc: str) -> Optional[str]:
        nonlocal encoding
        if enc in tried:
            return None
        tried.add(enc)
        try:
            text = data.decode(enc, errors="strict")
            encoding = enc
            return text
        except UnicodeDecodeError:
            return None

    decoded = try_decode(candidate_enc)
    if decoded is None:
        for enc in ("utf-8", "latin-1"):
            decoded = try_decode(enc)
            if decoded is not None:
                break

    if decoded is None:
        return None, "", 0.0, {"is_json": False, "is_xml_html": False, "is_urlencoded": False}

    if not decoded:
        confidence = 1.0
    else:
        printable_chars = sum(1 for ch in decoded if (ch.isprintable() or ch in "\r\n\t"))
        confidence = printable_chars / len(decoded)

    flags = {"is_json": False, "is_xml_html": False, "is_urlencoded": False}
    stripped = decoded.lstrip()
    lower_strip = stripped.lower()

    if stripped and stripped[0] in "{[" and any(c in decoded for c in (":", ",", '"')):
        flags["is_json"] = True
    if lower_strip.startswith("<?xml") or lower_strip.startswith("<!doctype html") or lower_strip.startswith("<html"):
        flags["is_xml_html"] = True
    elif stripped.startswith("<") and ">" in stripped[:200]:
        flags["is_xml_html"] = True

    percent_sequences = len(re.findall(r"%[0-9A-Fa-f]{2}", decoded))
    ampersands = decoded.count("&")
    equals = decoded.count("=")
    if percent_sequences >= 3 and ampersands >= 1 and equals >= 1:
        flags["is_urlencoded"] = True

    return encoding, decoded, confidence, flags


# --- Core numeric analysis ---------------------------------------------------


def shannon_entropy(counts: List[int], total: int) -> float:
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def analyze_bytes(data: bytes) -> Dict[str, Any]:
    total = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1

    printable_set = set(range(32, 127)) | {9, 10, 13}

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
            control += c
        else:
            extended += c

    ascii_ratio = ascii_bytes / total if total else 0.0
    printable_ratio = printable / total if total else 0.0
    null_ratio = nulls / total if total else 0.0

    b64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    b64_set = {ord(c) for c in b64_chars}
    b64_extra = {10, 13}
    b64_allowed = 0
    for i, c in enumerate(counts):
        if i in b64_set or i in b64_extra:
            b64_allowed += c
    base64_ratio = b64_allowed / total if total else 0.0
    base64_pure = (b64_allowed == total and total > 0)

    hex_digits = "0123456789abcdefABCDEF"
    hex_set = {ord(c) for c in hex_digits}
    whitespace_set = {ord(c) for c in " \t\r\n"}

    hex_allowed = 0
    for i, c in enumerate(counts):
        if i in hex_set or i in whitespace_set:
            hex_allowed += c
    hex_ratio = hex_allowed / total if total else 0.0
    hex_pure = (hex_allowed == total and total > 0)

    clean_hex_chars = ""
    if hex_pure:
        clean_hex_chars = "".join(chr(b) for b in data if b in hex_set)
    hex_even_length = (len(clean_hex_chars) % 2 == 0) if clean_hex_chars else False

    if base64_pure and hex_pure:
        base64_pure = False

    entropy = shannon_entropy(counts, total)

    fmt_info = detect_file_format(data)
    signature = fmt_info["format"]
    family = fmt_info["family"]

    text_encoding, decoded_text, text_confidence, text_flags = detect_text_flavor(data)
    is_probably_text = (
        text_encoding is not None
        and text_confidence >= 0.8
        and printable_ratio >= 0.5
    )

    scores = {
        "plain_text": 0.0,
        "utf16_text": 0.0,
        "json_text": 0.0,
        "xml_html_text": 0.0,
        "urlencoded_form": 0.0,
        "base64_text": 0.0,
        "hex_text": 0.0,
        "compressed_data": 0.0,
        "archive_data": 0.0,
        "image_binary": 0.0,
        "audio_video_binary": 0.0,
        "executable_binary": 0.0,
        "document_file": 0.0,
        "database_file": 0.0,
        "generic_binary": 0.0,
        "random_or_encrypted": 0.0,
    }

    if is_probably_text and not base64_pure and not hex_pure:
        scores["plain_text"] += 1.0
    if text_encoding in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
        scores["utf16_text"] += 1.0

    if text_flags.get("is_json"):
        scores["json_text"] += 1.5
    if text_flags.get("is_xml_html"):
        scores["xml_html_text"] += 1.5
    if text_flags.get("is_urlencoded"):
        scores["urlencoded_form"] += 1.5

    if base64_pure:
        scores["base64_text"] += 2.0
    if hex_pure and hex_even_length:
        scores["hex_text"] += 2.0

    if family == "compressed":
        scores["compressed_data"] += 2.0
    if family == "archive":
        scores["archive_data"] += 2.0
    if family == "image":
        scores["image_binary"] += 2.0
    if family == "audio":
        scores["audio_video_binary"] += 2.0
    if family == "video":
        scores["audio_video_binary"] += 2.0
    if family == "executable":
        scores["executable_binary"] += 2.0
    if family == "document":
        scores["document_file"] += 2.0
    if family == "database":
        scores["database_file"] += 2.0

    looks_random = (
        family is None
        and entropy >= 7.5
        and printable_ratio < 0.5
        and not base64_pure
        and not hex_pure
        and not is_probably_text
    )
    if looks_random:
        scores["random_or_encrypted"] += min(2.0, 1.0 + (entropy - 7.5) / 0.25)

    if all(v == 0.0 for v in scores.values()):
        if total == 0:
            scores["plain_text"] = 1.0
        elif is_probably_text:
            scores["plain_text"] = 1.0
        elif printable_ratio > 0.5:
            scores["plain_text"] = 0.7
            scores["generic_binary"] = 0.3
        else:
            scores["generic_binary"] = 1.0

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
        "format": signature,
        "family": family,
        "text_encoding": text_encoding,
        "text_confidence": text_confidence,
        "text_flags": text_flags,
        "scores": probs,
    }


def load_sample(path: str, head: int) -> Tuple[bytes, int]:
    """
    Read up to 'head' bytes from file at 'path' and return (data, file_size).
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"'{path}' is not a regular file or does not exist.")
    file_size = os.path.getsize(path)
    with open(path, "rb") as f:
        data = f.read(head)
    return data, file_size
