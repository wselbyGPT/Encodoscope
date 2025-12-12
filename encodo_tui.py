// Author: William Selby

#!/usr/bin/env python3
"""
encodo_tui.py — curses-based file explorer + byte inspector for encodoscope.

Usage:
    python3 encodo_tui.py [start_path] [--head N]

Behavior:
    - If start_path is a directory (default: .), open a TUI file explorer there.
    - If start_path is a file, open its parent directory and pre-select it.

TUI layout:
    - Left pane: directory listing (dirs first, then files), scrollable
    - Right pane: analysis of the selected file (if it's a regular file)

Views (right pane):
    - o: Overview     — entropy, ratios, encoding guesses
    - h: Heatmap      — 16x16 byte heatmap (0x00–0xFF)
    - b: Bins         — 16-bin byte-range histogram
    - g: Guesses      — classification scores with bars
    - p: Pipeline     — shell command hints (base64/hex/compressed/etc.)
    - x: Hex          — hex+ASCII dump of sampled bytes

Navigation:
    - Up / Down / k / j   : move selection
    - PageUp / PageDown   : scroll faster
    - Enter / Right arrow : enter directory
    - Backspace / Left    : go to parent directory
    - + / =               : increase head size (sample more bytes)
    - - / _               : decrease head size
    - r                   : re-analyze current file
    - q                   : quit
"""

import argparse
import os
import sys
from typing import Optional, List, Dict, Any

from encodo_core import analyze_bytes, load_sample

try:
    import curses
except ImportError:
    curses = None


# ---------------------------------------------------------------------------
# Browser state
# ---------------------------------------------------------------------------


class BrowserState:
    def __init__(self, start_path: str, head_size: int) -> None:
        self.head_size = head_size
        self.start_path = os.path.abspath(start_path)

        if os.path.isdir(self.start_path):
            self.current_dir = self.start_path
            self.initial_selection_name = None
        else:
            self.current_dir = os.path.dirname(self.start_path) or "."
            self.initial_selection_name = os.path.basename(self.start_path)

        self.current_dir = os.path.abspath(self.current_dir)

        self.entries: List[Dict[str, Any]] = []
        self.selected_index: int = 0
        self.scroll: int = 0
        self.active_view: str = "overview"  # overview, heatmap, bins, guesses, pipeline, hex
        self.sample_data: bytes = b""
        self.stats: Optional[Dict[str, Any]] = None
        self.file_size_for_entry: int = 0
        self.error_message: str = ""

        self.scan_directory()
        self._select_initial()
        self.load_current_file()

    # --- Directory and selection management --------------------------------

    def scan_directory(self) -> None:
        """Populate self.entries for self.current_dir."""
        entries: List[Dict[str, Any]] = []
        try:
            names = os.listdir(self.current_dir)
        except OSError as e:
            self.error_message = f"Error reading directory: {e}"
            self.entries = []
            self.selected_index = 0
            self.scroll = 0
            return

        # Parent directory entry (..), if applicable
        parent = os.path.dirname(self.current_dir)
        if parent and parent != self.current_dir:
            entries.append({
                "name": "..",
                "path": parent,
                "is_dir": True,
                "size": 0,
            })

        tmp: List[Dict[str, Any]] = []
        for name in names:
            full = os.path.join(self.current_dir, name)
            is_dir = os.path.isdir(full)
            size = 0
            if os.path.isfile(full):
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = 0
            tmp.append({
                "name": name,
                "path": full,
                "is_dir": is_dir,
                "size": size,
            })

        # Sort: dirs first, then files; each alphabetically
        tmp.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        entries.extend(tmp)

        self.entries = entries
        self.error_message = ""
        if self.selected_index >= len(self.entries):
            self.selected_index = max(0, len(self.entries) - 1)

    def _select_initial(self) -> None:
        """If there was an initial file, select it in the first directory view."""
        if self.initial_selection_name is None:
            self.selected_index = 0
            self.scroll = 0
            return

        for i, e in enumerate(self.entries):
            if not e["is_dir"] and e["name"] == self.initial_selection_name:
                self.selected_index = i
                break
        self.scroll = 0
        # Only do this once
        self.initial_selection_name = None

    def current_entry(self) -> Optional[Dict[str, Any]]:
        if 0 <= self.selected_index < len(self.entries):
            return self.entries[self.selected_index]
        return None

    def move_selection(self, delta: int) -> None:
        if not self.entries:
            return
        self.selected_index = max(0, min(self.selected_index + delta, len(self.entries) - 1))
        self.load_current_file()

    def page_selection(self, delta_pages: int, visible_rows: int) -> None:
        if not self.entries or visible_rows <= 0:
            return
        delta = delta_pages * visible_rows
        self.move_selection(delta)

    def go_parent(self) -> None:
        """Go to parent directory, selecting the directory we came from if possible."""
        old_dir = self.current_dir
        parent = os.path.dirname(old_dir)
        if not parent or parent == old_dir:
            return
        old_name = os.path.basename(old_dir)
        self.current_dir = parent
        self.scan_directory()

        # Try to select the directory we came from
        self.selected_index = 0
        for i, e in enumerate(self.entries):
            if e["is_dir"] and e["name"] == old_name:
                self.selected_index = i
                break
        self.scroll = 0
        self.load_current_file()

    def enter_selection(self) -> None:
        """If selection is a directory, descend into it."""
        entry = self.current_entry()
        if entry and entry["is_dir"]:
            self.current_dir = os.path.abspath(entry["path"])
            self.scan_directory()
            self.selected_index = 0
            self.scroll = 0
            self.load_current_file()
        else:
            # For files, analysis is already loaded; nothing special here.
            pass

    def adjust_scroll(self, visible_rows: int) -> None:
        """Ensure selected_index is visible given visible_rows."""
        if visible_rows <= 0:
            self.scroll = 0
            return
        if self.selected_index < self.scroll:
            self.scroll = self.selected_index
        elif self.selected_index >= self.scroll + visible_rows:
            self.scroll = self.selected_index - visible_rows + 1
        if self.scroll < 0:
            self.scroll = 0

    # --- Analysis -----------------------------------------------------------

    def load_current_file(self) -> None:
        """Analyze the currently selected file (if it's a regular file)."""
        entry = self.current_entry()
        self.sample_data = b""
        self.stats = None
        self.file_size_for_entry = 0

        if entry is None:
            self.error_message = "No entries in directory."
            return

        if entry["is_dir"]:
            # Directories are not analyzed as byte streams.
            self.error_message = ""
            return

        try:
            data, file_size = load_sample(entry["path"], self.head_size)
        except FileNotFoundError as e:
            self.error_message = f"File not found: {e}"
            return
        except OSError as e:
            self.error_message = f"Error reading file: {e}"
            return

        self.sample_data = data
        self.file_size_for_entry = file_size
        self.stats = analyze_bytes(data)
        self.error_message = ""

    def change_head_size(self, factor: float) -> None:
        """Scale head_size by factor within a safe range, then re-analyze."""
        new_size = int(self.head_size * factor)
        new_size = max(4096, min(new_size, 16 * 1024 * 1024))  # 4 KiB .. 16 MiB
        if new_size != self.head_size:
            self.head_size = new_size
            self.load_current_file()


# ---------------------------------------------------------------------------
# TUI drawing helpers
# ---------------------------------------------------------------------------


def _draw_header(stdscr, state: BrowserState) -> None:
    h, w = stdscr.getmaxyx()
    dir_line = f"Encodoscope TUI — {state.current_dir}"
    if len(dir_line) > w:
        dir_line = "…" + dir_line[-(w - 1):]
    stdscr.addnstr(0, 0, dir_line.ljust(w), w - 1)

    entry = state.current_entry()
    if entry is None:
        info_line = "(empty directory)"
    elif entry["is_dir"]:
        info_line = f"[DIR]  {entry['name']}/  entries={len(state.entries)}"
    else:
        size = entry["size"]
        if state.stats:
            fmt = state.stats["format"] or "None"
            fam = state.stats["family"] or "None"
            H = state.stats["entropy"]
        else:
            fmt = "None"
            fam = "None"
            H = 0.0
        info_line = (
            f"[FILE] {entry['name']}  size={size}B  head={state.head_size}B  "
            f"fmt={fmt} ({fam})  H={H:.2f}"
        )

    if len(info_line) > w:
        info_line = info_line[: w - 1]
    if h > 1:
        stdscr.addnstr(1, 0, info_line.ljust(w), w - 1)

    # Status / error line
    if h > 2:
        if state.error_message:
            line = f"ERROR: {state.error_message}"
        else:
            line = "Use Up/Down, Enter, Backspace, o/h/b/g/p/x, +/-, r, q"
        stdscr.addnstr(2, 0, line.ljust(w), w - 1)


def _draw_footer(stdscr, state: BrowserState) -> None:
    h, w = stdscr.getmaxyx()
    if h < 2:
        return
    help_line = "[Up/Down] move  [Enter] open dir  [Backspace] parent  [O/H/B/G/P/X] view  [+/-] head  [R] reload  [Q] quit"
    view_line = f"View={state.active_view}  head={state.head_size}B  entries={len(state.entries)}"
    stdscr.addnstr(h - 1, 0, help_line.ljust(w), w - 1)
    if h >= 3:
        stdscr.addnstr(h - 2, 0, view_line.ljust(w), w - 1)


def _draw_left_pane(stdscr, state: BrowserState, top: int, bottom: int, left_w: int) -> None:
    h, w = stdscr.getmaxyx()
    if top > bottom or left_w <= 0:
        return

    visible_rows = bottom - top + 1
    state.adjust_scroll(visible_rows)

    for row in range(visible_rows):
        y = top + row
        if y > bottom:
            break
        idx = state.scroll + row
        if idx >= len(state.entries):
            # blank line
            stdscr.addnstr(y, 0, " ".ljust(left_w), left_w)
            continue
        e = state.entries[idx]
        prefix = "[D]" if e["is_dir"] else "   "
        suffix = "/" if e["is_dir"] and e["name"] not in (".", "..") else ""
        label = f"{prefix} {e['name']}{suffix}"
        line = label[: max(0, left_w - 1)]
        if idx == state.selected_index:
            stdscr.addnstr(y, 0, line.ljust(left_w), left_w, curses.A_REVERSE)
        else:
            stdscr.addnstr(y, 0, line.ljust(left_w), left_w)

    # Vertical separator
    for y in range(top, bottom + 1):
        if left_w < w:
            stdscr.addch(y, left_w, ord("|"))


def _draw_overview_panel(stdscr, state: BrowserState, x: int, top: int, bottom: int) -> None:
    w = stdscr.getmaxyx()[1]
    width = max(0, w - x)
    if width <= 0 or top > bottom:
        return

    entry = state.current_entry()
    if entry is None or entry["is_dir"] or state.stats is None:
        msg = "No regular file selected — choose a file in the left pane."
        stdscr.addnstr(top, x, msg[: width - 1].ljust(width), width - 1)
        return

    s = state.stats
    enc = s["text_encoding"] or "None"
    conf = s["text_confidence"]
    flags = s["text_flags"]

    lines = [
        f"Entropy (Shannon): {s['entropy']:.3f} bits/byte",
        f"Printable ratio : {s['printable_ratio']*100:5.1f}%",
        f"ASCII ratio     : {s['ascii_ratio']*100:5.1f}%",
        f"Null bytes      : {s['nulls']} ({s['null_ratio']*100:5.3f}%)",
        f"Base64 use      : {s['base64_ratio']*100:5.1f}% (pure={s['base64_pure']})",
        f"Hex-like use    : {s['hex_ratio']*100:5.1f}% (pure={s['hex_pure']}, even_hex={s['hex_even_length']})",
        "",
        f"Text encoding   : {enc} (confidence {conf*100:5.1f}%)",
        f"Text flavors    : json={flags.get('is_json')}, xml/html={flags.get('is_xml_html')}, urlencoded={flags.get('is_urlencoded')}",
    ]

    y = top
    for line in lines:
        if y > bottom:
            break
        stdscr.addnstr(y, x, line[: width - 1].ljust(width), width - 1)
        y += 1


def _draw_heatmap_panel(stdscr, state: BrowserState, x: int, top: int, bottom: int) -> None:
    w = stdscr.getmaxyx()[1]
    width = max(0, w - x)
    if width <= 0 or top > bottom:
        return

    entry = state.current_entry()
    if entry is None or entry["is_dir"] or state.stats is None:
        msg = "Heatmap: select a file to analyze."
        stdscr.addnstr(top, x, msg[: width - 1].ljust(width), width - 1)
        return

    counts = state.stats["counts"]
    if not counts:
        msg = "No data sampled."
        stdscr.addnstr(top, x, msg[: width - 1].ljust(width), width - 1)
        return

    max_count = max(counts) or 1
    gradient = " .:-=+*#%@"

    y = top
    if y > bottom:
        return

    title = "Byte heatmap (0x00–0xFF): rows 0x00..0xF0, cols +0..+F"
    stdscr.addnstr(y, x, title[: width - 1].ljust(width), width - 1)
    y += 1

    for row in range(16):
        if y > bottom:
            break
        line_parts = [f"{row*16:02X}-{row*16+15:02X} | "]
        for col in range(16):
            idx = row * 16 + col
            c = counts[idx]
            if c == 0:
                ch = " "
            else:
                level = int((c / max_count) * (len(gradient) - 1))
                ch = gradient[level]
            line_parts.append(ch)
        s = "".join(line_parts)
        stdscr.addnstr(y, x, s[: width - 1].ljust(width), width - 1)
        y += 1


def _draw_bins_panel(stdscr, state: BrowserState, x: int, top: int, bottom: int) -> None:
    w = stdscr.getmaxyx()[1]
    width = max(0, w - x)
    if width <= 0 or top > bottom:
        return

    entry = state.current_entry()
    if entry is None or entry["is_dir"] or state.stats is None:
        msg = "Bins: select a file to analyze."
        stdscr.addnstr(top, x, msg[: width - 1].ljust(width), width - 1)
        return

    counts = state.stats["counts"]
    total = state.stats["total"] or 1

    y = top
    if y > bottom:
        return

    title = "Byte-range histogram (16 bins of 16 values each)"
    stdscr.addnstr(y, x, title[: width - 1].ljust(width), width - 1)
    y += 1

    bins = []
    for i in range(16):
        start = i * 16
        end = start + 16
        bins.append(sum(counts[start:end]))

    max_bin = max(bins) or 1
    bar_width = max(10, width - 16)

    for i, bcount in enumerate(bins):
        if y > bottom:
            break
        rng = f"{i*16:02X}-{i*16+15:02X}"
        length = int((bcount / max_bin) * bar_width)
        bar_str = "#" * length
        line = f"{rng} | {bar_str}"
        stdscr.addnstr(y, x, line[: width - 1].ljust(width), width - 1)
        y += 1


def _draw_guesses_panel(stdscr, state: BrowserState, x: int, top: int, bottom: int) -> None:
    w = stdscr.getmaxyx()[1]
    width = max(0, w - x)
    if width <= 0 or top > bottom:
        return

    entry = state.current_entry()
    if entry is None or entry["is_dir"] or state.stats is None:
        msg = "Guesses: select a file to analyze."
        stdscr.addnstr(top, x, msg[: width - 1].ljust(width), width - 1)
        return

    scores = state.stats["scores"]
    sorted_scores = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)

    y = top
    if y > bottom:
        return

    title = "Guesses (classification scores)"
    stdscr.addnstr(y, x, title[: width - 1].ljust(width), width - 1)
    y += 1

    bar_width = max(10, width - 24)
    for name, value in sorted_scores:
        if y > bottom:
            break
        pct = value * 100.0
        length = int((pct / 100.0) * bar_width)
        bar_str = "#" * length
        line = f"{name:20}: {pct:5.1f}% {bar_str}"
        stdscr.addnstr(y, x, line[: width - 1].ljust(width), width - 1)
        y += 1


def _build_pipeline_lines(path: str, stats: Dict[str, Any]) -> List[str]:
    lines: List[str] = []
    lines.append("Suggested pipelines / commands (hints only; not executed):")
    lines.append("")
    lines.append("1. Inspect raw file:")
    lines.append(f"   file '{path}'")
    lines.append("")

    fmt = stats["format"]
    family = stats["family"]
    base64_pure = stats["base64_pure"]
    hex_pure = stats["hex_pure"]
    hex_even = stats["hex_even_length"]

    if base64_pure:
        lines.append("2. Base64 decode:")
        lines.append(f"   base64 -d '{path}' | file -")
        lines.append("   # If 'file -' reports compressed data, pipe to gunzip/unzip/etc.")
        lines.append("")

    if hex_pure and hex_even:
        lines.append("2. Hex decode:")
        lines.append(f"   tr -d ' \\t\\r\\n' < '{path}' | xxd -r -p | file -")
        lines.append("")

    if fmt == "gzip":
        lines.append("Decompress gzip:")
        lines.append(f"   gunzip -c '{path}' | file -")
        lines.append("")
    elif fmt == "bzip2":
        lines.append("Decompress bzip2:")
        lines.append(f"   bunzip2 -c '{path}' | file -")
        lines.append("")
    elif fmt == "xz":
        lines.append("Decompress xz:")
        lines.append(f"   xz -dc '{path}' | file -")
        lines.append("")
    elif fmt == "zstd":
        lines.append("Decompress zstd:")
        lines.append(f"   zstd -dc '{path}' | file -")
        lines.append("")

    if fmt == "zip":
        lines.append("List zip contents:")
        lines.append(f"   unzip -l '{path}'")
        lines.append("Extract a member:")
        lines.append(f"   unzip -p '{path}' somefile | file -")
        lines.append("")
    elif fmt == "7z":
        lines.append("List 7z contents:")
        lines.append(f"   7z l '{path}'")
        lines.append("")
    elif fmt == "rar":
        lines.append("List rar contents:")
        lines.append(f"   unrar l '{path}'")
        lines.append("")

    if fmt == "tar":
        lines.append("List tar contents:")
        lines.append(f"   tar -tvf '{path}'")
        lines.append("")

    if family == "image":
        lines.append("Image file: inspect with 'file', 'identify', or open in an image viewer.")
        lines.append("")
    elif family == "audio":
        lines.append("Audio file: inspect with 'file', 'ffprobe', or a media player.")
        lines.append("")
    elif family == "video":
        lines.append("Video file: inspect with 'file', 'ffprobe', or a video player.")
        lines.append("")
    elif family == "executable":
        lines.append("Executable file: inspect with 'objdump', 'readelf', etc.")
        lines.append("")
    elif family == "document":
        lines.append("Document file: inspect with 'file', 'pdfinfo', or a viewer.")
        lines.append("")
    elif family == "database":
        lines.append("Database file: inspect with a DB CLI (e.g. sqlite3).")
        lines.append("")

    if stats["scores"].get("random_or_encrypted", 0.0) > 0.3 and family is None:
        lines.append("High-entropy binary with no known signature.")
        lines.append("May be encrypted, compressed with an unknown scheme, or random.")
        lines.append("Consider:")
        lines.append("   • If you expect compression: try '7z l' or similar.")
        lines.append("   • If you expect encryption: you will need the key/mode.")
        lines.append("")

    return lines


def _draw_pipeline_panel(stdscr, state: BrowserState, x: int, top: int, bottom: int) -> None:
    w = stdscr.getmaxyx()[1]
    width = max(0, w - x)
    if width <= 0 or top > bottom:
        return

    entry = state.current_entry()
    if entry is None or entry["is_dir"] or state.stats is None:
        msg = "Pipeline: select a file to see suggested shell commands."
        stdscr.addnstr(top, x, msg[: width - 1].ljust(width), width - 1)
        return

    lines = _build_pipeline_lines(entry["path"], state.stats)
    y = top
    for line in lines:
        if y > bottom:
            break
        stdscr.addnstr(y, x, line[: width - 1].ljust(width), width - 1)
        y += 1


def _draw_hex_panel(stdscr, state: BrowserState, x: int, top: int, bottom: int) -> None:
    w = stdscr.getmaxyx()[1]
    width = max(0, w - x)
    if width <= 0 or top > bottom:
        return

    entry = state.current_entry()
    if entry is None or entry["is_dir"] or not state.sample_data:
        msg = "Hex: select a file to view a hex+ASCII peek."
        stdscr.addnstr(top, x, msg[: width - 1].ljust(width), width - 1)
        return

    data = state.sample_data
    max_bytes = 16 * (bottom - top)  # 16 bytes per row
    data = data[: max_bytes]

    y = top
    offset = 0
    while y <= bottom and offset < len(data):
        chunk = data[offset:offset + 16]
        hex_bytes = " ".join(f"{b:02X}" for b in chunk)
        ascii_chars = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        line = f"{offset:08X}  {hex_bytes:<48}  {ascii_chars}"
        stdscr.addnstr(y, x, line[: width - 1].ljust(width), width - 1)
        offset += 16
        y += 1


# ---------------------------------------------------------------------------
# TUI main loop
# ---------------------------------------------------------------------------


def _tui_main(stdscr, state: BrowserState) -> None:
    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.keypad(True)

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        # Header and status lines
        _draw_header(stdscr, state)

        body_top = 3
        body_bottom = max(body_top, h - 3)
        if body_top > body_bottom:
            _draw_footer(stdscr, state)
            stdscr.refresh()
            ch = stdscr.getch()
            if ch in (ord("q"), ord("Q"), 27):
                break
            continue

        # Layout panes
        left_w = max(25, min(w // 3, w - 20))
        right_x = left_w + 1

        # Left: file list
        _draw_left_pane(stdscr, state, body_top, body_bottom, left_w)

        # Right: current view
        if state.active_view == "overview":
            _draw_overview_panel(stdscr, state, right_x, body_top, body_bottom)
        elif state.active_view == "heatmap":
            _draw_heatmap_panel(stdscr, state, right_x, body_top, body_bottom)
        elif state.active_view == "bins":
            _draw_bins_panel(stdscr, state, right_x, body_top, body_bottom)
        elif state.active_view == "guesses":
            _draw_guesses_panel(stdscr, state, right_x, body_top, body_bottom)
        elif state.active_view == "pipeline":
            _draw_pipeline_panel(stdscr, state, right_x, body_top, body_bottom)
        elif state.active_view == "hex":
            _draw_hex_panel(stdscr, state, right_x, body_top, body_bottom)

        # Footer
        _draw_footer(stdscr, state)

        stdscr.refresh()

        ch = stdscr.getch()
        if ch in (ord("q"), ord("Q"), 27):
            break
        elif ch in (curses.KEY_UP, ord("k")):
            state.move_selection(-1)
        elif ch in (curses.KEY_DOWN, ord("j")):
            state.move_selection(+1)
        elif ch == curses.KEY_PPAGE:
            visible_rows = body_bottom - body_top + 1
            state.page_selection(-1, visible_rows)
        elif ch == curses.KEY_NPAGE:
            visible_rows = body_bottom - body_top + 1
            state.page_selection(+1, visible_rows)
        elif ch in (curses.KEY_ENTER, 10, 13, curses.KEY_RIGHT):
            state.enter_selection()
        elif ch in (curses.KEY_BACKSPACE, 127, curses.KEY_LEFT):
            state.go_parent()
        elif ch in (ord("o"), ord("O")):
            state.active_view = "overview"
        elif ch in (ord("h"), ord("H")):
            state.active_view = "heatmap"
        elif ch in (ord("b"), ord("B")):
            state.active_view = "bins"
        elif ch in (ord("g"), ord("G")):
            state.active_view = "guesses"
        elif ch in (ord("p"), ord("P")):
            state.active_view = "pipeline"
        elif ch in (ord("x"), ord("X")):
            state.active_view = "hex"
        elif ch in (ord("+"), ord("=")):
            state.change_head_size(2.0)
        elif ch in (ord("-"), ord("_")):
            state.change_head_size(0.5)
        elif ch in (ord("r"), ord("R")):
            state.load_current_file()
        elif ch == curses.KEY_RESIZE:
            # Just loop; everything resizes on next iteration.
            pass


# ---------------------------------------------------------------------------
# CLI glue
# ---------------------------------------------------------------------------


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Encodoscope TUI — curses-based file explorer + byte inspector."
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Start path (file or directory). Default: current directory.",
    )
    parser.add_argument(
        "--head",
        type=int,
        default=65536,
        help="Maximum number of bytes to sample from each file (default: 65536).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> None:
    if curses is None:
        print("error: curses is not available in this Python environment.", file=sys.stderr)
        sys.exit(1)

    args = parse_args(argv)
    state = BrowserState(args.path, args.head)
    curses.wrapper(_tui_main, state)


if __name__ == "__main__":
    main()
