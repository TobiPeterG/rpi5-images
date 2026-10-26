"""Human-facing terminal output."""

import builtins
import os
import sys
import time
import unicodedata


def terminal_text(value, *, multiline=False, escape_backslash=True):
    """Render untrusted text literally"""
    output = []
    for character in str(value):
        if multiline and character in '\n\t':
            output.append(character)
        elif character == '\\' and escape_backslash:
            output.append('\\\\')
        elif unicodedata.category(character) in {'Cc', 'Cf', 'Cs', 'Zl', 'Zp'}:
            output.append(f'\\u{{{ord(character):x}}}')
        else:
            output.append(character)
    return ''.join(output)


def print(*values, color=None, **options):
    # These are presentation copies only.
    values = tuple(terminal_text(value, multiline=True, escape_backslash=False) for value in values)
    colors = {"red": "31", "yellow": "33", "green": "32"}
    if color is not None and color not in colors:
        raise ValueError(f"unsupported output color: {color}")
    stream = options.get("file", sys.stdout)
    if stream is None:
        stream = sys.stdout
    if color and stream.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb":
        separator = options.get("sep")
        text = (" " if separator is None else separator).join(str(value) for value in values)
        options.pop("sep", None)
        builtins.print(f"\033[{colors[color]}m{text}\033[0m", **options)
    else:
        builtins.print(*values, **options)


def human_size(size):
    """Format a byte count with binary units."""
    value = size
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024 or unit == "PiB":
            return f"{value} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024


class TransferProgress:
    """Single-line progress on interactive terminals."""

    def __init__(self, label, total, stream=None):
        self.stream = sys.stderr if stream is None else stream
        self.label, self.total = label, total
        self.enabled = self.stream.isatty()
        self.last = 0.0
        self.update(0, force=True)

    def update(self, completed, force=False):
        now = time.monotonic()
        if not self.enabled or (not force and completed != self.total and now - self.last < 0.5):
            return
        self.last = now
        percent = min(100, completed * 100 // self.total) if self.total else 100
        filled = percent * 24 // 100
        self.stream.write(f"\r{self.label} [{'#' * filled}{'-' * (24 - filled)}] {percent:3d}% {human_size(completed)} / {human_size(self.total)}")
        self.stream.flush()

    def finish(self):
        if self.enabled:
            self.stream.write("\n")
            self.stream.flush()
