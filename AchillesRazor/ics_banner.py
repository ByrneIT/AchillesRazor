"""Startup banner for AchillesRazor's CLI.

Tron-grid aesthetic: blue frame/grid, gold blade accent. Colors are only
emitted when stdout is a real terminal (sys.stdout.isatty()) so piped or
redirected output (logs, files, `| jq`, etc.) gets plain text instead of
raw ANSI escape codes.
"""

import sys

BLUE = "\033[38;5;39m"
GOLD = "\033[38;5;220m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

WIDTH = 80
INNER = WIDTH - 2  # inside the ║ ... ║ borders

# 5-row block font. Each glyph is a fixed width per character (4, except
# 'I' and ' ' which are narrower) so words can be composed by simple
# concatenation with a 1-column gap.
_FONT = {
    "A": [" ██ ", "█  █", "████", "█  █", "█  █"],
    "C": [" ███", "█   ", "█   ", "█   ", " ███"],
    "H": ["█  █", "█  █", "████", "█  █", "█  █"],
    "I": ["███", " █ ", " █ ", " █ ", "███"],
    "L": ["█   ", "█   ", "█   ", "█   ", "████"],
    "E": ["████", "█   ", "███ ", "█   ", "████"],
    "S": [" ███", "█   ", " ██ ", "   █", "███ "],
    "R": ["███ ", "█  █", "███ ", "█ █ ", "█  █"],
    "Z": ["████", "   █", "  █ ", " █  ", "████"],
    "O": [" ██ ", "█  █", "█  █", "█  █", " ██ "],
    " ": ["  ", "  ", "  ", "  ", "  "],
}


def _render_word(word):
    """Render a word as 5 lines of block-font text.

    Every row is padded to the same width (rather than stripped
    individually) so letter columns stay vertically aligned - a per-row
    rstrip() here would shift each row's centering independently and make
    the word look slanted.
    """
    rows = ["", "", "", "", ""]
    for ch in word:
        glyph = _FONT[ch]
        for i in range(5):
            rows[i] += glyph[i] + "  "
    width = max(len(r) for r in rows)
    return [r.ljust(width) for r in rows]


def _center(text, width=INNER):
    pad = max(0, width - len(text))
    left = pad // 2
    right = pad - left
    return (" " * left) + text + (" " * right)


def _row(content, color=None):
    """Wrap a line of interior content with the box border."""
    line = _center(content) if len(content) <= INNER else content[:INNER]
    if color:
        return f"{BLUE}║{RESET}{color}{line}{RESET}{BLUE}║{RESET}"
    return f"║{line}║"


def _blade_divider(color):
    """A grid line sliced by a diagonal blade edge."""
    left = "─" * 33
    blade = "◢█◣"
    right = "─" * (INNER - len(left) - len(blade))
    if color:
        return f"{BLUE}║{RESET}{BLUE}{left}{RESET}{GOLD}{blade}{RESET}{BLUE}{right}{RESET}{BLUE}║{RESET}"
    return f"║{left}{blade}{right}║"


def get_banner(version="1.0.0", color=None):
    """Build the full banner as a single string.

    color=None auto-detects sys.stdout.isatty(); pass True/False to force.
    """
    if color is None:
        color = sys.stdout.isatty()

    blue = BLUE if color else ""
    gold = GOLD if color else ""
    bold = BOLD if color else ""
    dim = DIM if color else ""
    reset = RESET if color else ""

    lines = []
    top = "╔" + ("═" * INNER) + "╗"
    bottom = "╚" + ("═" * INNER) + "╝"
    blank = _row("", None)

    lines.append(f"{blue}{top}{reset}" if color else top)
    lines.append(blank)

    for text_row in _render_word("ACHILLES"):
        lines.append(_row(text_row, f"{bold}{blue}" if color else None))

    lines.append(_blade_divider(color))

    for text_row in _render_word("RAZOR"):
        lines.append(_row(text_row, f"{bold}{gold}" if color else None))

    lines.append(blank)
    tagline = f"OT / ICS Passive Security Scanner{' ' * 4}v{version}"
    lines.append(_row(tagline, dim if color else None))
    lines.append(blank)
    lines.append(f"{blue}{bottom}{reset}" if color else bottom)

    return "\n".join(lines)


def print_banner(version="1.0.0"):
    print(get_banner(version=version))
    print()
