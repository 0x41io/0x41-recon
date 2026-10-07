"""
Terminal styling for monomi: the colored banner and status markers.

Uses plain ANSI escape codes (no extra dependency). Color turns itself off
when output isn't a terminal (piping to a file) or when NO_COLOR is set.
"""

import os
import sys

from collectors import VERSION

ENABLED = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def disable() -> None:
    global ENABLED
    ENABLED = False


def rgb(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"


RESET = "\033[0m"
BOLD = "\033[1m"

WHITE = rgb(240, 240, 240)
SILVER = rgb(120, 120, 128)    # shadow edge on the white letters
RED = rgb(255, 40, 60)
DARK_RED = rgb(110, 0, 18)     # shadow edge on the red letters
GREY = rgb(130, 130, 140)
GREEN = rgb(80, 220, 120)
YELLOW = rgb(255, 200, 60)

# Top-to-bottom red gradient for the "41" (bright at the top, deeper below)
RED_RAMP = [rgb(255, 70, 85), rgb(255, 45, 62), rgb(235, 25, 45),
            rgb(210, 15, 35), rgb(180, 8, 28), rgb(150, 0, 22)]


def paint(text: str, *codes: str) -> str:
    return "".join(codes) + text + RESET if ENABLED else text


LOGO = [
    " ██████╗ ██╗  ██╗██╗  ██╗ ██╗",
    "██╔═████╗╚██╗██╔╝██║  ██║███║",
    "██║██╔██║ ╚███╔╝ ███████║╚██║",
    "████╔╝██║ ██╔██╗ ╚════██║ ██║",
    "╚██████╔╝██╔╝ ██╗     ██║ ██║",
    " ╚═════╝ ╚═╝  ╚═╝     ╚═╝ ╚═╝",
]
SPLIT = 17  # column where "0x" ends and "41" begins


def _shade(segment: str, face: str, edge: str) -> str:
    """Solid blocks get the face color, box-drawing 'shadow' gets the edge color."""
    out, current = [], None
    for ch in segment:
        color = face if ch == "█" else edge if ch.strip() else None
        if color and color != current:
            out.append(color)
            current = color
        out.append(ch)
    return "".join(out) + RESET


def banner() -> str:
    side = [
        "",
        f"{paint('mønømi', BOLD, RED)}  {paint('v' + VERSION, GREY)}",
        "",
        paint("passive OSINT · AI analysis", GREY),
        paint("by ", GREY) + paint("0x", WHITE) + paint("41", RED),
        "",
    ]
    lines = []
    for i, row in enumerate(LOGO):
        if ENABLED:
            logo = _shade(row[:SPLIT], WHITE, SILVER) + _shade(row[SPLIT:], RED_RAMP[i], DARK_RED)
        else:
            logo = row
        lines.append(f"{logo}   {side[i]}".rstrip())
    return "\n" + "\n".join(lines) + "\n"


# Status markers used throughout the CLI
def info(msg: str) -> None:
    print(f"{paint('[*]', GREY)} {msg}")


def good(msg: str) -> None:
    print(f"{paint('[+]', GREEN)} {msg}")


def warn(msg: str) -> None:
    print(f"{paint('[!]', YELLOW)} {msg}")


def fail(msg: str) -> None:
    print(f"{paint('[x]', BOLD, RED)} {msg}")
