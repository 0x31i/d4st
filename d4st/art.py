"""Terminal delight for d4st — a startup banner and small creature art shown at
scan-phase boundaries.

Everything here is **cosmetic and output-safe**:

* All art is written to **stderr**, never stdout, so it can never contaminate
  ``--json`` output, a piped findings file, or anything a downstream tool reads.
* It is **TTY-gated**. If stderr is not an interactive terminal, or ``D4ST_NO_ART``
  is set, or we are in CI, nothing is emitted. Reports, logs, and automated runs
  stay perfectly clean.
* It does **no** network, no disk, and no meaningful CPU — a handful of prints.

So the tool is fun to drive by hand, and byte-for-byte identical in a pipeline.
"""

from __future__ import annotations

import os
import sys

from . import __version__

# ── gating ──────────────────────────────────────────────────────────────────


def art_enabled() -> bool:
    """True only when it is safe + wanted to draw. stderr must be a real TTY,
    the user must not have opted out, and we must not be in CI."""
    if os.environ.get("D4ST_NO_ART"):
        return False
    if os.environ.get("CI") or os.environ.get("D4ST_JSON"):
        return False
    try:
        return sys.stderr.isatty()
    except Exception:  # noqa: BLE001
        return False


def _err(text: str) -> None:
    try:
        sys.stderr.write(text + "\n")
        sys.stderr.flush()
    except Exception:  # noqa: BLE001,S110
        pass


# ── startup banner ──────────────────────────────────────────────────────────

_BANNER = r"""
     ██████╗  ██╗  ██╗ ███████╗ ████████╗
     ██╔══██╗ ██║  ██║ ██╔════╝ ╚══██╔══╝
     ██║  ██║ ███████║ ███████╗    ██║
     ██║  ██║ ╚════██║ ╚════██║    ██║
     ██████╔╝      ██║ ███████║    ██║
     ╚═════╝       ╚═╝ ╚══════╝    ╚═╝
"""

# ANSI (used directly so the banner works even before rich is configured)
_PURPLE = "\033[38;5;99m"
_VIOLET = "\033[38;5;141m"
_DIM = "\033[38;5;244m"
_GREEN = "\033[38;5;114m"
_RST = "\033[0m"
_BOLD = "\033[1m"


def banner(subtitle: str = "standalone open-source DAST appliance") -> None:
    """Draw the d4st wordmark once, at startup. No-op unless art is enabled."""
    if not art_enabled():
        return
    color = _VIOLET if sys.stderr.isatty() else ""
    rst = _RST if color else ""
    _err(color + _BANNER.rstrip("\n") + rst)
    tag = f"{_DIM}     v{__version__}  ·  {subtitle}{rst}" if color else f"     v{__version__}  ·  {subtitle}"
    _err(tag)
    _err("")


# ── creature art (phase flair) ──────────────────────────────────────────────
# Small, tasteful ASCII. Purely decorative — a wink at long-running phases.

_CREATURES: dict[str, str] = {
    "pikachu": r"""
      /\   /\
     ( o.o )   ~pika pika~
      > ^ <
     /|   |\
    (_|   |_)  //
     '|   |'  //
      \___/ =v
    """,
    "bulbasaur": r"""
         .-=~~~=-.
        / ,-. ,-. \    ~bulba~
       |  (o) (o)  |
       |    <>     |
        \  \___/  /
         `-.___.-'
          //   \\
    """,
    "charmander": r"""
        ,--.
       ( oo )        ~char!~
       /`--'\
      |      |___
       \    /    \_
        `--'   (~)/  ~flame tail~
              (~~)
    """,
    "squirtle": r"""
       .------.
      / -    - \     ~squirt~
     |    <>    |
      \  \__/  /
      /`------'\~
     '._{####}_.'   ~water~
    """,
    "eevee": r"""
      |\_   _/|
      |  \_/  |      ~vee!~
      ( o   o )
       )  ^  (
      /_/vvv\_\
        (___)
    """,
    "gengar": r"""
      .-^^^^^-.
     / >     < \     ~gengaar~
    |  (o) (o)  |
     \  \___/  /
      `-vvvvv-'
       ^^   ^^
    """,
    "snorlax": r"""
        _.-''''-._
      .'  z  z  z  '.
     /   .------.    \
    |   ( -    - )    |   ~snooore~
     \   '------'    /
      '-.________.-'
    """,
    "magikarp": r"""
              _
           .-' '.
      ><((( o    >   ~splash splash~
           '-._.'
            >< ><
    """,
    "psyduck": r"""
       \       /
        \(o o)/       ~psy... yduck?~
         ( - )
         /   \
        _|   |_
       (___|___)
    """,
    "mewtwo": r"""
        .---.
       / o o \        ~mew... two~
      (   V   )
       \ '-' /___
        `---'    \_
         |  |     (~)  ~psychic~
    """,
}

# Which creature greets which scan phase. Missing phases fall back to a rotation.
_PHASE_CREATURE = {
    "session": "eevee",
    "crawl": "pikachu",
    "discover": "bulbasaur",
    "active": "charmander",
    "attack": "gengar",
    "verify": "psyduck",
    "capture": "squirtle",
    "report": "snorlax",
}
_ROTATION = ["pikachu", "bulbasaur", "charmander", "squirtle", "eevee", "gengar", "magikarp"]


def _pick(phase_key: str) -> str:
    if phase_key in _PHASE_CREATURE:
        return _PHASE_CREATURE[phase_key]
    # deterministic-but-varied: index by phase name length so it is stable per phase
    return _ROTATION[len(phase_key) % len(_ROTATION)]


def phase(title: str = "", subtitle: str = "", phase_key: str | None = None) -> None:
    """Draw a creature to mark a scan phase. No-op unless art is enabled.

    The real phase status/commands are printed by the CLI itself — this only adds
    the ASCII art plus a ``-NAME`` tag so the creature is easy to identify.
    ``phase_key`` (or ``title``) selects which creature."""
    if not art_enabled():
        return
    sel = (phase_key or title).strip().lower()
    key = sel.split()[0] if sel else "d4st"
    name = _pick(key)
    art = _CREATURES.get(name, "").rstrip("\n")
    color = _VIOLET if sys.stderr.isatty() else ""
    dim = _DIM if color else ""
    rst = _RST if color else ""
    _err("")
    _err(f"{color}{art}{rst}")
    _err(f"        {dim}-{name.upper()}{rst}")
    _err("")


def wink(message: str) -> None:
    """A one-line dim aside (e.g. between minor steps). No creature."""
    if not art_enabled():
        return
    color = _DIM if sys.stderr.isatty() else ""
    rst = _RST if color else ""
    _err(f"  {color}{message}{rst}")
