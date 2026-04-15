#!/usr/bin/env python3
"""Launch the SEER console UI.

This script:
- Locates seer_console.py relative to itself
- Determines theme from CLI or environment, with auto-detection fallback
- Passes all non-theme arguments through to seer_console.py
- Executes the console script using python3
"""

import os
import subprocess
import sys
from typing import List, Optional, Tuple


def usage(argv0: str) -> None:
    """Print usage information.

    Args:
        argv0: Program name.

    Returns:
        None
    """
    print(f"usage: {argv0} [--theme THEME]")


def find_console_script() -> Optional[str]:
    """Locate seer_console.py relative to this script.

    Returns:
        Path to console script, or None if not found.
    """
    base = os.path.dirname(os.path.abspath(__file__))

    candidates = [
        os.path.join(base, "seer_console.py"),
        os.path.join(base, "..", "seer_console.py"),
        "/usr/local/bin/seer_console.py",
    ]

    for path in candidates:
        if os.path.isfile(path):
            return path

    return None


def detect_theme() -> str:
    """Auto-detect terminal theme using tput colors.

    Mirrors bash logic: prefer 'evr' when terminal supports >= 16 colors,
    else fall back to 'classic'.

    Returns:
        'evr' if terminal supports >= 16 colors, otherwise 'classic'.
    """
    try:
        result = subprocess.run(
            ["tput", "colors"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        colors = int(result.stdout.strip())
    except Exception:  # Intentional isolation point — tput may be unavailable.
        colors = 0

    return "evr" if colors >= 16 else "classic"


def parse_args(argv: list) -> Tuple[Optional[str], List[str]]:
    """Parse CLI arguments for theme, collecting remaining args for pass-through.

    Unknown arguments are NOT rejected — they are collected and forwarded to
    seer_console.py, matching bash REST_ARGS behavior.

    Args:
        argv: Command-line arguments.

    Returns:
        Tuple of (theme_or_None, list_of_remaining_args).
    """
    args = list(argv[1:])
    theme: Optional[str] = None
    rest: List[str] = []

    while args:
        arg = args.pop(0)

        if arg == "--theme":
            if not args:
                usage(argv[0])
                sys.exit(2)
            theme = args.pop(0)
        elif arg.startswith("--theme="):
            theme = arg.split("=", 1)[1]
        elif arg in ("-h", "--help"):
            usage(argv[0])
            sys.exit(0)
        else:
            # Pass unrecognized args through to seer_console.py (bash REST_ARGS).
            rest.append(arg)

    return theme, rest


def main(argv: list) -> int:
    """Main entry point.

    Args:
        argv: Command-line arguments.

    Returns:
        Exit code; only returns on error. Replaces the process via exec on
        success.
    """
    theme, rest_args = parse_args(argv)

    console = find_console_script()
    if not console:
        print("ERROR: cannot find seer_console.py", file=sys.stderr)
        return 1

    # Theme resolution: CLI > SEER_THEME env > auto-detect (matches bash).
    if theme is None:
        theme = os.environ.get("SEER_THEME")
    if theme is None:
        theme = detect_theme()

    env = os.environ.copy()
    env["SEER_THEME"] = theme

    # Propagate NO_COLORS only when explicitly set to '1' or 'true' (matches bash).
    no_colors = env.get("NO_COLORS")
    if no_colors not in ("1", "true"):
        env.pop("NO_COLORS", None)

    # Build exec command, forwarding all remaining args (bash REST_ARGS parity).
    cmd = ["python3", console] + rest_args

    # True exec (parity with bash `exec python3 "$CONSOLE_PY" "${REST_ARGS[@]:-}"`).
    os.execvpe("python3", cmd, env)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
