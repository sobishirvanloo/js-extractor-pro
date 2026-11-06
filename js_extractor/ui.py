"""
Terminal colours (disabled when stdout is not a TTY, on Windows, or when
NO_COLOR is set — https://no-color.org).
"""
import os
import sys


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if sys.platform == "win32":
        return False
    # stdout may be a pipe, a StringIO, or anything without a real fd (common
    # under pytest capture, nohup, or some IDE consoles) — never crash on import.
    try:
        return os.isatty(sys.stdout.fileno())
    except (AttributeError, ValueError, OSError):
        return getattr(sys.stdout, "isatty", lambda: False)()


_USE_COLOR = _supports_color()



def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text



def green(t):  return _c("32", t)



def yellow(t): return _c("33", t)



def red(t):    return _c("31", t)



def cyan(t):   return _c("36", t)



def bold(t):   return _c("1",  t)

