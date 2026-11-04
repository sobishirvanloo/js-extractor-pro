"""
Terminal colours (disabled when stdout is not a TTY, and on Windows).
"""
import os
import sys


_USE_COLOR = sys.platform != "win32" and os.isatty(sys.stdout.fileno())



def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text



def green(t):  return _c("32", t)



def yellow(t): return _c("33", t)



def red(t):    return _c("31", t)



def cyan(t):   return _c("36", t)



def bold(t):   return _c("1",  t)

