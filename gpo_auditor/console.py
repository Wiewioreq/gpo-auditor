"""Console utilities: colors, progress bar, icons, banner, HTML escape helper."""

import os
import sys
import html
from typing import Any


def h(text: Any) -> str:
    """Safely escape HTML entities."""
    if text is None:
        return ''
    return html.escape(str(text))


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'

    _supports_color = None
    _supports_unicode = None

    @classmethod
    def supports_color(cls) -> bool:
        """Check if terminal supports colors."""
        if cls._supports_color is not None:
            return cls._supports_color

        # Check for NO_COLOR env variable
        if os.environ.get('NO_COLOR'):
            cls._supports_color = False
            return False

        # Check for FORCE_COLOR env variable
        if os.environ.get('FORCE_COLOR'):
            cls._supports_color = True
            return True

        if sys.platform == 'win32':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                cls._supports_color = True
            except:
                cls._supports_color = False
        else:
            cls._supports_color = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

        return cls._supports_color

    @classmethod
    def supports_unicode(cls) -> bool:
        """Check if terminal supports Unicode."""
        if cls._supports_unicode is not None:
            return cls._supports_unicode

        try:
            # Try to encode some unicode characters
            '🔍📊✅❌'.encode(sys.stdout.encoding or 'utf-8')
            cls._supports_unicode = True
        except (UnicodeEncodeError, LookupError):
            cls._supports_unicode = False

        return cls._supports_unicode


def colored(text: str, color: str) -> str:
    """Return colored text if supported."""
    if Colors.supports_color():
        return f"{color}{text}{Colors.END}"
    return text


def icon(unicode_icon: str, ascii_fallback: str = '*') -> str:
    """Return unicode icon or ASCII fallback."""
    if Colors.supports_unicode():
        return unicode_icon
    return ascii_fallback


def print_banner():
    """Print application banner."""
    if Colors.supports_unicode():
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗ ██████╗  ██████╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗        ║
║  ██╔════╝ ██╔══██╗██╔═══██╗    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝        ║
║  ██║  ███╗██████╔╝██║   ██║    ███████║██║   ██║██║  ██║██║   ██║           ║
║  ██║   ██║██╔═══╝ ██║   ██║    ██╔══██║██║   ██║██║  ██║██║   ██║           ║
║  ╚██████╔╝██║     ╚██████╔╝    ██║  ██║╚██████╔╝██████╔╝██║   ██║           ║
║   ╚═════╝ ╚═╝      ╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝           ║
║                                                                              ║
║                    🔍 Security Audit System Pro v3.1                         ║
║                    Group Policy Objects Analyzer                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    else:
        banner = """
================================================================================
                         GPO AUDIT SYSTEM PRO v3.1
                      Group Policy Objects Analyzer
================================================================================
"""
    print(colored(banner, Colors.CYAN))


class ProgressBar:
    """Simple progress bar for console output."""

    def __init__(self, total: int, prefix: str = 'Progress', length: int = 40):
        self.total = max(total, 1)  # Prevent division by zero
        self.prefix = prefix
        self.length = length
        self.current = 0

    def update(self, current=None, suffix: str = ''):
        if current is not None:
            self.current = current
        else:
            self.current += 1

        percent = min(self.current / self.total, 1.0)
        filled = int(self.length * percent)

        if Colors.supports_unicode():
            bar = '█' * filled + '░' * (self.length - filled)
        else:
            bar = '#' * filled + '-' * (self.length - filled)

        line = f'\r{self.prefix} |{bar}| {self.current}/{self.total} ({percent:.0%}) {suffix[:30]}'

        if Colors.supports_color():
            if percent < 0.5:
                line = colored(line, Colors.WARNING)
            else:
                line = colored(line, Colors.GREEN)

        print(line, end='', flush=True)

        if self.current >= self.total:
            print()

    def finish(self):
        self.update(self.total)
