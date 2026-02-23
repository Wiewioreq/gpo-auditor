"""GPO scripts parser with scripts.ini reading and sensitive content detection."""

import configparser
import os
import re
from pathlib import Path
from typing import Dict, List

from .logging_setup import get_logger

# Patterns indicative of sensitive content in scripts
_SENSITIVE_PATTERNS = [
    re.compile(r'password\s*=\s*\S+', re.IGNORECASE),
    re.compile(r'-password\s+\S+', re.IGNORECASE),
    re.compile(r'passwd\s*=\s*\S+', re.IGNORECASE),
    re.compile(r'credential', re.IGNORECASE),
    re.compile(r'net\s+use\s+.*\s+/user:', re.IGNORECASE),
    re.compile(r'runas\s+/password', re.IGNORECASE),
    re.compile(r'ConvertTo-SecureString', re.IGNORECASE),
    re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),  # base64-like strings
]

_SCRIPT_SECTIONS = ['Startup', 'Shutdown', 'Logon', 'Logoff']

_SYSVOL_SCRIPT_DIRS = {
    'Startup':  ('Machine', 'Scripts', 'Startup'),
    'Shutdown': ('Machine', 'Scripts', 'Shutdown'),
    'Logon':    ('User',    'Scripts', 'Logon'),
    'Logoff':   ('User',    'Scripts', 'Logoff'),
}


def _scan_sensitive(content: str) -> List[str]:
    """Return list of matched sensitive pattern descriptions."""
    found = []
    for pat in _SENSITIVE_PATTERNS:
        if pat.search(content):
            found.append(pat.pattern)
    return found


def parse_scripts_ini(scripts_ini_path: str, gpo_sysvol_root: str = '') -> List[Dict]:
    """
    Parse a scripts.ini file and return enriched script entries.

    Args:
        scripts_ini_path: Full path to scripts.ini
        gpo_sysvol_root:  Root of the GPO folder in SYSVOL (used to resolve script paths)
    """
    log = get_logger()
    entries = []

    if not os.path.exists(scripts_ini_path):
        return entries

    parser = configparser.RawConfigParser()
    try:
        with open(scripts_ini_path, 'r', encoding='utf-16', errors='replace') as f:
            parser.read_file(f)
    except UnicodeError:
        try:
            with open(scripts_ini_path, 'r', encoding='utf-8', errors='replace') as f:
                parser.read_file(f)
        except Exception as e:
            log.warning(f"Could not read scripts.ini {scripts_ini_path}: {e}")
            return entries
    except Exception as e:
        log.warning(f"Could not parse scripts.ini {scripts_ini_path}: {e}")
        return entries

    for section in _SCRIPT_SECTIONS:
        if not parser.has_section(section):
            continue

        # Keys are like 0CmdLine, 0Parameters, 1CmdLine, 1Parameters ...
        idx = 0
        while True:
            cmdline_key = f'{idx}CmdLine'
            params_key  = f'{idx}Parameters'
            if not parser.has_option(section, cmdline_key):
                break

            script_path = parser.get(section, cmdline_key).strip()
            parameters  = parser.get(section, params_key).strip() if parser.has_option(section, params_key) else ''

            # Attempt to resolve absolute path
            resolved_path = script_path
            if gpo_sysvol_root and not os.path.isabs(script_path):
                script_dir = os.path.join(gpo_sysvol_root, *_SYSVOL_SCRIPT_DIRS.get(section, ()))
                resolved_path = os.path.join(script_dir, script_path)

            file_exists = os.path.exists(resolved_path)
            content_size = 0
            has_sensitive = False
            sensitive_found: List[str] = []

            if file_exists:
                try:
                    stat = os.stat(resolved_path)
                    content_size = stat.st_size
                    if content_size < 1_000_000:  # read files < 1 MB
                        with open(resolved_path, 'r', encoding='utf-8', errors='replace') as sf:
                            content = sf.read()
                        sensitive_found = _scan_sensitive(content)
                        has_sensitive = bool(sensitive_found)
                except Exception:
                    pass

            entries.append({
                'type': section,
                'path': resolved_path,
                'name': os.path.basename(script_path) if script_path else '',
                'order': idx + 1,
                'parameters': parameters,
                'file_exists': file_exists,
                'content_size': content_size,
                'has_sensitive_content': has_sensitive,
                'sensitive_patterns_found': sensitive_found,
            })
            idx += 1

    return entries


def parse_scripts(scripts_dict: Dict[str, List[str]]) -> List[Dict]:
    """Extract script information from a dict of {type: [file_paths]}.

    Kept for backward compatibility with existing callers.
    Also attempts to read adjacent scripts.ini if only a directory is given.
    """
    log = get_logger()
    lst: List[Dict] = []

    for scr_type, files in scripts_dict.items():
        # If files is empty, skip
        if not files:
            continue

        # Try to find scripts.ini in the parent directory
        # e.g. files[0] might be: /sysvol/{guid}/Machine/Scripts/Startup/foo.bat
        # scripts.ini would be at:  /sysvol/{guid}/Machine/Scripts/scripts.ini
        ini_searched = set()
        for fpath in files:
            ini_dir = str(Path(fpath).parent.parent)  # go up one level from Startup/Logon/...
            ini_path = os.path.join(ini_dir, 'scripts.ini')
            if ini_path not in ini_searched and os.path.exists(ini_path):
                ini_searched.add(ini_path)
                # Determine gpo_sysvol_root (two levels above Machine/User)
                root = str(Path(ini_dir).parent.parent)
                ini_entries = parse_scripts_ini(ini_path, root)
                if ini_entries:
                    lst.extend(ini_entries)
                    log.debug(f"Loaded {len(ini_entries)} scripts from {ini_path}")

        # Fallback: entries from the dict itself (no ini parsing done)
        for i, fpath in enumerate(files):
            # Avoid duplicates if ini already provided info
            already = any(e['path'] == fpath for e in lst)
            if not already:
                file_exists = os.path.exists(fpath)
                content_size = 0
                has_sensitive = False
                sensitive_found: List[str] = []
                if file_exists:
                    try:
                        content_size = os.path.getsize(fpath)
                        if content_size < 1_000_000:
                            with open(fpath, 'r', encoding='utf-8', errors='replace') as sf:
                                content = sf.read()
                            sensitive_found = _scan_sensitive(content)
                            has_sensitive = bool(sensitive_found)
                    except Exception:
                        pass

                lst.append({
                    'type': scr_type,
                    'path': fpath,
                    'name': os.path.basename(fpath),
                    'order': i + 1,
                    'parameters': '',
                    'file_exists': file_exists,
                    'content_size': content_size,
                    'has_sensitive_content': has_sensitive,
                    'sensitive_patterns_found': sensitive_found,
                })
    return lst
