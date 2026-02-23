"""Registry.pol parser."""

import os
from typing import Dict, List

from .logging_setup import get_logger

try:
    import pyregpol
except ImportError:
    pyregpol = None


def parse_registry_pol(pol_path: str, scope: str = 'Unknown') -> List[Dict]:
    """Parse Registry.pol file from GPO with scope information."""
    log = get_logger()
    entries = []

    if not os.path.exists(pol_path):
        return entries

    if pyregpol is None:
        log.warning(f"pyregpol not installed, skipping: {pol_path}")
        return entries

    try:
        rp = pyregpol.RegistryPolicyFile(pol_path)
        for elem in rp.entries():
            entries.append({
                'key': elem.key,
                'value': elem.value,
                'type': str(elem.type),
                'data': str(elem.data),
                'scope': scope,
                'pol_file': pol_path,
            })
        log.debug(f"Parsed {len(entries)} entries from {pol_path}")
    except Exception as e:
        log.error(f"Error parsing {pol_path}: {e}")

    return entries
