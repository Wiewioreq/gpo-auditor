"""Registry.pol parser with binary fallback."""

import os
import struct
from typing import Dict, List

from .logging_setup import get_logger

try:
    import pyregpol
except ImportError:
    pyregpol = None

# Registry type constants
_REG_TYPES = {
    0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY',
    4: 'REG_DWORD', 5: 'REG_DWORD_BIG_ENDIAN', 6: 'REG_LINK',
    7: 'REG_MULTI_SZ', 11: 'REG_QWORD',
}

_PREG_SIGNATURE = b'PReg'
_PREG_VERSION = 1


def _read_utf16_field(data: bytes, offset: int) -> tuple:
    """Read a null-terminated UTF-16LE string; return (string, new_offset)."""
    end = offset
    while end + 1 < len(data):
        if data[end] == 0 and data[end + 1] == 0:
            break
        end += 2
    text = data[offset:end].decode('utf-16-le', errors='replace')
    return text, end + 2  # skip the null terminator


def _parse_registry_pol_binary(pol_path: str, scope: str) -> List[Dict]:
    """Manually parse Registry.pol binary format."""
    log = get_logger()
    entries = []
    try:
        with open(pol_path, 'rb') as f:
            data = f.read()

        if len(data) < 8:
            return entries

        # Validate header
        sig = data[0:4]
        version = struct.unpack_from('<I', data, 4)[0]
        if sig != _PREG_SIGNATURE or version != _PREG_VERSION:
            log.warning(f"Invalid Registry.pol header in {pol_path}")
            return entries

        offset = 8
        while offset < len(data):
            # Each entry starts with '['
            if offset >= len(data) or data[offset:offset + 2] != b'[\x00':
                break
            offset += 2

            key, offset = _read_utf16_field(data, offset)
            # skip ';'
            offset += 2

            value, offset = _read_utf16_field(data, offset)
            # skip ';'
            offset += 2

            if offset + 4 > len(data):
                break
            reg_type = struct.unpack_from('<I', data, offset)[0]
            offset += 4
            # skip ';'
            offset += 2

            if offset + 4 > len(data):
                break
            data_size = struct.unpack_from('<I', data, offset)[0]
            offset += 4
            # skip ';'
            offset += 2

            raw_data = data[offset:offset + data_size]
            offset += data_size

            # Decode data based on type
            try:
                if reg_type in (1, 2):  # REG_SZ, REG_EXPAND_SZ
                    decoded = raw_data.decode('utf-16-le', errors='replace').rstrip('\x00')
                elif reg_type == 4:  # REG_DWORD
                    decoded = str(struct.unpack_from('<I', raw_data)[0]) if len(raw_data) >= 4 else str(raw_data.hex())
                elif reg_type == 11:  # REG_QWORD
                    decoded = str(struct.unpack_from('<Q', raw_data)[0]) if len(raw_data) >= 8 else str(raw_data.hex())
                elif reg_type == 7:  # REG_MULTI_SZ
                    decoded = raw_data.decode('utf-16-le', errors='replace').replace('\x00', '\n').strip()
                else:
                    decoded = raw_data.hex()
            except Exception:
                decoded = raw_data.hex()

            # skip ']'
            offset += 2

            entries.append({
                'key': key,
                'value': value,
                'type': _REG_TYPES.get(reg_type, f'REG_{reg_type}'),
                'data': decoded,
                'scope': scope,
                'pol_file': pol_path,
            })

    except Exception as e:
        log.error(f"Binary parse error for {pol_path}: {e}")

    return entries


def parse_registry_pol(pol_path: str, scope: str = 'Unknown') -> List[Dict]:
    """Parse Registry.pol file from GPO with scope information."""
    log = get_logger()
    entries = []

    if not os.path.exists(pol_path):
        return entries

    if pyregpol is not None:
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
            return entries
        except Exception as e:
            log.warning(f"pyregpol failed for {pol_path}, using binary fallback: {e}")

    # Binary fallback
    entries = _parse_registry_pol_binary(pol_path, scope)
    log.debug(f"Binary-parsed {len(entries)} entries from {pol_path}")
    return entries
