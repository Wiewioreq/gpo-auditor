"""Group Policy Preferences XML parser with stdlib fallback and cpassword detection."""

import json
import os
import re
from typing import Dict, List

from .logging_setup import get_logger

try:
    from lxml import etree as _etree
    HAS_LXML = True
except ImportError:
    _etree = None
    HAS_LXML = False

import xml.etree.ElementTree as _stdlib_etree

# Pattern to detect encrypted passwords in GPP files
_CPASSWORD_RE = re.compile(r'cpassword\s*=\s*"([^"]+)"', re.IGNORECASE)

# Known sensitive attribute names
_SENSITIVE_ATTRS = {'cpassword', 'password', 'passwd'}


def _detect_cpassword(xml_path: str) -> bool:
    """Return True if the file contains a non-empty cpassword attribute."""
    try:
        with open(xml_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        m = _CPASSWORD_RE.search(content)
        return bool(m and m.group(1).strip())
    except Exception:
        return False


def _parse_with_lxml(xml_path: str, log) -> List[Dict]:
    """Parse GPP XML using lxml."""
    prefs = []
    tree = _etree.parse(xml_path)
    root_el = tree.getroot()

    has_cpassword = _detect_cpassword(xml_path)

    for elem in root_el:
        attrs = dict(elem.attrib)
        attrs_json = json.dumps(attrs)
        if len(attrs_json) > 1000:
            attrs_json = attrs_json[:997] + '...'

        pref = {
            'file': os.path.basename(xml_path),
            'full_path': xml_path,
            'element': elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag,
            'action': attrs.get('action', attrs.get('clsid', '')),
            'attributes': attrs_json,
            'has_cpassword': has_cpassword or any(k.lower() in _SENSITIVE_ATTRS for k in attrs),
        }

        targeting = elem.find('Properties') or elem.find('.//Properties')
        if targeting is not None:
            target_attrs = json.dumps(dict(targeting.attrib))
            if len(target_attrs) > 500:
                target_attrs = target_attrs[:497] + '...'
            pref['targeting'] = target_attrs

        prefs.append(pref)
    return prefs


def _parse_with_stdlib(xml_path: str, log) -> List[Dict]:
    """Parse GPP XML using stdlib xml.etree.ElementTree."""
    prefs = []
    tree = _stdlib_etree.parse(xml_path)
    root_el = tree.getroot()

    has_cpassword = _detect_cpassword(xml_path)

    for elem in root_el:
        attrs = dict(elem.attrib)
        attrs_json = json.dumps(attrs)
        if len(attrs_json) > 1000:
            attrs_json = attrs_json[:997] + '...'

        tag = elem.tag
        if '}' in tag:
            tag = tag.split('}', 1)[-1]

        pref = {
            'file': os.path.basename(xml_path),
            'full_path': xml_path,
            'element': tag,
            'action': attrs.get('action', attrs.get('clsid', '')),
            'attributes': attrs_json,
            'has_cpassword': has_cpassword or any(k.lower() in _SENSITIVE_ATTRS for k in attrs),
        }

        targeting = elem.find('Properties') or elem.find('.//Properties')
        if targeting is not None:
            target_attrs = json.dumps(dict(targeting.attrib))
            if len(target_attrs) > 500:
                target_attrs = target_attrs[:497] + '...'
            pref['targeting'] = target_attrs

        prefs.append(pref)
    return prefs


def parse_gpp_preferences(preferences_xmls: List[str]) -> List[Dict]:
    """Parse Group Policy Preferences XML files with full paths."""
    log = get_logger()
    prefs = []

    for xml_path in preferences_xmls:
        try:
            if HAS_LXML:
                try:
                    prefs.extend(_parse_with_lxml(xml_path, log))
                    log.debug(f"Parsed preferences (lxml) from {xml_path}")
                    continue
                except Exception as e:
                    log.debug(f"lxml failed for {xml_path}, using stdlib: {e}")

            prefs.extend(_parse_with_stdlib(xml_path, log))
            log.debug(f"Parsed preferences (stdlib) from {xml_path}")
        except Exception as e:
            log.error(f"Error parsing GPP {xml_path}: {e}")

    return prefs
