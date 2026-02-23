"""Group Policy Preferences XML parser."""

import json
import os
from typing import Dict, List

from .logging_setup import get_logger

try:
    from lxml import etree
    HAS_LXML = True
except ImportError:
    HAS_LXML = False


def parse_gpp_preferences(preferences_xmls: List[str]) -> List[Dict]:
    """Parse Group Policy Preferences XML files with full paths."""
    log = get_logger()
    prefs = []

    if not HAS_LXML:
        return prefs

    for xml_path in preferences_xmls:
        try:
            tree = etree.parse(xml_path)
            root_el = tree.getroot()

            # Handle namespaces
            nsmap = root_el.nsmap.copy()
            if None in nsmap:
                nsmap['default'] = nsmap.pop(None)

            for elem in root_el:
                attrs = dict(elem.attrib)
                attrs_json = json.dumps(attrs)
                # Truncate very long JSON
                if len(attrs_json) > 1000:
                    attrs_json = attrs_json[:997] + '...'

                pref = {
                    'file': os.path.basename(xml_path),
                    'full_path': xml_path,
                    'element': elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag,
                    'action': attrs.get('action', attrs.get('clsid', '')),
                    'attributes': attrs_json
                }

                targeting = elem.find('Properties') or elem.find('.//Properties')
                if targeting is not None:
                    target_attrs = json.dumps(dict(targeting.attrib))
                    if len(target_attrs) > 500:
                        target_attrs = target_attrs[:497] + '...'
                    pref['targeting'] = target_attrs

                prefs.append(pref)
            log.debug(f"Parsed preferences from {xml_path}")
        except etree.XMLSyntaxError as e:
            log.warning(f"XML syntax error in {xml_path}: {e}")
        except Exception as e:
            log.error(f"Error parsing GPP {xml_path}: {e}")

    return prefs
