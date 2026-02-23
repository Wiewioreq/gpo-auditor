"""GPO scripts parser."""

import os
from typing import Dict, List


def parse_scripts(scripts_dict: Dict[str, List[str]]) -> List[Dict]:
    """Extract script information."""
    lst = []
    for scr_type, files in scripts_dict.items():
        for i, fpath in enumerate(files):
            lst.append({
                'type': scr_type,
                'path': fpath,
                'name': os.path.basename(fpath),
                'order': i + 1
            })
    return lst
