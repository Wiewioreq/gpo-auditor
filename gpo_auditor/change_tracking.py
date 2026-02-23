"""Change tracking: load/save scan cache and compare scans."""

import json
import os
import pickle
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .logging_setup import get_logger


def load_previous_scan(output_dir: str) -> Optional[List[Dict]]:
    """Load the most recent previous scan for comparison."""
    log = get_logger()
    scan_files = list(Path(output_dir).glob('gpos_*.json'))

    if len(scan_files) < 2:
        return None

    # Sort by modification time
    scan_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)

    try:
        with open(scan_files[1], 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        log.error(f"Error loading previous scan: {e}")
        return None


def save_scan_cache(data: Dict, output_dir: str) -> None:
    """Save scan results to cache for faster subsequent runs."""
    log = get_logger()
    cache_file = os.path.join(output_dir, '.gpo_cache.pkl')

    try:
        cache_data = {
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        with open(cache_file, 'wb') as f:
            pickle.dump(cache_data, f)
        log.debug(f"Cache saved to {cache_file}")
    except Exception as e:
        log.debug(f"Could not save cache: {e}")


def load_scan_cache(output_dir: str, max_age_hours: int = 24) -> Optional[Dict]:
    """Load scan cache if not too old."""
    log = get_logger()
    cache_file = os.path.join(output_dir, '.gpo_cache.pkl')

    if not os.path.exists(cache_file):
        return None

    try:
        with open(cache_file, 'rb') as f:
            cache_data = pickle.load(f)

        cache_time = datetime.fromisoformat(cache_data['timestamp'])
        age = datetime.now() - cache_time

        if age.total_seconds() > max_age_hours * 3600:
            log.debug("Cache expired")
            return None

        log.info(f"Using cached data from {cache_time}")
        return cache_data['data']

    except Exception as e:
        log.debug(f"Could not load cache: {e}")
        return None


def compare_scans(current_gpos: List[Dict], previous_gpos: List[Dict]) -> Optional[Dict]:
    """Compare current scan with previous scan to detect changes."""
    if not previous_gpos:
        return None

    changes = {
        'new_gpos': [],
        'deleted_gpos': [],
        'modified_gpos': [],
        'timestamp': datetime.now().isoformat()
    }

    current_guids = {g['guid'].upper(): g for g in current_gpos}
    previous_guids = {g['guid'].upper(): g for g in previous_gpos}

    # New GPOs
    for guid in set(current_guids.keys()) - set(previous_guids.keys()):
        changes['new_gpos'].append(current_guids[guid])

    # Deleted GPOs
    for guid in set(previous_guids.keys()) - set(current_guids.keys()):
        changes['deleted_gpos'].append(previous_guids[guid])

    # Modified GPOs
    for guid in set(current_guids.keys()) & set(previous_guids.keys()):
        curr = current_guids[guid]
        prev = previous_guids[guid]

        if curr['version'] != prev['version'] or curr['whenChanged'] != prev['whenChanged']:
            changes['modified_gpos'].append({
                'name': curr['name'],
                'guid': guid,
                'old_version': prev['version'],
                'new_version': curr['version'],
                'old_modified': prev['whenChanged'],
                'new_modified': curr['whenChanged']
            })

    return changes
