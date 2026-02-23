"""GPO-related functions: listing, SYSVOL analysis, OU links, WMI filters, versioning."""

import os
import re
import sys
from datetime import datetime
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .logging_setup import get_logger
from .console import Colors, colored, icon, ProgressBar
from .ad import ADConnection
from .config import ConfigError

try:
    import pyregpol
except ImportError:
    pyregpol = None


def get_gpo_list(config: dict) -> Tuple[List[Dict], ADConnection]:
    """Fetch all GPOs from Active Directory."""
    log = get_logger()
    log.info("Connecting to AD...")
    print(colored(f"\n  {icon('📡', '[AD]')} Connecting to Active Directory...", Colors.CYAN))

    ad_conn = ADConnection(config['ad'])

    if not ad_conn.connect():
        raise ConfigError(f"{icon('❌', 'X')} Cannot connect to AD")

    try:
        print(colored(f"  {icon('🔍', '[SEARCH]')} Searching for GPOs in: {config['ad']['base_dn']}", Colors.CYAN))

        entries = ad_conn.search(
            config['ad']['base_dn'],
            '(objectClass=groupPolicyContainer)',
            attributes=[
                'displayName', 'name', 'versionNumber', 'whenChanged',
                'whenCreated', 'gPCFileSysPath', 'flags', 'gPCWQLFilter'
            ]
        )

        gpos = []
        for entry in entries:
            try:
                ver = int(entry.versionNumber.value) if entry.versionNumber.value else 0
                user_ver = (ver >> 16) & 0xFFFF
                comp_ver = ver & 0xFFFF

                flags = int(entry.flags.value) if hasattr(entry, 'flags') and entry.flags.value else 0

                gpos.append({
                    'name': entry.displayName.value if entry.displayName.value else 'Unnamed GPO',
                    'guid': entry.name.value if entry.name.value else 'N/A',
                    'version': ver,
                    'user_version': user_ver,
                    'comp_version': comp_ver,
                    'whenChanged': str(entry.whenChanged.value) if entry.whenChanged.value else 'N/A',
                    'whenCreated': str(entry.whenCreated.value) if hasattr(entry, 'whenCreated') and entry.whenCreated.value else 'N/A',
                    'sysvol_path': entry.gPCFileSysPath.value if hasattr(entry, 'gPCFileSysPath') and entry.gPCFileSysPath.value else 'N/A',
                    'flags': flags,
                    'user_enabled': not bool(flags & 2),
                    'computer_enabled': not bool(flags & 1),
                    'wmi_filter': entry.gPCWQLFilter.value if hasattr(entry, 'gPCWQLFilter') and entry.gPCWQLFilter.value else None
                })
            except Exception as e:
                log.error(f"Error parsing GPO entry: {e}")
                continue

        log.info(f"Found {len(gpos)} GPOs")
        print(colored(f"  {icon('✅', 'OK')} Found {len(gpos)} GPOs", Colors.GREEN))
        return gpos, ad_conn

    except Exception as e:
        ad_conn.disconnect()
        raise


def get_gpo_folder_size(sysvol_path: str, gpo_guid: str) -> int:
    """Calculate the total size of a GPO folder in SYSVOL."""
    gpo_path = Path(sysvol_path) / f"{{{gpo_guid}}}"
    if not gpo_path.exists():
        return 0

    total_size = 0
    try:
        for file_path in gpo_path.rglob('*'):
            if file_path.is_file():
                try:
                    total_size += file_path.stat().st_size
                except (PermissionError, OSError):
                    pass
    except Exception:
        pass

    return total_size


def format_size(size_bytes: int) -> str:
    """Format bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def check_gpo_sysvol_components(gpo_data: Tuple[str, str]) -> Dict:
    """Check GPO components in SYSVOL with error handling."""
    try:
        gpo_guid, sysvol_path = gpo_data
        sys_data = {
            'guid': gpo_guid,
            'found': False,
            'Machine-Registry.pol': False,
            'User-Registry.pol': False,
            'size': 0,
            'Preferences': [],
            'Scripts': {},
            'error': None
        }

        gpo_path = Path(sysvol_path) / f"{{{gpo_guid}}}"
        sys_data['found'] = gpo_path.exists()

        if not sys_data['found']:
            return sys_data

        sys_data['Machine-Registry.pol'] = (gpo_path / 'Machine/Registry.pol').exists()
        sys_data['User-Registry.pol'] = (gpo_path / 'User/Registry.pol').exists()
        sys_data['size'] = get_gpo_folder_size(sysvol_path, gpo_guid)

        pref_xmls = []
        for part in ['User', 'Machine']:
            pref = gpo_path / f"{part}/Preferences"
            if pref.exists():
                try:
                    pref_xmls += [str(x) for x in pref.glob('**/*.xml')]
                except PermissionError:
                    pass
        sys_data['Preferences'] = pref_xmls

        scripts = {}
        for part, act in [('Machine', 'Startup'), ('Machine', 'Shutdown'), ('User', 'Logon'), ('User', 'Logoff')]:
            scr_dir = gpo_path / f"{part}/Scripts/{act}"
            try:
                scripts[f'{part}-{act}'] = [str(x) for x in (scr_dir.glob('*') if scr_dir.exists() else [])]
            except PermissionError:
                scripts[f'{part}-{act}'] = []
        sys_data['Scripts'] = scripts

        return sys_data

    except Exception as e:
        return {
            'guid': gpo_data[0] if gpo_data else 'unknown',
            'found': False,
            'error': str(e),
            'Machine-Registry.pol': False,
            'User-Registry.pol': False,
            'size': 0,
            'Preferences': [],
            'Scripts': {}
        }


def check_gpo_components_parallel(gpo_list: List[Dict], sysvol_path: str,
                                   num_processes: Optional[int] = None,
                                   sequential: bool = False) -> List[Dict]:
    """Check GPO components - sequential for EXE, parallel for Python."""
    log = get_logger()

    print(colored(f"\n  {icon('⚙️', '[PROC]')} Analyzing {len(gpo_list)} GPO components...", Colors.CYAN))

    # Force sequential mode for EXE or if requested
    if getattr(sys, 'frozen', False) or sequential or len(gpo_list) <= 5:
        log.info(f"Sequential analysis of {len(gpo_list)} GPOs")

        progress = ProgressBar(len(gpo_list), prefix='  Analyzing')
        results = []
        for gpo in gpo_list:
            result = check_gpo_sysvol_components((gpo['guid'], sysvol_path))
            results.append(result)
            if result.get('error'):
                log.warning(f"Error analyzing GPO {gpo['name']}: {result['error']}")
            progress.update()
        return results

    # Parallel for larger lists
    if num_processes is None:
        num_processes = min(cpu_count(), 4)

    log.info(f"Parallel analysis of {len(gpo_list)} GPOs with {num_processes} processes")

    data = [(gpo['guid'], sysvol_path) for gpo in gpo_list]

    try:
        with Pool(processes=num_processes) as pool:
            results = pool.map(check_gpo_sysvol_components, data)

        # Check for errors
        for gpo, result in zip(gpo_list, results):
            if result.get('error'):
                log.warning(f"Error analyzing GPO {gpo['name']}: {result['error']}")

        print(colored(f"  {icon('✅', 'OK')} Analysis complete", Colors.GREEN))
        return results

    except Exception as e:
        log.error(f"Parallel processing failed, falling back to sequential: {e}")
        return check_gpo_components_parallel(gpo_list, sysvol_path, sequential=True)


def detect_orphaned_gpos(gpo_list: List[Dict], sysvol_path: str) -> Tuple[List[Dict], List[str]]:
    """Detect orphaned GPOs (AD without SYSVOL or SYSVOL without AD)."""
    log = get_logger()

    # GPOs in AD but not in SYSVOL
    orphaned_ad = []
    for gpo in gpo_list:
        gpo_path = Path(sysvol_path) / f"{{{gpo['guid']}}}"
        if not gpo_path.exists():
            orphaned_ad.append(gpo)
            log.warning(f"Orphaned GPO (no SYSVOL): {gpo['name']} ({gpo['guid']})")

    # Folders in SYSVOL but not in AD
    orphaned_sysvol = []
    ad_guids = {gpo['guid'].upper() for gpo in gpo_list}

    try:
        sysvol_dir = Path(sysvol_path)
        if sysvol_dir.exists():
            for folder in sysvol_dir.iterdir():
                if folder.is_dir() and folder.name.startswith('{') and folder.name.endswith('}'):
                    guid = folder.name[1:-1].upper()
                    if guid not in ad_guids:
                        orphaned_sysvol.append(folder.name)
                        log.warning(f"Orphaned SYSVOL folder (no AD object): {folder.name}")
    except PermissionError:
        log.warning("Cannot access SYSVOL directory for orphan detection")

    return orphaned_ad, orphaned_sysvol


def get_ou_links(config: dict, ad_conn: Optional[ADConnection] = None) -> Tuple[Dict, Dict, List[str]]:
    """Fetch GPO-OU links from Active Directory."""
    log = get_logger()
    log.info("Fetching OU links...")
    print(colored(f"\n  {icon('📡', '[AD]')} Fetching OU links...", Colors.CYAN))

    close_conn = False
    if ad_conn is None:
        ad_conn = ADConnection(config['ad'])
        if not ad_conn.connect():
            raise ConfigError(f"{icon('❌', 'X')} Cannot connect to AD for OU links")
        close_conn = True

    try:
        entries = ad_conn.search(
            config['ad']['ldap_ou_base'],
            '(|(objectClass=organizationalUnit)(objectClass=domain))',
            attributes=['gPLink', 'distinguishedName', 'gPOptions']
        )

        ou_to_gpo, gpo_to_ou = {}, {}
        blocked_inheritance = []

        for entry in entries:
            try:
                ou_dn = entry.distinguishedName.value
                gp_links = entry.gPLink.value if hasattr(entry, 'gPLink') else None

                # Check for blocked inheritance
                gp_options = int(entry.gPOptions.value) if hasattr(entry, 'gPOptions') and entry.gPOptions.value else 0
                if gp_options & 1:
                    blocked_inheritance.append(ou_dn)

                if not gp_links:
                    continue

                links = re.findall(r'LDAP://cn=\{([^}]+)\}[^;]*;(\d)', gp_links, re.IGNORECASE)
                ou_to_gpo[ou_dn] = [{'guid': g[0].upper(), 'enforced': g[1] == '2'} for g in links]

                for g in links:
                    guid_upper = g[0].upper()
                    if guid_upper not in gpo_to_ou:
                        gpo_to_ou[guid_upper] = []
                    gpo_to_ou[guid_upper].append({
                        'ou': ou_dn,
                        'enforced': g[1] == '2'
                    })
            except Exception as e:
                log.debug(f"Error parsing OU entry: {e}")
                continue

        log.info(f"Found {len(gpo_to_ou)} linked GPOs, {len(blocked_inheritance)} OUs with blocked inheritance")
        print(colored(f"  {icon('✅', 'OK')} Found {len(gpo_to_ou)} linked GPOs", Colors.GREEN))

        return ou_to_gpo, gpo_to_ou, blocked_inheritance

    finally:
        if close_conn:
            ad_conn.disconnect()


def get_wmi_filters(config: dict, ad_conn: Optional[ADConnection] = None) -> Dict:
    """Fetch WMI Filters from Active Directory."""
    log = get_logger()

    close_conn = False
    if ad_conn is None:
        ad_conn = ADConnection(config['ad'])
        if not ad_conn.connect():
            return {}
        close_conn = True

    try:
        # WMI Filters are in CN=SOM,CN=WMIPolicy,CN=System
        base_dn = config['ad']['base_dn']
        wmi_base = base_dn.replace('CN=Policies,CN=System,', 'CN=SOM,CN=WMIPolicy,CN=System,')

        entries = ad_conn.search(
            wmi_base,
            '(objectClass=msWMI-Som)',
            attributes=['msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2', 'msWMI-ID']
        )

        wmi_filters = {}
        for entry in entries:
            try:
                wmi_id = getattr(entry, 'msWMI-ID', None)
                wmi_id = wmi_id.value if wmi_id else 'N/A'

                wmi_filters[wmi_id] = {
                    'name': getattr(entry, 'msWMI-Name', None),
                    'description': getattr(entry, 'msWMI-Parm1', None),
                    'query': getattr(entry, 'msWMI-Parm2', None),
                }
                wmi_filters[wmi_id] = {k: (v.value if v else '') for k, v in wmi_filters[wmi_id].items()}
            except Exception as e:
                log.debug(f"Error parsing WMI filter: {e}")

        return wmi_filters

    except Exception as e:
        log.debug(f"Could not fetch WMI filters: {e}")
        return {}
    finally:
        if close_conn:
            ad_conn.disconnect()


def analyze_gpo_versions(gpo_list: List[Dict], gpo_to_ou: Dict) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Analyze GPO versions and detect inconsistencies."""
    log = get_logger()
    inconsistencies = []
    unused = []
    disabled = []

    for gpo in gpo_list:
        if gpo['user_version'] != gpo['comp_version']:
            inconsistencies.append(gpo)

        # Check if linked (compare uppercase GUIDs)
        gpo_guid_upper = gpo['guid'].upper()
        if gpo_guid_upper not in gpo_to_ou:
            unused.append(gpo)

        if not gpo.get('user_enabled', True) or not gpo.get('computer_enabled', True):
            disabled.append(gpo)

    log.info(f"Found {len(inconsistencies)} inconsistencies, {len(unused)} unused, {len(disabled)} disabled GPOs")
    return inconsistencies, unused, disabled


def compare_gpo(gpo1: Dict, gpo2: Dict, sysvol_path: str) -> Dict:
    """Compare two GPOs."""
    log = get_logger()
    log.info(f"Comparing GPO: {gpo1['name']} vs {gpo2['name']}")

    comparison = {
        'gpo1': {'name': gpo1['name'], 'guid': gpo1['guid']},
        'gpo2': {'name': gpo2['name'], 'guid': gpo2['guid']},
        'registry': {'added': [], 'removed': [], 'modified': []},
        'timestamp': datetime.now().isoformat()
    }

    if pyregpol is None:
        return comparison

    for scope in ['Machine', 'User']:
        pol1 = os.path.join(sysvol_path, f"{{{gpo1['guid']}}}", scope, 'Registry.pol')
        pol2 = os.path.join(sysvol_path, f"{{{gpo2['guid']}}}", scope, 'Registry.pol')

        if os.path.exists(pol1) and os.path.exists(pol2):
            try:
                entries1 = {(e.key, e.value): e for e in pyregpol.RegistryPolicyFile(pol1).entries()}
                entries2 = {(e.key, e.value): e for e in pyregpol.RegistryPolicyFile(pol2).entries()}

                keys1, keys2 = set(entries1.keys()), set(entries2.keys())

                for k in keys2 - keys1:
                    comparison['registry']['added'].append({
                        'scope': scope, 'key': k[0], 'value': k[1], 'data': str(entries2[k].data)
                    })

                for k in keys1 - keys2:
                    comparison['registry']['removed'].append({
                        'scope': scope, 'key': k[0], 'value': k[1], 'data': str(entries1[k].data)
                    })

                for k in keys1 & keys2:
                    if entries1[k].data != entries2[k].data:
                        comparison['registry']['modified'].append({
                            'scope': scope, 'key': k[0], 'value': k[1],
                            'old': str(entries1[k].data), 'new': str(entries2[k].data)
                        })
            except Exception as e:
                log.error(f"Error comparing {scope} registry: {e}")

    return comparison
