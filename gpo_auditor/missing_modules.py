"""
Stub/template functions that tie the modules together.

These 12 functions provide high-level orchestration on top of the individual
module functions.  They are intentionally kept as thin wrappers so callers can
compose the individual building blocks however they need.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from .logging_setup import get_logger
from .config import load_config, validate_config, ensure_output_dir, get_password_from_env_or_prompt
from .ad import ADConnection
from .gpo import (
    get_gpo_list, get_ou_links, get_wmi_filters,
    check_gpo_components_parallel, detect_orphaned_gpos,
    analyze_gpo_versions, format_size,
)
from .parser_registry import parse_registry_pol
from .parser_gpp import parse_gpp_preferences
from .parser_scripts import parse_scripts
from .security import SecurityAnalyzer
from .reports import save_json, save_csv, save_excel, save_html_report
from .change_tracking import load_previous_scan, save_scan_cache, compare_scans
from .dashboard import (
    calculate_risk_score, get_severity_distribution,
    get_category_distribution, get_gpo_health_summary,
)


def run_full_audit(config: dict) -> Dict[str, Any]:
    """Orchestrate a full GPO audit and return all collected data."""
    log = get_logger()
    log.info("Starting full audit via run_full_audit()")

    validate_config(config)
    config['ad']['_resolved_password'] = get_password_from_env_or_prompt(config)

    output_dir = ensure_output_dir(config['paths']['output_dir'])
    sysvol_path = config['paths']['sysvol']

    gpo_list, ad_conn = get_gpo_list(config)
    ou_to_gpo, gpo_to_ou, blocked_inheritance = get_ou_links(config, ad_conn)
    wmi_filters = get_wmi_filters(config, ad_conn)
    ad_conn.disconnect()

    components = check_gpo_components_parallel(gpo_list, sysvol_path)
    for gpo, comp in zip(gpo_list, components):
        gpo['size'] = comp.get('size', 0)
        gpo['sysvol_found'] = comp['found']

    registry_entries: List[Dict] = []
    gpprefs: List[Dict] = []
    scripts: List[Dict] = []
    for gpo, comp in zip(gpo_list, components):
        if comp.get('Machine-Registry.pol'):
            registry_entries.extend(parse_registry_pol(
                f"{sysvol_path}/{{{gpo['guid']}}}/Machine/Registry.pol", scope='Machine'))
        if comp.get('User-Registry.pol'):
            registry_entries.extend(parse_registry_pol(
                f"{sysvol_path}/{{{gpo['guid']}}}/User/Registry.pol", scope='User'))
        gpprefs.extend(parse_gpp_preferences(comp.get('Preferences', [])))
        scripts.extend(parse_scripts(comp.get('Scripts', {})))

    analyzer = SecurityAnalyzer()
    for gpo in gpo_list:
        analyzer.analyze_gpo(gpo, sysvol_path)
    security_findings = analyzer.get_findings()

    inconsistencies, unused, disabled = analyze_gpo_versions(gpo_list, gpo_to_ou)

    return {
        'gpo_list': gpo_list,
        'ou_to_gpo': ou_to_gpo,
        'gpo_to_ou': gpo_to_ou,
        'blocked_inheritance': blocked_inheritance,
        'wmi_filters': wmi_filters,
        'registry_entries': registry_entries,
        'gpprefs': gpprefs,
        'scripts': scripts,
        'security_findings': security_findings,
        'inconsistencies': inconsistencies,
        'unused': unused,
        'disabled': disabled,
        'output_dir': output_dir,
    }


def generate_dashboard_metrics(gpo_list: List[Dict], security_findings: List[Dict]) -> Dict:
    """Generate dashboard metrics dictionary from GPO list and security findings."""
    return {
        'risk_score': calculate_risk_score(security_findings),
        'severity_distribution': get_severity_distribution(security_findings),
        'category_distribution': get_category_distribution(security_findings),
        'gpo_health': get_gpo_health_summary(gpo_list),
        'total_gpos': len(gpo_list),
        'total_findings': len(security_findings),
    }


def get_audit_summary(gpo_list: List[Dict], security_findings: List[Dict],
                      changes: Optional[Dict]) -> Dict:
    """Return a high-level summary dictionary suitable for notifications/reports."""
    severity_dist = get_severity_distribution(security_findings)
    summary = {
        'total_gpos': len(gpo_list),
        'total_findings': len(security_findings),
        'critical': severity_dist.get('CRITICAL', 0),
        'high': severity_dist.get('HIGH', 0),
        'medium': severity_dist.get('MEDIUM', 0),
        'low': severity_dist.get('LOW', 0),
        'risk_score': calculate_risk_score(security_findings),
        'timestamp': datetime.now().isoformat(),
    }
    if changes:
        summary['new_gpos'] = len(changes.get('new_gpos', []))
        summary['deleted_gpos'] = len(changes.get('deleted_gpos', []))
        summary['modified_gpos'] = len(changes.get('modified_gpos', []))
    return summary


def get_top_risky_gpos(gpo_list: List[Dict], security_findings: List[Dict],
                       top_n: int = 10) -> List[Dict]:
    """Return the top N GPOs ordered by accumulated risk score."""
    analyzer = SecurityAnalyzer()
    analyzer.findings = security_findings
    for f in security_findings:
        gid = f.get('gpo_guid', 'unknown')
        if gid not in analyzer._findings_by_gpo:
            analyzer._findings_by_gpo[gid] = []
        analyzer._findings_by_gpo[gid].append(f)
    return analyzer.get_top_risky_gpos(top_n)


def check_compliance(gpo_list: List[Dict], security_findings: List[Dict]) -> float:
    """Return a compliance score (0-100) based on absence of critical/high findings."""
    if not gpo_list:
        return 100.0
    severity_dist = get_severity_distribution(security_findings)
    penalty = (severity_dist.get('CRITICAL', 0) * 10 +
               severity_dist.get('HIGH', 0) * 5 +
               severity_dist.get('MEDIUM', 0) * 2)
    score = max(0.0, 100.0 - penalty)
    return round(score, 2)


def export_all_reports(gpo_list: List[Dict], registry: List[Dict], gpprefs: List[Dict],
                       scripts: List[Dict], security_findings: List[Dict],
                       config: dict) -> Dict[str, str]:
    """Export all report formats (JSON, CSV, Excel, HTML) and return file paths."""
    output_dir = config['paths']['output_dir']
    ensure_output_dir(output_dir)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    paths: Dict[str, str] = {}

    json_path = f"{output_dir}/gpos_{timestamp}.json"
    save_json(gpo_list, json_path)
    paths['json'] = json_path

    csv_path = f"{output_dir}/gpos_{timestamp}.csv"
    save_csv(gpo_list, csv_path)
    paths['csv'] = csv_path

    xlsx_path = f"{output_dir}/gpo_audit_{timestamp}.xlsx"
    save_excel(gpo_list, registry, gpprefs, scripts, {}, [], [], security_findings, xlsx_path)
    paths['excel'] = xlsx_path

    html_path = f"{output_dir}/gpo_report_{timestamp}.html"
    save_html_report(gpo_list, registry, gpprefs, scripts, [], [], security_findings,
                     None, [], None, [], html_path)
    paths['html'] = html_path

    return paths


def get_gpo_inheritance_tree(config: dict) -> Dict:
    """Return OU/GPO inheritance tree as a nested dictionary."""
    validate_config(config)
    config['ad']['_resolved_password'] = get_password_from_env_or_prompt(config)
    ou_to_gpo, gpo_to_ou, blocked_inheritance = get_ou_links(config)
    return {
        'ou_to_gpo': ou_to_gpo,
        'gpo_to_ou': gpo_to_ou,
        'blocked_inheritance': blocked_inheritance,
    }


def check_sysvol_consistency(gpo_list: List[Dict], sysvol_path: str) -> Dict:
    """Check SYSVOL consistency and return a report dict."""
    components = check_gpo_components_parallel(gpo_list, sysvol_path, sequential=True)
    missing = [g['name'] for g, c in zip(gpo_list, components) if not c['found']]
    errors = [(g['name'], c['error']) for g, c in zip(gpo_list, components) if c.get('error')]
    total_size = sum(c.get('size', 0) for c in components)
    return {
        'total_gpos': len(gpo_list),
        'missing_from_sysvol': missing,
        'errors': errors,
        'total_sysvol_size_bytes': total_size,
        'total_sysvol_size': format_size(total_size),
    }


def classify_findings_by_severity(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Return findings grouped by severity level."""
    grouped: Dict[str, List[Dict]] = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': []}
    for f in findings:
        severity = f.get('severity', 'INFO')
        grouped.setdefault(severity, []).append(f)
    return grouped


def get_wmi_filter_report(config: dict) -> Dict:
    """Return WMI filter report from Active Directory."""
    validate_config(config)
    config['ad']['_resolved_password'] = get_password_from_env_or_prompt(config)
    wmi_filters = get_wmi_filters(config)
    return {
        'count': len(wmi_filters),
        'filters': wmi_filters,
    }


def detect_version_mismatches(gpo_list: List[Dict], config: dict) -> List[Dict]:
    """Detect version mismatches between AD and SYSVOL GPO versions."""
    validate_config(config)
    config['ad']['_resolved_password'] = get_password_from_env_or_prompt(config)
    _, gpo_to_ou, _ = get_ou_links(config)
    inconsistencies, _, _ = analyze_gpo_versions(gpo_list, gpo_to_ou)
    return inconsistencies


def build_change_report(current_gpos: List[Dict], output_dir: str) -> Optional[Dict]:
    """Build a change tracking report comparing current GPOs against the last saved scan."""
    previous = load_previous_scan(output_dir)
    if previous is None:
        return None
    changes = compare_scans(current_gpos, previous)
    save_scan_cache({'gpo_list': current_gpos}, output_dir)
    return changes
