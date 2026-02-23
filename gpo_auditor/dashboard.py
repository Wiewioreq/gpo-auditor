"""Dashboard metric calculation functions."""

from typing import Dict, List


def calculate_risk_score(security_findings: List[Dict]) -> int:
    """Calculate overall risk score from security findings."""
    severity_scores = {
        'CRITICAL': 10,
        'HIGH': 5,
        'MEDIUM': 3,
        'LOW': 1,
        'INFO': 0
    }
    score = 0
    for finding in security_findings:
        severity = finding.get('severity', 'INFO')
        score += severity_scores.get(severity, 0)
    return score


def get_severity_distribution(security_findings: List[Dict]) -> Dict[str, int]:
    """Return count of findings grouped by severity."""
    distribution = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for finding in security_findings:
        severity = finding.get('severity', 'INFO')
        distribution[severity] = distribution.get(severity, 0) + 1
    return distribution


def get_category_distribution(security_findings: List[Dict]) -> Dict[str, int]:
    """Return count of findings grouped by category."""
    distribution: Dict[str, int] = {}
    for finding in security_findings:
        category = finding.get('category', 'Unknown')
        distribution[category] = distribution.get(category, 0) + 1
    return distribution


def get_gpo_health_summary(gpo_list: List[Dict]) -> Dict:
    """Return health summary for the GPO list."""
    total = len(gpo_list)
    user_disabled = sum(1 for g in gpo_list if not g.get('user_enabled', True))
    computer_disabled = sum(1 for g in gpo_list if not g.get('computer_enabled', True))
    with_wmi = sum(1 for g in gpo_list if g.get('wmi_filter'))
    found_in_sysvol = sum(1 for g in gpo_list if g.get('sysvol_found', True))

    return {
        'total': total,
        'user_disabled': user_disabled,
        'computer_disabled': computer_disabled,
        'with_wmi_filter': with_wmi,
        'found_in_sysvol': found_in_sysvol,
        'missing_from_sysvol': total - found_in_sysvol,
    }
