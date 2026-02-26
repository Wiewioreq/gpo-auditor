"""Dashboard metric calculation functions."""

from typing import Dict, List

# Severity weight constants shared across all dashboard calculations
SEVERITY_WEIGHTS: Dict[str, int] = {
    'CRITICAL': 10,
    'HIGH': 5,
    'MEDIUM': 3,
    'LOW': 1,
    'INFO': 0,
}


def calculate_risk_score(security_findings: List[Dict]) -> int:
    """Calculate overall risk score from security findings."""
    score = 0
    for finding in security_findings:
        severity = finding.get('severity', 'INFO')
        score += SEVERITY_WEIGHTS.get(severity, 0)
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


# ---------------------------------------------------------------------------
# New dashboard functions
# ---------------------------------------------------------------------------

def get_compliance_score(security_findings: List[Dict], gpo_list: List[Dict]) -> float:
    """
    Calculate a compliance score between 0.0 (worst) and 100.0 (best).

    The score is penalised by risk score relative to the maximum possible risk
    (all GPOs having CRITICAL findings).  Returns 100.0 when there are no findings.
    """
    if not gpo_list:
        return 100.0

    risk = calculate_risk_score(security_findings)
    # Max possible: every GPO contributes one CRITICAL finding
    max_risk = max(len(gpo_list) * SEVERITY_WEIGHTS['CRITICAL'], 1)
    score = max(0.0, 100.0 - (risk / max_risk) * 100.0)
    return round(score, 1)


def get_top_risky_gpos(gpo_list: List[Dict], security_findings: List[Dict], top_n: int = 10) -> List[Dict]:
    """Return top-N GPOs ranked by their aggregated risk score."""
    gpo_scores: Dict[str, Dict] = {}
    for gpo in gpo_list:
        name = gpo.get('name', '')
        gpo_scores[name] = {'name': name, 'guid': gpo.get('guid', ''), 'score': 0, 'findings': 0}

    for f in security_findings:
        name = f.get('gpo_name', '')
        if name not in gpo_scores:
            gpo_scores[name] = {'name': name, 'guid': '', 'score': 0, 'findings': 0}
        sev = f.get('severity', 'INFO')
        gpo_scores[name]['score'] += SEVERITY_WEIGHTS.get(sev, 0)
        gpo_scores[name]['findings'] += 1

    ranked = sorted(gpo_scores.values(), key=lambda x: x['score'], reverse=True)
    return ranked[:top_n]


def get_category_breakdown(security_findings: List[Dict]) -> List[Dict]:
    """Return list of {'category', 'count'} dicts sorted by count descending."""
    dist = get_category_distribution(security_findings)
    return sorted(
        [{'category': cat, 'count': cnt} for cat, cnt in dist.items()],
        key=lambda x: x['count'],
        reverse=True,
    )


def get_gpo_scope_summary(gpo_list: List[Dict]) -> Dict:
    """
    Return scope summary:
      user_only, computer_only, both, disabled (neither enabled)
    """
    user_only = computer_only = both = disabled = 0
    for gpo in gpo_list:
        u = gpo.get('applies_to_user', gpo.get('user_enabled', True))
        c = gpo.get('applies_to_computer', gpo.get('computer_enabled', True))
        if u and c:
            both += 1
        elif u:
            user_only += 1
        elif c:
            computer_only += 1
        else:
            disabled += 1
    return {'user_only': user_only, 'computer_only': computer_only, 'both': both, 'disabled': disabled}


def get_sysvol_size_summary(gpo_list: List[Dict]) -> Dict:
    """Return SYSVOL size stats: total, avg, max, min (in bytes)."""
    sizes = [g.get('size', 0) for g in gpo_list]
    if not sizes:
        return {'total': 0, 'avg': 0, 'max': 0, 'min': 0}
    return {
        'total': sum(sizes),
        'avg': int(sum(sizes) / len(sizes)),
        'max': max(sizes),
        'min': min(sizes),
    }


def get_wmi_filter_summary(gpo_list: List[Dict], wmi_filters: Dict) -> Dict:
    """Return WMI filter summary: count of filters, GPOs with WMI filter attached."""
    gpos_with_wmi = sum(1 for g in gpo_list if g.get('wmi_filter'))
    return {
        'count': len(wmi_filters),
        'gpos_with_wmi': gpos_with_wmi,
    }

