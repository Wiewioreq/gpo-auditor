"""Security findings filter, grouping, and summarization utilities."""

from typing import Dict, List


_SEVERITY_RANK: Dict[str, int] = {
    'CRITICAL': 4,
    'HIGH': 3,
    'MEDIUM': 2,
    'LOW': 1,
    'INFO': 0,
}

_RISK_WEIGHTS: Dict[str, int] = {
    'CRITICAL': 10,
    'HIGH': 5,
    'MEDIUM': 3,
    'LOW': 1,
    'INFO': 0,
}


def get_severity_rank(severity: str) -> int:
    """Return numeric rank for a severity string (CRITICAL=4 … INFO=0)."""
    return _SEVERITY_RANK.get(severity.upper(), 0)


def filter_by_severity(findings: List[Dict], min_severity: str = 'LOW') -> List[Dict]:
    """Return findings whose severity is >= min_severity."""
    min_rank = get_severity_rank(min_severity)
    return [f for f in findings if get_severity_rank(f.get('severity', 'INFO')) >= min_rank]


def filter_by_category(findings: List[Dict], categories: List[str]) -> List[Dict]:
    """Return findings whose category is in *categories* (case-insensitive)."""
    cats = {c.upper() for c in categories}
    return [f for f in findings if f.get('category', '').upper() in cats]


def filter_by_gpo(findings: List[Dict], gpo_names: List[str]) -> List[Dict]:
    """Return findings associated with any of the given GPO names."""
    names = {n.lower() for n in gpo_names}
    return [f for f in findings if f.get('gpo_name', '').lower() in names]


def filter_by_cve(findings: List[Dict], cve: str) -> List[Dict]:
    """Return findings that reference a specific CVE identifier."""
    cve_upper = cve.upper()
    return [
        f for f in findings
        if cve_upper in f.get('cve', '').upper() or cve_upper in f.get('description', '').upper()
    ]


def group_by_severity(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Group findings by severity level."""
    result: Dict[str, List[Dict]] = {s: [] for s in _SEVERITY_RANK}
    for f in findings:
        sev = f.get('severity', 'INFO').upper()
        result.setdefault(sev, []).append(f)
    return result


def group_by_category(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Group findings by category."""
    result: Dict[str, List[Dict]] = {}
    for f in findings:
        cat = f.get('category', 'Unknown')
        result.setdefault(cat, []).append(f)
    return result


def sort_by_severity(findings: List[Dict]) -> List[Dict]:
    """Return findings sorted from highest to lowest severity."""
    return sorted(findings, key=lambda f: get_severity_rank(f.get('severity', 'INFO')), reverse=True)


def get_unique_cves(findings: List[Dict]) -> List[str]:
    """Return sorted list of unique CVE identifiers referenced by findings."""
    cves = set()
    for f in findings:
        for cve in f.get('cve', '').split(','):
            cve = cve.strip()
            if cve.upper().startswith('CVE-'):
                cves.add(cve.upper())
    return sorted(cves)


def summarize_findings(findings: List[Dict]) -> Dict:
    """
    Return a summary dict:
      counts        – per-severity counts
      total         – total number of findings
      risk_score    – weighted risk score
      top_categories – list of (category, count) sorted by count desc
      top_cves      – list of unique CVEs found
    """
    counts: Dict[str, int] = {s: 0 for s in _SEVERITY_RANK}
    risk_score = 0
    category_counts: Dict[str, int] = {}

    for f in findings:
        sev = f.get('severity', 'INFO').upper()
        counts[sev] = counts.get(sev, 0) + 1
        risk_score += _RISK_WEIGHTS.get(sev, 0)
        cat = f.get('category', 'Unknown')
        category_counts[cat] = category_counts.get(cat, 0) + 1

    top_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)

    return {
        'counts': counts,
        'total': len(findings),
        'risk_score': risk_score,
        'top_categories': top_categories,
        'top_cves': get_unique_cves(findings),
    }
