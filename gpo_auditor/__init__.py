"""
GPO Auditor – Public API
========================

Import the most commonly used symbols directly from the package:

    from gpo_auditor import SecurityAnalyzer, ADConnection, ConfigError
    from gpo_auditor import load_config, get_gpo_list, save_html_report
"""

from .logging_setup import setup_logging, get_logger
from .console import Colors, colored, icon, print_banner, h, ProgressBar
from .config import ConfigError, load_config, validate_config, ensure_output_dir, security_lint
from .ad import ADConnection, ARGS_REQUIRE_LDAPS, LAST_CONNECTION_MODE
from .security import SecurityAnalyzer
from .gpo import (
    get_gpo_list, get_gpo_folder_size, format_size,
    check_gpo_sysvol_components, check_gpo_components_parallel,
    detect_orphaned_gpos, get_ou_links, get_wmi_filters,
    analyze_gpo_versions, compare_gpo,
    check_sysvol_consistency, get_inheritance_info, get_user_computer_scope, parse_wmi_query,
)
from .parser_registry import parse_registry_pol
from .parser_gpp import parse_gpp_preferences
from .parser_scripts import parse_scripts
from .reports import save_json, save_csv, save_excel, save_html_report
from .change_tracking import load_previous_scan, save_scan_cache, load_scan_cache, compare_scans
from .notifications import send_email_notification, send_teams_notification
from .dashboard import (
    calculate_risk_score, get_severity_distribution,
    get_category_distribution, get_gpo_health_summary,
    get_compliance_score, get_top_risky_gpos, get_category_breakdown,
    get_gpo_scope_summary, get_sysvol_size_summary, get_wmi_filter_summary,
)
from .security_filter import (
    filter_by_severity, filter_by_category, filter_by_gpo, filter_by_cve,
    group_by_severity, group_by_category, get_severity_rank, sort_by_severity,
    get_unique_cves, summarize_findings,
)

__version__ = "3.1"
__all__ = [
    # logging
    "setup_logging", "get_logger",
    # console
    "Colors", "colored", "icon", "print_banner", "h", "ProgressBar",
    # config
    "ConfigError", "load_config", "validate_config", "ensure_output_dir", "security_lint",
    # ad
    "ADConnection", "ARGS_REQUIRE_LDAPS", "LAST_CONNECTION_MODE",
    # security
    "SecurityAnalyzer",
    # gpo
    "get_gpo_list", "get_gpo_folder_size", "format_size",
    "check_gpo_sysvol_components", "check_gpo_components_parallel",
    "detect_orphaned_gpos", "get_ou_links", "get_wmi_filters",
    "analyze_gpo_versions", "compare_gpo",
    # parsers
    "parse_registry_pol", "parse_gpp_preferences", "parse_scripts",
    # reports
    "save_json", "save_csv", "save_excel", "save_html_report",
    # change tracking
    "load_previous_scan", "save_scan_cache", "load_scan_cache", "compare_scans",
    # notifications
    "send_email_notification", "send_teams_notification",
    # dashboard
    "calculate_risk_score", "get_severity_distribution",
    "get_category_distribution", "get_gpo_health_summary",
    "get_compliance_score", "get_top_risky_gpos", "get_category_breakdown",
    "get_gpo_scope_summary", "get_sysvol_size_summary", "get_wmi_filter_summary",
    # security_filter
    "filter_by_severity", "filter_by_category", "filter_by_gpo", "filter_by_cve",
    "group_by_severity", "group_by_category", "get_severity_rank", "sort_by_severity",
    "get_unique_cves", "summarize_findings",
    # gpo new functions
    "check_sysvol_consistency", "get_inheritance_info", "get_user_computer_scope", "parse_wmi_query",
]
