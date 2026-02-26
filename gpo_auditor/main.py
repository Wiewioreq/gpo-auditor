"""CLI entry point, argument parsing, and main orchestration."""

import os
import sys
import argparse
import traceback
from datetime import datetime
from multiprocessing import freeze_support

from .logging_setup import setup_logging, get_logger
from .console import Colors, colored, icon, print_banner
from .config import (load_config, validate_config, security_lint,
                     ensure_output_dir, get_password_from_env_or_prompt, ConfigError)
from .ad import ARGS_REQUIRE_LDAPS as _ARGS_REQUIRE_LDAPS
import gpo_auditor.ad as _ad_module
from .gpo import (get_gpo_list, get_ou_links, get_wmi_filters,
                  check_gpo_components_parallel, detect_orphaned_gpos,
                  analyze_gpo_versions, compare_gpo,
                  check_sysvol_consistency, get_inheritance_info, get_user_computer_scope)
from .parser_registry import parse_registry_pol
from .parser_gpp import parse_gpp_preferences
from .parser_scripts import parse_scripts
from .security import SecurityAnalyzer
from .reports import save_json, save_csv, save_excel, save_html_report
from .change_tracking import load_previous_scan, save_scan_cache, load_scan_cache, compare_scans
from .notifications import send_email_notification, send_teams_notification
from .security_filter import summarize_findings, sort_by_severity
from .dashboard import get_compliance_score, get_top_risky_gpos


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='🔍 GPO Audit System Pro - Advanced Group Policy Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  gpo_report.exe --config config.yaml
  gpo_report.exe --config config.yaml --security-only
  gpo_report.exe --config config.yaml --compare-gpo "GPO1" "GPO2"
  gpo_report.exe --config config.yaml --notify
  gpo_report.exe --config config.yaml --track-changes
  gpo_report.exe --config config.yaml --require-ldaps

For more information, visit: https://github.com/yourusername/gpo-audit
        """
    )

    parser.add_argument('--config', default='config.yaml', help='Path to configuration file')

    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--no-json', action='store_true', help='Skip JSON output')
    output_group.add_argument('--no-csv', action='store_true', help='Skip CSV output')
    output_group.add_argument('--no-excel', action='store_true', help='Skip Excel output')
    output_group.add_argument('--no-html', action='store_true', help='Skip HTML output')
    output_group.add_argument('--only-json', action='store_true', help='Only JSON output')
    output_group.add_argument('--only-html', action='store_true', help='Only HTML output')
    output_group.add_argument('--only-excel', action='store_true', help='Only Excel output')
    output_group.add_argument('--output-dir', help='Override output directory')

    # Analysis options
    analysis_group = parser.add_argument_group('Analysis Options')
    analysis_group.add_argument('--security-only', action='store_true', help='Only run security analysis')
    analysis_group.add_argument('--no-security', action='store_true', help='Skip security analysis')
    analysis_group.add_argument('--no-registry', action='store_true', help='Skip registry.pol parsing')
    analysis_group.add_argument('--no-gpp', action='store_true', help='Skip GPP parsing')
    analysis_group.add_argument('--no-scripts', action='store_true', help='Skip script parsing')
    analysis_group.add_argument('--compare-gpo', nargs=2, metavar=('GPO1', 'GPO2'), help='Compare two GPOs')
    analysis_group.add_argument('--track-changes', action='store_true', help='Compare with previous scan')
    analysis_group.add_argument('--detect-orphans', action='store_true', help='Detect orphaned GPOs')

    # Security controls
    security_group = parser.add_argument_group('Security Controls')
    security_group.add_argument('--accept-insecure-ldap', action='store_true',
                                help='Suppress warnings about insecure LDAP/TLS')
    security_group.add_argument('--require-ldaps', action='store_true',
                                help='Fail if secure LDAPS/StartTLS cannot be established')

    # Performance options
    perf_group = parser.add_argument_group('Performance Options')
    perf_group.add_argument('--processes', type=int, default=None, help='Number of parallel processes')
    perf_group.add_argument('--sequential', action='store_true', help='Force sequential processing')
    perf_group.add_argument('--use-cache', action='store_true', help='Use cached AD data if available')
    perf_group.add_argument('--cache-hours', type=int, default=24, help='Cache validity in hours')

    # Notification options
    notify_group = parser.add_argument_group('Notification Options')
    notify_group.add_argument('--notify', action='store_true', help='Send notifications after scan')
    notify_group.add_argument('--email-only', action='store_true', help='Only send email notification')
    notify_group.add_argument('--teams-only', action='store_true', help='Only send Teams notification')

    # Other options
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    parser.add_argument('--debug', action='store_true', help='Debug mode with full logging')
    parser.add_argument('--version', action='version', version='GPO Audit System Pro v3.1')

    return parser.parse_args()


def apply_auto_notifications(config, args):
    """
    Auto‑powiadomienia przy podwójnym kliknięciu (brak flag CLI).
    Nie wymuszamy --email-only / --teams-only (są wzajemnie wykluczające),
    tylko zapisujemy wewnętrzne znaczniki i później WYLICZAMY kanały.
    """
    # Double‑click heurystyka: brak parametrów = uruchomienie bezpośrednio z EXE
    if len(sys.argv) > 1:
        return args

    notif_cfg = config.get("notifications", {})
    if not notif_cfg.get("enabled", False):
        return args

    auto_email = bool(notif_cfg.get("auto_email_on_double_click", False))
    auto_teams = bool(notif_cfg.get("auto_teams_on_double_click", False))

    # Jeśli jakikolwiek kanał ma być wysłany automatycznie — ustaw ogólny 'notify'
    if auto_email or auto_teams:
        args.notify = True

    # Zapamiętaj wewnętrzne flagi; na ich podstawie policzymy 'send_email'/'send_teams' w main()
    setattr(args, "_auto_email", auto_email)
    setattr(args, "_auto_teams", auto_teams)
    return args


def main():
    """Main entry point."""
    # Parse arguments first
    args = parse_arguments()

    # Load configuration (rzeczywisty plik z --config)
    print(colored(f"\n{icon('📋', '[CFG]')} Loading Configuration...", Colors.BOLD))
    config = load_config(args.config)

    # Ustal auto‑powiadomienia po wczytaniu WŁAŚCIWEGO config.yaml
    args = apply_auto_notifications(config, args)

    # Set global flags in the ad module
    _ad_module.ARGS_REQUIRE_LDAPS = getattr(args, 'require_ldaps', False)

    # Initialize logging based on args
    log_level = 'DEBUG' if args.debug else 'INFO'
    console_level = 'DEBUG' if args.debug else ('WARNING' if args.quiet else 'INFO')
    setup_logging(log_level=log_level, console_level=console_level)
    log = get_logger()

    try:
        # Print banner
        if not args.quiet:
            print_banner()

        # Resolve password from ENV or prompt if needed
        config['ad']['_resolved_password'] = get_password_from_env_or_prompt(config)

        # Validate configuration
        validate_config(config)

        # Security lint
        if not args.quiet:
            security_lint(config, args)

        # Override output directory if specified
        if args.output_dir:
            config['paths']['output_dir'] = args.output_dir

        # Setup directories
        output_dir = ensure_output_dir(config['paths']['output_dir'])
        sysvol_path = config['paths']['sysvol']

        # Get options
        options = config.get('options', {})

        # Apply CLI overrides
        if args.no_json: options['generate_json'] = False
        if args.no_csv: options['generate_csv'] = False
        if args.no_excel: options['generate_excel'] = False
        if args.no_html: options['generate_html'] = False
        if args.no_registry: options['parse_registry'] = False
        if args.no_gpp: options['parse_gpp'] = False
        if args.no_scripts: options['parse_scripts'] = False

        if args.only_json or args.only_html or args.only_excel:
            options['generate_json'] = args.only_json
            options['generate_csv'] = False
            options['generate_excel'] = args.only_excel
            options['generate_html'] = args.only_html

        # Check cache
        cached_data = None
        if args.use_cache:
            cached_data = load_scan_cache(output_dir, args.cache_hours)
            if cached_data:
                print(colored(f"  {icon('📦', '[CACHE]')} Using cached data", Colors.CYAN))

        # Step 1: Get GPO list
        print(colored(f"\n{'='*70}", Colors.CYAN))
        print(colored(f"  STEP 1: Fetching GPO List from Active Directory", Colors.BOLD))
        print(colored(f"{'='*70}", Colors.CYAN))

        gpo_list, ad_conn = get_gpo_list(config)
        connection_mode = ad_conn.connection_mode

        # Step 2: Get OU links
        print(colored(f"\n{'='*70}", Colors.CYAN))
        print(colored(f"  STEP 2: Fetching OU Links", Colors.BOLD))
        print(colored(f"{'='*70}", Colors.CYAN))

        ou_to_gpo, gpo_to_ou, blocked_inheritance = get_ou_links(config, ad_conn)

        # Get WMI filters
        wmi_filters = get_wmi_filters(config, ad_conn)

        # Disconnect from AD
        ad_conn.disconnect()

        # Step 3: Detect orphaned GPOs (if requested)
        orphaned_ad = []
        orphaned_sysvol = []
        if args.detect_orphans:
            print(colored(f"\n{'='*70}", Colors.CYAN))
            print(colored(f"  STEP 3: Detecting Orphaned GPOs", Colors.BOLD))
            print(colored(f"{'='*70}", Colors.CYAN))

            orphaned_ad, orphaned_sysvol = detect_orphaned_gpos(gpo_list, sysvol_path)
            print(colored(f"  {icon('⚠️', '!')} Orphaned (no SYSVOL): {len(orphaned_ad)}",
                         Colors.WARNING if orphaned_ad else Colors.GREEN))
            print(colored(f"  {icon('⚠️', '!')} Orphaned (no AD object): {len(orphaned_sysvol)}",
                         Colors.WARNING if orphaned_sysvol else Colors.GREEN))

        # Step 4: Analyze SYSVOL components
        print(colored(f"\n{'='*70}", Colors.CYAN))
        print(colored(f"  STEP 4: Analyzing SYSVOL Components", Colors.BOLD))
        print(colored(f"{'='*70}", Colors.CYAN))

        components = check_gpo_components_parallel(
            gpo_list, sysvol_path,
            num_processes=args.processes,
            sequential=args.sequential
        )

        # Add size info to GPOs
        for gpo, comp in zip(gpo_list, components):
            gpo['size'] = comp.get('size', 0)
            gpo['sysvol_found'] = comp['found']

        # Step 5: Parse GPO contents
        print(colored(f"\n{'='*70}", Colors.CYAN))
        print(colored(f"  STEP 5: Parsing GPO Contents", Colors.BOLD))
        print(colored(f"{'='*70}", Colors.CYAN))

        from .console import ProgressBar
        registry_entries = []
        gpprefs = []
        scripts = []

        if not args.quiet:
            progress = ProgressBar(len(gpo_list), prefix='  Processing')

        for i, (gpo, comp) in enumerate(zip(gpo_list, components)):
            if options.get('parse_registry', True):
                if comp.get('Machine-Registry.pol'):
                    reg_path = os.path.join(sysvol_path, f"{{{gpo['guid']}}}", 'Machine', 'Registry.pol')
                    registry_entries.extend(parse_registry_pol(reg_path, scope='Machine'))
                if comp.get('User-Registry.pol'):
                    reg_path = os.path.join(sysvol_path, f"{{{gpo['guid']}}}", 'User', 'Registry.pol')
                    registry_entries.extend(parse_registry_pol(reg_path, scope='User'))

            if options.get('parse_gpp', True):
                gpprefs.extend(parse_gpp_preferences(comp.get('Preferences', [])))

            if options.get('parse_scripts', True):
                scripts.extend(parse_scripts(comp.get('Scripts', {})))

            if not args.quiet:
                progress.update(suffix=gpo['name'][:30])

        print(colored(f"\n  {icon('✅', 'OK')} Parsed: {len(registry_entries)} registry, {len(gpprefs)} GPP, {len(scripts)} scripts", Colors.GREEN))

        # Step 6: Security Analysis
        security_findings = []
        top_risky_gpos = []

        if not args.no_security:
            print(colored(f"\n{'='*70}", Colors.CYAN))
            print(colored(f"  STEP 6: Security Vulnerability Analysis", Colors.BOLD))
            print(colored(f"{'='*70}", Colors.CYAN))

            analyzer = SecurityAnalyzer()

            if not args.quiet:
                progress = ProgressBar(len(gpo_list), prefix='  Scanning')

            for gpo in gpo_list:
                analyzer.analyze_gpo(gpo, sysvol_path)
                if not args.quiet:
                    progress.update(suffix=gpo['name'][:30])

            security_findings = analyzer.get_findings()
            summary = analyzer.get_summary()
            top_risky_gpos = analyzer.get_top_risky_gpos(10)
            risk_score = analyzer.get_risk_score()

            print(colored(f"\n  {icon('🔒', '[SEC]')} Security Scan Complete (Risk Score: {risk_score}):", Colors.BOLD))
            if summary['CRITICAL'] > 0:
                print(colored(f"     {icon('🔴', '[!]')} Critical: {summary['CRITICAL']}", Colors.FAIL))
            if summary['HIGH'] > 0:
                print(colored(f"     {icon('🟠', '[!]')} High: {summary['HIGH']}", Colors.WARNING))
            if summary['MEDIUM'] > 0:
                print(colored(f"     {icon('🟡', '[!]')} Medium: {summary['MEDIUM']}", Colors.WARNING))
            print(colored(f"     {icon('🟢', '[OK]')} Low: {summary['LOW']}", Colors.GREEN))

        # Step 7: Analyze versions and status
        print(colored(f"\n{'='*70}", Colors.CYAN))
        print(colored(f"  STEP 7: GPO Status Analysis", Colors.BOLD))
        print(colored(f"{'='*70}", Colors.CYAN))

        inconsistencies, unused, disabled = analyze_gpo_versions(gpo_list, gpo_to_ou)

        print(colored(f"  {icon('⚠️', '!')} Version inconsistencies: {len(inconsistencies)}",
                     Colors.WARNING if inconsistencies else Colors.GREEN))
        print(colored(f"  {icon('🚫', '[X]')} Unused GPOs: {len(unused)}",
                     Colors.WARNING if unused else Colors.GREEN))
        print(colored(f"  {icon('⏸️', '[-]')} Disabled GPOs: {len(disabled)}", Colors.CYAN))

        # Enrich GPOs with scope info and inheritance
        get_user_computer_scope(gpo_list, sysvol_path)
        inheritance_info = get_inheritance_info(gpo_list, ou_to_gpo, blocked_inheritance)
        compliance = get_compliance_score(security_findings, gpo_list)
        if not args.quiet:
            print(colored(f"  {icon('📊', '[SCORE]')} Compliance Score: {compliance:.1f}/100", Colors.CYAN))

        # Step 8: Change tracking
        changes = None
        if args.track_changes:
            print(colored(f"\n{'='*70}", Colors.CYAN))
            print(colored(f"  STEP 8: Change Tracking", Colors.BOLD))
            print(colored(f"{'='*70}", Colors.CYAN))

            previous_scan = load_previous_scan(output_dir)
            if previous_scan:
                changes = compare_scans(gpo_list, previous_scan)
                if changes:
                    print(colored(f"  {icon('📊', '[CHG]')} Changes detected:", Colors.CYAN))
                    print(f"     New GPOs: {len(changes['new_gpos'])}")
                    print(f"     Deleted GPOs: {len(changes['deleted_gpos'])}")
                    print(f"     Modified GPOs: {len(changes['modified_gpos'])}")
            else:
                print(colored(f"  {icon('ℹ️', '[i]')} No previous scan found for comparison", Colors.CYAN))

        # Step 9: GPO Comparison (if requested)
        if args.compare_gpo:
            print(colored(f"\n{'='*70}", Colors.CYAN))
            print(colored(f"  STEP 9: GPO Comparison", Colors.BOLD))
            print(colored(f"{'='*70}", Colors.CYAN))

            gpo1 = next((g for g in gpo_list if g['name'] == args.compare_gpo[0]), None)
            gpo2 = next((g for g in gpo_list if g['name'] == args.compare_gpo[1]), None)

            if gpo1 and gpo2:
                comparison = compare_gpo(gpo1, gpo2, sysvol_path)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                save_json(comparison, os.path.join(output_dir, f'gpo_comparison_{timestamp}.json'))
                print(colored(f"  {icon('✅', 'OK')} Comparison saved", Colors.GREEN))
            else:
                print(colored(f"  {icon('❌', 'X')} GPO not found: {args.compare_gpo}", Colors.FAIL))

        # Step 10: Generate reports
        print(colored(f"\n{'='*70}", Colors.CYAN))
        print(colored(f"  STEP 10: Generating Reports", Colors.BOLD))
        print(colored(f"{'='*70}", Colors.CYAN))

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        if options.get('generate_json', True):
            save_json(gpo_list, os.path.join(output_dir, f'gpos_{timestamp}.json'))
            if security_findings:
                save_json(security_findings, os.path.join(output_dir, f'security_findings_{timestamp}.json'))

        if options.get('generate_csv', True):
            save_csv(gpo_list, os.path.join(output_dir, f'gpos_{timestamp}.csv'))
            if security_findings:
                save_csv(security_findings, os.path.join(output_dir, f'security_findings_{timestamp}.csv'))

        if options.get('generate_excel', True):
            save_excel(gpo_list, registry_entries, gpprefs, scripts, gpo_to_ou,
                      inconsistencies, unused, security_findings,
                      os.path.join(output_dir, f'gpo_audit_{timestamp}.xlsx'),
                      wmi_filters=wmi_filters, disabled=disabled,
                      blocked_inheritance=blocked_inheritance, changes=changes)

        html_path = None
        if options.get('generate_html', True):
            html_path = os.path.join(output_dir, f'gpo_report_{timestamp}.html')
            save_html_report(gpo_list, registry_entries, gpprefs, scripts,
                           inconsistencies, unused, security_findings, changes,
                           blocked_inheritance, connection_mode, top_risky_gpos, html_path,
                           wmi_filters=wmi_filters, disabled=disabled)

        # Save cache for next run
        if not args.use_cache:
            save_scan_cache({
                'gpo_list': gpo_list,
                'gpo_to_ou': gpo_to_ou,
            }, output_dir)

        # Step 11: Send notifications
        # Policz ostatecznie, co wysyłamy (CLI + auto_* z config.yaml)
        auto_email = getattr(args, "_auto_email", False)
        auto_teams = getattr(args, "_auto_teams", False)
        send_email = (args.notify and not args.teams_only) or args.email_only or auto_email
        send_teams = (args.notify and not args.email_only) or args.teams_only or auto_teams

        if send_email or send_teams:
            print(colored(f"\n{'='*70}", Colors.CYAN))
            print(colored(f" STEP 11: Sending Notifications", Colors.BOLD))
            print(colored(f"{'='*70}", Colors.CYAN))

        notification_summary = {
            'total_gpos': len(gpo_list),
            'total_findings': len(security_findings),
            'critical': sum(1 for f in security_findings if f.get('severity') == 'CRITICAL'),
            'high': sum(1 for f in security_findings if f.get('severity') == 'HIGH'),
            'medium': sum(1 for f in security_findings if f.get('severity') == 'MEDIUM'),
            'unused': len(unused),
            'inconsistencies': len(inconsistencies)
        }

        if send_email:
            send_email_notification(config, html_path, notification_summary)
        if send_teams:
            send_teams_notification(config, notification_summary)

        # Final summary
        print(colored(f"\n{'='*70}", Colors.GREEN))
        print(colored(f"  {icon('✅', 'OK')} AUDIT COMPLETED SUCCESSFULLY!", Colors.GREEN + Colors.BOLD))
        print(colored(f"{'='*70}", Colors.GREEN))

        print(colored(f"\n  {icon('📊', '[SUMMARY]')} Summary:", Colors.BOLD))
        print(f"     {icon('•', '*')} Total GPOs analyzed: {len(gpo_list)}")
        print(f"     {icon('•', '*')} Security findings: {len(security_findings)}")
        print(f"     {icon('•', '*')} Registry entries: {len(registry_entries)}")
        print(f"     {icon('•', '*')} GPP preferences: {len(gpprefs)}")
        print(f"     {icon('•', '*')} Scripts found: {len(scripts)}")
        print(f"     {icon('•', '*')} Version inconsistencies: {len(inconsistencies)}")
        print(f"     {icon('•', '*')} Unused GPOs: {len(unused)}")

        if connection_mode == 'ldap_insecure':
            print(colored(f"\n  {icon('⚠️', '!')} Warning: Connection was established over insecure LDAP", Colors.WARNING))

        print(colored(f"\n  {icon('📂', '[DIR]')} Reports saved to: {output_dir}", Colors.CYAN))
        print(colored(f"{'='*70}\n", Colors.GREEN))

        log.info("Audit completed successfully!")

    except ConfigError as e:
        log.error(f"{e}")
        print(colored(f"\n{icon('❌', 'X')} Configuration Error: {e}", Colors.FAIL))
        sys.exit(1)
    except KeyboardInterrupt:
        print(colored(f"\n\n{icon('⚠️', '!')} Audit cancelled by user", Colors.WARNING))
        sys.exit(130)
    except Exception as e:
        log.error(f"Unexpected error: {e}", exc_info=True)
        print(colored(f"\n{icon('❌', 'X')} Unexpected error: {e}", Colors.FAIL))
        if args.debug:
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    freeze_support()
    main()
