"""Report generation: JSON, CSV, Excel, HTML."""

import csv
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import pandas as pd

from .logging_setup import get_logger
from .console import Colors, colored, icon, h

try:
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.chart import PieChart, BarChart, Reference
    from openpyxl.chart.label import DataLabelList
    HAS_OPENPYXL_STYLES = True
except ImportError:
    HAS_OPENPYXL_STYLES = False


def save_json(data: Any, path: str) -> None:
    """Save data to JSON file."""
    log = get_logger()
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        log.info(f"JSON saved: {path}")
        print(colored(f"  {icon('✅', 'OK')} JSON: {path}", Colors.GREEN))
    except Exception as e:
        log.error(f"Error saving JSON: {e}")
        print(colored(f"  {icon('❌', 'X')} JSON error: {e}", Colors.FAIL))


def save_csv(data: List[Dict], path: str, fields: Optional[List[str]] = None) -> None:
    """Save data to CSV file."""
    log = get_logger()
    if not data:
        log.warning(f"No data for CSV: {path}")
        return
    try:
        with open(path, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(f, fieldnames=fields or data[0].keys(), extrasaction='ignore')
            writer.writeheader()
            writer.writerows(data)
        log.info(f"CSV saved: {path}")
        print(colored(f"  {icon('✅', 'OK')} CSV: {path}", Colors.GREEN))
    except Exception as e:
        log.error(f"Error saving CSV: {e}")


def save_excel(gpo_list: List[Dict], registry: List[Dict], gpprefs: List[Dict],
               scripts: List[Dict], links: Dict, inconsistencies: List[Dict],
               unused: List[Dict], security_findings: List[Dict], path: str,
               wmi_filters: Optional[Dict] = None, disabled: Optional[List[Dict]] = None,
               blocked_inheritance: Optional[List[str]] = None,
               changes: Optional[Dict] = None) -> None:
    """Save reports to styled Excel file with multiple sheets and charts."""
    log = get_logger()
    try:
        with pd.ExcelWriter(path, engine='openpyxl') as writer:
            # Summary sheet
            summary_data = [{
                'Metric': 'Total GPOs',
                'Value': len(gpo_list)
            }, {
                'Metric': 'Security Findings',
                'Value': len(security_findings)
            }, {
                'Metric': 'Critical Issues',
                'Value': sum(1 for f in security_findings if f.get('severity') == 'CRITICAL')
            }, {
                'Metric': 'High Issues',
                'Value': sum(1 for f in security_findings if f.get('severity') == 'HIGH')
            }, {
                'Metric': 'Medium Issues',
                'Value': sum(1 for f in security_findings if f.get('severity') == 'MEDIUM')
            }, {
                'Metric': 'Unused GPOs',
                'Value': len(unused)
            }, {
                'Metric': 'Inconsistent GPOs',
                'Value': len(inconsistencies)
            }, {
                'Metric': 'Report Generated',
                'Value': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }]
            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)

            # GPO Summary
            from .gpo import format_size
            gpo_df = pd.DataFrame(gpo_list)
            if 'size' in gpo_df.columns:
                gpo_df['size_formatted'] = gpo_df['size'].apply(format_size)
            gpo_df.to_excel(writer, sheet_name='GPO Summary', index=False)

            # Security Findings
            if security_findings:
                # Truncate long fields for Excel
                findings_df = pd.DataFrame(security_findings)
                for col in ['description', 'recommendation', 'file']:
                    if col in findings_df.columns:
                        findings_df[col] = findings_df[col].astype(str).str[:500]
                findings_df.to_excel(writer, sheet_name='Security Findings', index=False)

            # Registry
            if registry:
                reg_df = pd.DataFrame(registry)
                for col in ['key', 'data']:
                    if col in reg_df.columns:
                        reg_df[col] = reg_df[col].astype(str).str[:500]
                reg_df.to_excel(writer, sheet_name='Registry', index=False)

            # GPP Preferences
            if gpprefs:
                gpp_df = pd.DataFrame(gpprefs)
                for col in ['attributes', 'targeting']:
                    if col in gpp_df.columns:
                        gpp_df[col] = gpp_df[col].astype(str).str[:500]
                gpp_df.to_excel(writer, sheet_name='GPP Preferences', index=False)

            # Scripts
            if scripts:
                pd.DataFrame(scripts).to_excel(writer, sheet_name='Scripts', index=False)

            # OU Links
            if links:
                links_data = []
                for gpo_guid, ous in links.items():
                    for ou_info in ous:
                        links_data.append({
                            'gpo_guid': gpo_guid,
                            'ou': ou_info['ou'] if isinstance(ou_info, dict) else ou_info,
                            'enforced': ou_info.get('enforced', False) if isinstance(ou_info, dict) else False
                        })
                if links_data:
                    pd.DataFrame(links_data).to_excel(writer, sheet_name='OU Links', index=False)

            # Inconsistencies
            if inconsistencies:
                pd.DataFrame(inconsistencies).to_excel(writer, sheet_name='Inconsistencies', index=False)

            # Unused GPOs
            if unused:
                pd.DataFrame(unused).to_excel(writer, sheet_name='Unused GPOs', index=False)

            # WMI Filters
            if wmi_filters:
                wmi_data = []
                for wid, wf in wmi_filters.items():
                    row = {'id': wid, 'name': wf.get('name', ''), 'query': wf.get('query', ''),
                           'description': wf.get('description', '')}
                    parsed = wf.get('parsed_query', {})
                    row['wmi_class'] = parsed.get('class', '')
                    row['wmi_namespace'] = parsed.get('namespace', '')
                    row['wmi_conditions'] = '; '.join(parsed.get('conditions', []))
                    wmi_data.append(row)
                pd.DataFrame(wmi_data).to_excel(writer, sheet_name='WMI Filters', index=False)

            # Disabled GPOs
            if disabled:
                pd.DataFrame(disabled).to_excel(writer, sheet_name='Disabled GPOs', index=False)

            # Blocked Inheritance
            if blocked_inheritance:
                bi_data = [{'ou_dn': ou} for ou in blocked_inheritance]
                pd.DataFrame(bi_data).to_excel(writer, sheet_name='Blocked Inheritance', index=False)

            # Change Tracking
            if changes:
                change_rows = []
                for gpo_info in changes.get('new_gpos', []):
                    change_rows.append({'change_type': 'New', 'name': gpo_info.get('name', ''),
                                        'guid': gpo_info.get('guid', ''), 'detail': ''})
                for gpo_info in changes.get('deleted_gpos', []):
                    change_rows.append({'change_type': 'Deleted', 'name': gpo_info.get('name', ''),
                                        'guid': gpo_info.get('guid', ''), 'detail': ''})
                for gpo_info in changes.get('modified_gpos', []):
                    change_rows.append({
                        'change_type': 'Modified', 'name': gpo_info.get('name', ''),
                        'guid': gpo_info.get('guid', ''),
                        'detail': f"v{gpo_info.get('old_version','')} -> v{gpo_info.get('new_version','')}",
                    })
                if change_rows:
                    pd.DataFrame(change_rows).to_excel(writer, sheet_name='Change Tracking', index=False)

            # Security Summary
            sev_dist = {s: 0 for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')}
            cat_dist: Dict[str, int] = {}
            for f in security_findings:
                sev = f.get('severity', 'INFO')
                sev_dist[sev] = sev_dist.get(sev, 0) + 1
                cat = f.get('category', 'Unknown')
                cat_dist[cat] = cat_dist.get(cat, 0) + 1
            sec_summary_data = [{'type': 'Severity', 'label': k, 'count': v} for k, v in sev_dist.items()]
            sec_summary_data += [{'type': 'Category', 'label': k, 'count': v}
                                  for k, v in sorted(cat_dist.items(), key=lambda x: x[1], reverse=True)]
            pd.DataFrame(sec_summary_data).to_excel(writer, sheet_name='Security Summary', index=False)

            # Apply styling
            if HAS_OPENPYXL_STYLES:
                _style_excel_workbook(writer.book, security_findings)

        log.info(f"Excel saved: {path}")
        print(colored(f"  {icon('✅', 'OK')} Excel: {path}", Colors.GREEN))
    except Exception as e:
        log.error(f"Error saving Excel: {e}")
        print(colored(f"  {icon('❌', 'X')} Excel error: {e}", Colors.FAIL))


def _style_excel_workbook(workbook, security_findings: List[Dict]) -> None:
    """Apply styling to Excel workbook."""
    header_font = Font(bold=True, color="FFFFFF", size=11)
    header_fill = PatternFill(start_color="2E86AB", end_color="2E86AB", fill_type="solid")
    header_alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    thin_border = Border(
        left=Side(style='thin', color='CCCCCC'),
        right=Side(style='thin', color='CCCCCC'),
        top=Side(style='thin', color='CCCCCC'),
        bottom=Side(style='thin', color='CCCCCC')
    )

    severity_fills = {
        'CRITICAL': PatternFill(start_color="FF6B6B", end_color="FF6B6B", fill_type="solid"),
        'HIGH': PatternFill(start_color="FFA06B", end_color="FFA06B", fill_type="solid"),
        'MEDIUM': PatternFill(start_color="FFE66B", end_color="FFE66B", fill_type="solid"),
        'LOW': PatternFill(start_color="C8E6C9", end_color="C8E6C9", fill_type="solid"),
    }
    warning_fill = PatternFill(start_color="FFE0B2", end_color="FFE0B2", fill_type="solid")
    alt_row_fill = PatternFill(start_color="F8F9FA", end_color="F8F9FA", fill_type="solid")

    for sheet_name in workbook.sheetnames:
        ws = workbook[sheet_name]
        if ws.max_row < 1:
            continue

        # Header styling
        for col in range(1, ws.max_column + 1):
            cell = ws.cell(row=1, column=col)
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_alignment
            cell.border = thin_border

        # Data rows
        severity_col = None
        for col in range(1, ws.max_column + 1):
            if ws.cell(row=1, column=col).value == 'severity':
                severity_col = col
                break

        for row in range(2, ws.max_row + 1):
            for col in range(1, ws.max_column + 1):
                cell = ws.cell(row=row, column=col)
                cell.border = thin_border
                cell.alignment = Alignment(vertical="center", wrap_text=True)

                if row % 2 == 0:
                    cell.fill = alt_row_fill

            # Color by severity
            if sheet_name == 'Security Findings' and severity_col:
                severity = ws.cell(row=row, column=severity_col).value
                fill = severity_fills.get(severity)
                if fill:
                    for col in range(1, ws.max_column + 1):
                        ws.cell(row=row, column=col).fill = fill

            if sheet_name in ['Inconsistencies', 'Unused GPOs']:
                for col in range(1, ws.max_column + 1):
                    ws.cell(row=row, column=col).fill = warning_fill

        # Auto-width columns
        for col in range(1, ws.max_column + 1):
            max_length = 0
            column_letter = get_column_letter(col)
            for row in range(1, min(ws.max_row + 1, 100)):
                cell = ws.cell(row=row, column=col)
                try:
                    if cell.value:
                        max_length = max(max_length, len(str(cell.value)))
                except:
                    pass
            adjusted_width = min(max(max_length + 2, 12), 60)
            ws.column_dimensions[column_letter].width = adjusted_width

        ws.freeze_panes = "A2"
        if ws.max_row > 1:
            ws.auto_filter.ref = f"A1:{get_column_letter(ws.max_column)}{ws.max_row}"


def save_html_report(gpo_list: List[Dict], registry: List[Dict], gpprefs: List[Dict],
                     scripts: List[Dict], inconsistencies: List[Dict], unused: List[Dict],
                     security_findings: List[Dict], changes: Optional[Dict],
                     blocked_inheritance: List[str], connection_mode: Optional[str],
                     top_risky_gpos: List[Dict], path: str,
                     gpprefs_tab: bool = True,
                     wmi_filters: Optional[Dict] = None,
                     disabled: Optional[List[Dict]] = None) -> None:
    """Generate interactive HTML dashboard with charts, security findings, and timeline."""
    log = get_logger()

    from .gpo import format_size

    # Calculate statistics
    total_gpos = len(gpo_list)
    total_findings = len(security_findings) if security_findings else 0

    security_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    if security_findings:
        for f in security_findings:
            sev = f.get('severity', 'LOW')
            security_summary[sev] = security_summary.get(sev, 0) + 1

    # Connection security warning
    connection_warning = ""
    if connection_mode == 'ldap_insecure':
        connection_warning = """
        <div style="margin-top:12px;padding:12px 20px;border-radius:10px;background:#fff3cd;color:#856404;display:inline-block;">
            ⚠️ Report generated from a session established over <strong>insecure LDAP:389 (no TLS)</strong>.
            Use for lab/POC only.
        </div>
        """

    # Changes summary
    changes_html = ""
    if changes:
        new_count = len(changes.get('new_gpos', []))
        deleted_count = len(changes.get('deleted_gpos', []))
        modified_count = len(changes.get('modified_gpos', []))

        if new_count or deleted_count or modified_count:
            changes_html = f"""
            <div class="section">
                <h2 class="section-title">📊 Changes Since Last Scan</h2>
                <div class="changes-grid">
                    <div class="change-box new"><span class="change-number">{new_count}</span><span class="change-label">New GPOs</span></div>
                    <div class="change-box deleted"><span class="change-number">{deleted_count}</span><span class="change-label">Deleted GPOs</span></div>
                    <div class="change-box modified"><span class="change-number">{modified_count}</span><span class="change-label">Modified GPOs</span></div>
                </div>
            """

            # Timeline of changes
            if changes.get('modified_gpos'):
                changes_html += """
                <div style="margin-top:20px;">
                    <h3 style="color:#333;margin-bottom:15px;">📅 Recent Changes Timeline</h3>
                    <div class="table-wrapper">
                        <table>
                            <tr><th>GPO Name</th><th>Old Version</th><th>New Version</th><th>Previous Modified</th><th>Current Modified</th></tr>
                """
                for mod in changes['modified_gpos'][:10]:
                    changes_html += f"""
                    <tr>
                        <td><strong>{h(mod['name'])}</strong></td>
                        <td>{h(mod['old_version'])}</td>
                        <td>{h(mod['new_version'])}</td>
                        <td>{h(mod['old_modified'])}</td>
                        <td>{h(mod['new_modified'])}</td>
                    </tr>
                    """
                changes_html += "</table></div></div>"

            changes_html += "</div>"

    # Top risky GPOs section
    top_risky_html = ""
    if top_risky_gpos:
        top_risky_html = """
        <div class="section">
            <h2 class="section-title">🎯 Top 10 Risky GPOs</h2>
            <div class="table-wrapper">
                <table>
                    <tr><th>Rank</th><th>GPO Name</th><th>Risk Score</th><th>Findings</th></tr>
        """
        for i, gpo in enumerate(top_risky_gpos, 1):
            score_class = 'badge-critical' if gpo['score'] >= 20 else ('badge-high' if gpo['score'] >= 10 else 'badge-medium')
            top_risky_html += f"""
            <tr>
                <td><strong>#{i}</strong></td>
                <td><strong>{h(gpo['name'])}</strong></td>
                <td><span class="badge {score_class}">{gpo['score']}</span></td>
                <td>{gpo['findings']}</td>
            </tr>
            """
        top_risky_html += "</table></div></div>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GPO Security Audit Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --primary: #2E86AB;
            --secondary: #A23B72;
            --success: #28a745;
            --warning: #ffc107;
            --danger: #dc3545;
            --critical: #721c24;
            --dark: #1a1a2e;
            --light: #f8f9fa;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; 
            background: linear-gradient(135deg, var(--dark) 0%, #16213e 100%); 
            min-height: 100vh; 
            padding: 20px;
            color: #333;
        }}
        .container {{ 
            max-width: 1600px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 20px; 
            box-shadow: 0 25px 80px rgba(0,0,0,0.4); 
            overflow: hidden; 
        }}
        header {{ 
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%); 
            color: white; 
            padding: 50px 40px; 
            text-align: center; 
            position: relative;
        }}
        header::after {{
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--success), var(--warning), var(--danger));
        }}
        header h1 {{ font-size: 2.8em; margin-bottom: 10px; font-weight: 700; }}
        header p {{ font-size: 1.2em; opacity: 0.9; }}
        .header-meta {{ 
            margin-top: 25px; 
            padding-top: 20px; 
            border-top: 1px solid rgba(255,255,255,0.2); 
            display: flex; 
            justify-content: center; 
            gap: 40px; 
            flex-wrap: wrap;
        }}
        .content {{ padding: 40px; }}
        
        .stats-grid {{ 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); 
            gap: 20px; 
            margin: 30px 0; 
        }}
        .stat-box {{ 
            padding: 25px; 
            border-radius: 16px; 
            text-align: center; 
            color: white;
            transition: transform 0.3s, box-shadow 0.3s;
        }}
        .stat-box:hover {{ transform: translateY(-5px); box-shadow: 0 15px 40px rgba(0,0,0,0.2); }}
        .stat-box.primary {{ background: linear-gradient(135deg, var(--primary), #1a5276); }}
        .stat-box.success {{ background: linear-gradient(135deg, var(--success), #1e7e34); }}
        .stat-box.warning {{ background: linear-gradient(135deg, var(--warning), #d39e00); color: #333; }}
        .stat-box.danger {{ background: linear-gradient(135deg, var(--danger), #a71d2a); }}
        .stat-box.critical {{ background: linear-gradient(135deg, #6c1420, var(--critical)); }}
        .stat-box.secondary {{ background: linear-gradient(135deg, var(--secondary), #7b2d59); }}
        .stat-number {{ font-size: 2.8em; font-weight: 700; margin: 10px 0; }}
        .stat-label {{ font-size: 0.9em; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px; }}
        
        .changes-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
        .change-box {{ padding: 20px; border-radius: 12px; text-align: center; color: white; }}
        .change-box.new {{ background: var(--success); }}
        .change-box.deleted {{ background: var(--danger); }}
        .change-box.modified {{ background: var(--warning); color: #333; }}
        .change-number {{ font-size: 2em; font-weight: 700; display: block; }}
        .change-label {{ font-size: 0.85em; opacity: 0.9; }}
        
        .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 30px; margin: 30px 0; }}
        .chart-container {{ background: var(--light); padding: 25px; border-radius: 16px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); }}
        .chart-title {{ font-size: 1.2em; font-weight: 600; margin-bottom: 20px; color: var(--dark); }}
        
        .tabs {{ 
            display: flex; 
            border-bottom: 3px solid var(--primary); 
            margin: 30px 0 25px; 
            background: var(--light); 
            border-radius: 12px 12px 0 0; 
            overflow-x: auto;
        }}
        .tab {{ 
            padding: 18px 30px; 
            cursor: pointer; 
            border: none; 
            background: none; 
            font-size: 0.95em; 
            color: #666; 
            transition: all 0.3s; 
            font-weight: 500;
            white-space: nowrap;
        }}
        .tab:hover {{ color: var(--primary); background: rgba(46, 134, 171, 0.1); }}
        .tab.active {{ color: white; background: var(--primary); font-weight: 600; }}
        .tab-content {{ display: none; animation: fadeIn 0.3s ease; }}
        .tab-content.active {{ display: block; }}
        @keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
        
        .section {{ margin: 40px 0; }}
        .section-title {{ 
            font-size: 1.6em; 
            color: var(--dark); 
            margin-bottom: 20px; 
            padding-bottom: 15px; 
            border-bottom: 3px solid var(--primary);
        }}
        
        .table-wrapper {{ overflow-x: auto; margin: 20px 0; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }}
        table {{ width: 100%; border-collapse: collapse; background: white; }}
        th {{ background: var(--primary); color: white; padding: 16px 15px; text-align: left; font-weight: 600; cursor: pointer; }}
        th:hover {{ background: #256d8a; }}
        td {{ padding: 14px 15px; border-bottom: 1px solid #eee; }}
        tr:hover td {{ background-color: #f8f9ff; }}
        tr:nth-child(even) td {{ background-color: #fafbfc; }}
        
        .severity-critical td {{ background-color: #f8d7da !important; }}
        .severity-high td {{ background-color: #ffe5d0 !important; }}
        .severity-medium td {{ background-color: #fff3cd !important; }}
        
        .search-box {{ margin: 20px 0; }}
        .search-box input {{ 
            width: 100%; 
            padding: 16px 20px; 
            border: 2px solid #e0e0e0; 
            border-radius: 12px; 
            font-size: 1em; 
        }}
        .search-box input:focus {{ outline: none; border-color: var(--primary); }}
        
        .badge {{ display: inline-block; padding: 5px 12px; border-radius: 20px; font-size: 0.8em; font-weight: 600; }}
        .badge-critical {{ background: #f8d7da; color: var(--critical); }}
        .badge-high {{ background: #ffe5d0; color: #856404; }}
        .badge-medium {{ background: #fff3cd; color: #856404; }}
        .badge-low {{ background: #d4edda; color: #155724; }}
        .badge-success {{ background: #d4edda; color: #155724; }}
        .badge-warning {{ background: #fff3cd; color: #856404; }}
        .badge-info {{ background: #cce5ff; color: #004085; }}
        
        code {{ background: #e9ecef; padding: 3px 8px; border-radius: 4px; font-family: 'Consolas', monospace; font-size: 0.85em; }}
        
        .empty-state {{ text-align: center; padding: 60px 20px; color: #6c757d; }}
        .empty-state .icon {{ font-size: 4em; margin-bottom: 20px; opacity: 0.5; }}
        
        footer {{ background: var(--dark); color: white; padding: 30px; text-align: center; }}
        
        @media print {{ 
            body {{ background: white; padding: 0; }} 
            .container {{ box-shadow: none; }} 
            .tabs, .search-box {{ display: none; }} 
            .tab-content {{ display: block !important; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 GPO Security Audit Report</h1>
            <p>Comprehensive Group Policy Objects Analysis</p>
            <div class="header-meta">
                <span>📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                <span>📊 {total_gpos} GPOs Analyzed</span>
                <span>🔒 {total_findings} Security Findings</span>
            </div>
            {connection_warning}
        </header>
        
        <div class="content">
            <div class="section">
                <h2 class="section-title">📈 Executive Summary</h2>
                <div class="stats-grid">
                    <div class="stat-box primary">
                        <div class="stat-label">Total GPOs</div>
                        <div class="stat-number">{total_gpos}</div>
                    </div>
                    <div class="stat-box critical">
                        <div class="stat-label">Critical Issues</div>
                        <div class="stat-number">{security_summary.get('CRITICAL', 0)}</div>
                    </div>
                    <div class="stat-box danger">
                        <div class="stat-label">High Risk</div>
                        <div class="stat-number">{security_summary.get('HIGH', 0)}</div>
                    </div>
                    <div class="stat-box warning">
                        <div class="stat-label">Medium Risk</div>
                        <div class="stat-number">{security_summary.get('MEDIUM', 0)}</div>
                    </div>
                    <div class="stat-box success">
                        <div class="stat-label">Unused GPOs</div>
                        <div class="stat-number">{len(unused)}</div>
                    </div>
                    <div class="stat-box secondary">
                        <div class="stat-label">Inconsistencies</div>
                        <div class="stat-number">{len(inconsistencies)}</div>
                    </div>
                </div>
            </div>
            
            {changes_html}
            {top_risky_html}
            
            <div class="section">
                <h2 class="section-title">📊 Visual Analytics</h2>
                <div class="charts-grid">
                    <div class="chart-container">
                        <div class="chart-title">Security Findings by Severity</div>
                        <canvas id="securityChart"></canvas>
                    </div>
                    <div class="chart-container">
                        <div class="chart-title">GPO Status Overview</div>
                        <canvas id="statusChart"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="tabs">
                <button class="tab active" onclick="showTab(event, 'security')">🔒 Security ({total_findings})</button>
                <button class="tab" onclick="showTab(event, 'gpos')">📋 All GPOs ({total_gpos})</button>
                <button class="tab" onclick="showTab(event, 'issues')">⚠️ Issues ({len(inconsistencies) + len(unused)})</button>
                <button class="tab" onclick="showTab(event, 'registry')">🔧 Registry ({len(registry)})</button>
                <button class="tab" onclick="showTab(event, 'scripts')">📜 Scripts ({len(scripts)})</button>
                <button class="tab" onclick="showTab(event, 'gpp')">📎 GPP ({len(gpprefs)})</button>
                <button class="tab" onclick="showTab(event, 'wmi')">🔒 WMI Filters ({len(wmi_filters) if wmi_filters else 0})</button>
                <button class="tab" onclick="showTab(event, 'inheritance')">🏗️ Inheritance ({len(blocked_inheritance)})</button>
                <button class="tab" onclick="showTab(event, 'disabled_tab')">⏸️ Disabled ({len(disabled) if disabled else 0})</button>"""

    if changes:
        html_content += """<button class="tab" onclick="showTab(event, 'changes_tab')">📊 Changes</button>"""

    html_content += """
            </div>
            
            <div id="security" class="tab-content active">
                <div class="section">
                    <h2 class="section-title">🔒 Security Findings</h2>
                    <div class="search-box">
                        <input type="text" id="securitySearch" placeholder="🔍 Search security findings..." onkeyup="filterTable('securityTable', this)">
                    </div>
                    <div class="table-wrapper">
                        <table id="securityTable">
                            <tr>
                                <th onclick="sortTable(this, 0)">Severity</th>
                                <th onclick="sortTable(this, 1)">GPO Name</th>
                                <th onclick="sortTable(this, 2)">Category</th>
                                <th onclick="sortTable(this, 3)">Finding</th>
                                <th>Recommendation</th>
                            </tr>"""

    if security_findings:
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        for f in sorted(security_findings, key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4)):
            severity = f.get('severity', 'LOW')
            badge_class = f"badge-{severity.lower()}"
            row_class = f"severity-{severity.lower()}"
            rec = h(f.get('recommendation', 'N/A'))[:150]
            html_content += f'''<tr class="{row_class}">
                <td><span class="badge {badge_class}">{h(severity)}</span></td>
                <td><strong>{h(f.get('gpo_name', 'N/A'))}</strong></td>
                <td>{h(f.get('category', 'N/A'))}</td>
                <td>{h(f.get('finding', 'N/A'))}</td>
                <td>{rec}...</td>
            </tr>'''
    else:
        html_content += '<tr><td colspan="5"><div class="empty-state"><div class="icon">✅</div>No security issues found!</div></td></tr>'

    html_content += """</table></div></div></div>
            
            <div id="gpos" class="tab-content">
                <div class="section">
                    <h2 class="section-title">📋 All Group Policy Objects</h2>
                    <div class="search-box">
                        <input type="text" id="gpoSearch" placeholder="🔍 Search GPOs..." onkeyup="filterTable('gpoTable', this)">
                    </div>
                    <div class="table-wrapper">
                        <table id="gpoTable">
                            <tr>
                                <th onclick="sortTable(this, 0)">Name</th>
                                <th>GUID</th>
                                <th onclick="sortTable(this, 2)">Version</th>
                                <th onclick="sortTable(this, 3)">Modified</th>
                                <th>Size</th>
                                <th>Status</th>
                            </tr>"""

    for g in gpo_list:
        status_badge = '<span class="badge badge-success">OK</span>'
        row_class = ""
        if g in inconsistencies:
            status_badge = '<span class="badge badge-warning">Version Mismatch</span>'
            row_class = "severity-medium"
        elif g in unused:
            status_badge = '<span class="badge badge-warning">Unused</span>'

        size = format_size(g.get('size', 0))

        html_content += f'''<tr class="{row_class}">
            <td><strong>{h(g['name'])}</strong></td>
            <td><code>{h(g['guid'][:15])}...</code></td>
            <td>{g['version']} (U:{g['user_version']} C:{g['comp_version']})</td>
            <td>{h(g['whenChanged'])}</td>
            <td>{size}</td>
            <td>{status_badge}</td>
        </tr>'''

    html_content += """</table></div></div></div>
            
            <div id="issues" class="tab-content">
                <div class="section">
                    <h2 class="section-title">⚠️ Version Inconsistencies</h2>
                    <div class="table-wrapper">
                        <table>
                            <tr><th>GPO Name</th><th>GUID</th><th>User Version</th><th>Computer Version</th></tr>"""

    if inconsistencies:
        for g in inconsistencies:
            html_content += f'<tr class="severity-medium"><td><strong>{h(g["name"])}</strong></td><td><code>{h(g["guid"][:20])}...</code></td><td>{g["user_version"]}</td><td>{g["comp_version"]}</td></tr>'
    else:
        html_content += '<tr><td colspan="4"><div class="empty-state"><div class="icon">✅</div>No inconsistencies found</div></td></tr>'

    html_content += """</table></div></div>
                <div class="section">
                    <h2 class="section-title">🚫 Unused GPOs</h2>
                    <div class="table-wrapper">
                        <table>
                            <tr><th>GPO Name</th><th>GUID</th><th>Version</th><th>Last Modified</th></tr>"""

    if unused:
        for g in unused:
            html_content += f'<tr><td><strong>{h(g["name"])}</strong></td><td><code>{h(g["guid"][:20])}...</code></td><td>{g["version"]}</td><td>{h(g["whenChanged"])}</td></tr>'
    else:
        html_content += '<tr><td colspan="4"><div class="empty-state"><div class="icon">✅</div>All GPOs are linked</div></td></tr>'

    html_content += """</table></div></div></div>
            
            <div id="registry" class="tab-content">
                <div class="section">
                    <h2 class="section-title">🔧 Registry Policy Entries</h2>
                    <div class="search-box">
                        <input type="text" id="regSearch" placeholder="🔍 Search registry entries..." onkeyup="filterTable('regTable', this)">
                    </div>
                    <div class="table-wrapper">
                        <table id="regTable">
                            <tr><th>Scope</th><th>Registry Key</th><th>Value Name</th><th>Type</th><th>Data</th></tr>"""

    for r in registry[:200]:
        key = h(r.get('key', ''))
        if len(key) > 60:
            key = '...' + key[-57:]
        data = h(str(r.get('data', '')))[:50]
        scope = h(r.get('scope', 'Unknown'))
        html_content += f'<tr><td><span class="badge badge-info">{scope}</span></td><td><code>{key}</code></td><td><strong>{h(r.get("value", ""))}</strong></td><td>{h(r.get("type", ""))}</td><td>{data}</td></tr>'

    if len(registry) > 200:
        html_content += f'<tr><td colspan="5" style="text-align:center;padding:20px;color:#666;">Showing 200 of {len(registry)} entries</td></tr>'
    if not registry:
        html_content += '<tr><td colspan="5"><div class="empty-state"><div class="icon">📭</div>No registry entries found</div></td></tr>'

    html_content += """</table></div></div></div>
            
            <div id="scripts" class="tab-content">
                <div class="section">
                    <h2 class="section-title">📜 GPO Scripts</h2>
                    <div class="table-wrapper">
                        <table>
                            <tr><th>Type</th><th>Script Name</th><th>Order</th><th>Path</th></tr>"""

    type_colors = {
        'Machine-Startup': '#28a745',
        'Machine-Shutdown': '#dc3545',
        'User-Logon': '#007bff',
        'User-Logoff': '#fd7e14'
    }

    for s in scripts:
        color = type_colors.get(s.get('type', ''), '#6c757d')
        path_display = h(s.get('path', ''))[-60:]
        html_content += f'''<tr>
            <td><span class="badge" style="background:{color};color:white;">{h(s.get('type', ''))}</span></td>
            <td><strong>{h(s.get('name', ''))}</strong></td>
            <td>{s.get('order', '')}</td>
            <td><code>{path_display}</code></td>
        </tr>'''

    if not scripts:
        html_content += '<tr><td colspan="4"><div class="empty-state"><div class="icon">📭</div>No scripts found</div></td></tr>'

    # --- GPP tab ---
    html_content += """</table></div></div></div>

            <div id="gpp" class="tab-content">
                <div class="section">
                    <h2 class="section-title">📎 GPP Preferences</h2>
                    <div class="search-box">
                        <input type="text" id="gppSearch" placeholder="🔍 Search GPP preferences..." onkeyup="filterTable('gppTable', this)">
                    </div>
                    <div class="table-wrapper">
                        <table id="gppTable">
                            <tr><th>File</th><th>Element</th><th>Action</th><th>Attributes</th><th>cPassword?</th></tr>"""

    if gpprefs_tab and gpprefs:
        for p in gpprefs[:500]:
            cpass_badge = '<span class="badge badge-critical">YES ⚠️</span>' if p.get('has_cpassword') else '<span class="badge badge-success">No</span>'
            html_content += f'''<tr>
                <td>{h(p.get("file", ""))}</td>
                <td><strong>{h(p.get("element", ""))}</strong></td>
                <td>{h(p.get("action", ""))}</td>
                <td><code>{h(str(p.get("attributes", ""))[:80])}</code></td>
                <td>{cpass_badge}</td>
            </tr>'''
        if len(gpprefs) > 500:
            html_content += f'<tr><td colspan="5" style="text-align:center;padding:20px;color:#666;">Showing 500 of {len(gpprefs)} entries</td></tr>'
    else:
        html_content += '<tr><td colspan="5"><div class="empty-state"><div class="icon">📭</div>No GPP preferences found</div></td></tr>'

    # --- WMI Filters tab ---
    wmi_count = len(wmi_filters) if wmi_filters else 0
    html_content += """</table></div></div></div>

            <div id="wmi" class="tab-content">
                <div class="section">
                    <h2 class="section-title">🔒 WMI Filters</h2>
                    <div class="table-wrapper">
                        <table>
                            <tr><th>Name</th><th>WMI Class</th><th>Namespace</th><th>Conditions</th><th>Raw Query</th></tr>"""

    if wmi_filters:
        for wid, wf in wmi_filters.items():
            parsed = wf.get('parsed_query', {})
            conds = '; '.join(parsed.get('conditions', []))
            html_content += f'''<tr>
                <td><strong>{h(wf.get("name", wid))}</strong></td>
                <td><code>{h(parsed.get("class", ""))}</code></td>
                <td>{h(parsed.get("namespace", ""))}</td>
                <td>{h(conds[:100])}</td>
                <td><code>{h(wf.get("query", "")[:80])}</code></td>
            </tr>'''
    else:
        html_content += '<tr><td colspan="5"><div class="empty-state"><div class="icon">✅</div>No WMI filters found</div></td></tr>'

    # --- Inheritance tab ---
    html_content += """</table></div></div></div>

            <div id="inheritance" class="tab-content">
                <div class="section">
                    <h2 class="section-title">🏗️ Blocked Inheritance OUs</h2>
                    <div class="table-wrapper">
                        <table>
                            <tr><th>OU Distinguished Name</th></tr>"""

    if blocked_inheritance:
        for ou in blocked_inheritance:
            html_content += f'<tr><td><code>{h(ou)}</code></td></tr>'
    else:
        html_content += '<tr><td><div class="empty-state"><div class="icon">✅</div>No blocked inheritance found</div></td></tr>'

    html_content += """</table></div></div></div>

            <div id="disabled_tab" class="tab-content">
                <div class="section">
                    <h2 class="section-title">⏸️ Disabled GPOs</h2>
                    <div class="table-wrapper">
                        <table>
                            <tr><th>GPO Name</th><th>GUID</th><th>User Enabled</th><th>Computer Enabled</th></tr>"""

    if disabled:
        for g in disabled:
            u_badge = '<span class="badge badge-success">Yes</span>' if g.get('user_enabled', True) else '<span class="badge badge-critical">No</span>'
            c_badge = '<span class="badge badge-success">Yes</span>' if g.get('computer_enabled', True) else '<span class="badge badge-critical">No</span>'
            html_content += f'<tr><td><strong>{h(g.get("name",""))}</strong></td><td><code>{h(g.get("guid","")[:20])}</code></td><td>{u_badge}</td><td>{c_badge}</td></tr>'
    else:
        html_content += '<tr><td colspan="4"><div class="empty-state"><div class="icon">✅</div>No disabled GPOs</div></td></tr>'

    # --- Changes tab (only if changes data is present) ---
    if changes:
        new_count = len(changes.get('new_gpos', []))
        deleted_count = len(changes.get('deleted_gpos', []))
        modified_count = len(changes.get('modified_gpos', []))
        html_content += f"""</table></div></div></div>

            <div id="changes_tab" class="tab-content">
                <div class="section">
                    <h2 class="section-title">📊 Change Tracking</h2>
                    <div class="changes-grid">
                        <div class="change-box new"><span class="change-number">{new_count}</span><span class="change-label">New GPOs</span></div>
                        <div class="change-box deleted"><span class="change-number">{deleted_count}</span><span class="change-label">Deleted GPOs</span></div>
                        <div class="change-box modified"><span class="change-number">{modified_count}</span><span class="change-label">Modified GPOs</span></div>
                    </div>
                    <div class="table-wrapper" style="margin-top:20px;">
                        <table>
                            <tr><th>Change Type</th><th>GPO Name</th><th>Detail</th></tr>"""
        for g in changes.get('new_gpos', []):
            html_content += f'<tr><td><span class="badge badge-success">New</span></td><td><strong>{h(g.get("name",""))}</strong></td><td></td></tr>'
        for g in changes.get('deleted_gpos', []):
            html_content += f'<tr><td><span class="badge badge-critical">Deleted</span></td><td><strong>{h(g.get("name",""))}</strong></td><td></td></tr>'
        for g in changes.get('modified_gpos', []):
            detail = f"v{g.get('old_version','')} → v{g.get('new_version','')}"
            html_content += f'<tr><td><span class="badge badge-warning">Modified</span></td><td><strong>{h(g.get("name",""))}</strong></td><td>{h(detail)}</td></tr>'
        html_content += "</table></div></div></div>"
    else:
        html_content += "</table></div></div></div>"

    html_content += f"""
        </div>
        
        <footer>
            <p><strong>🔐 GPO Audit System Pro v3.1</strong></p>
            <p style="margin-top:10px;opacity:0.8;">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </footer>
    </div>
    
    <script>
        // Charts
        const securityCtx = document.getElementById('securityChart').getContext('2d');
        new Chart(securityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{security_summary.get('CRITICAL', 0)}, {security_summary.get('HIGH', 0)}, {security_summary.get('MEDIUM', 0)}, {security_summary.get('LOW', 0)}],
                    backgroundColor: ['#721c24', '#dc3545', '#ffc107', '#28a745'],
                    borderWidth: 0
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ position: 'bottom' }} }}
            }}
        }});
        
        const statusCtx = document.getElementById('statusChart').getContext('2d');
        new Chart(statusCtx, {{
            type: 'bar',
            data: {{
                labels: ['Total', 'Linked', 'Unused', 'Inconsistent'],
                datasets: [{{
                    label: 'GPO Count',
                    data: [{total_gpos}, {total_gpos - len(unused)}, {len(unused)}, {len(inconsistencies)}],
                    backgroundColor: ['#2E86AB', '#28a745', '#dc3545', '#ffc107']
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{ y: {{ beginAtZero: true }} }}
            }}
        }});
        
        // Tab switching - fixed to not use global event
        function showTab(evt, tabId) {{
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            evt.currentTarget.classList.add('active');
        }}
        
        // Table sorting - fixed
        function sortTable(header, col) {{
            const table = header.closest('table');
            const rows = Array.from(table.querySelectorAll('tr')).slice(1);
            const asc = table.dataset.sortAsc !== 'true';
            rows.sort((a, b) => {{
                const aVal = a.cells[col]?.textContent.trim() || '';
                const bVal = b.cells[col]?.textContent.trim() || '';
                return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
            }});
            rows.forEach(row => table.appendChild(row));
            table.dataset.sortAsc = asc ? 'true' : 'false';
        }}
        
        // Table filtering - fixed
        function filterTable(tableId, input) {{
            const filter = input.value.toUpperCase();
            const rows = document.getElementById(tableId).querySelectorAll('tr');
            rows.forEach((row, i) => {{
                if (i === 0) return;
                row.style.display = row.textContent.toUpperCase().includes(filter) ? '' : 'none';
            }});
        }}
        
        // Print
        function printReport() {{ window.print(); }}
    </script>
</body>
</html>"""

    with open(path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    log.info(f"HTML report saved: {path}")
    print(colored(f"  {icon('✅', 'OK')} HTML: {path}", Colors.GREEN))
