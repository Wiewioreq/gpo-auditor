"""Email and Microsoft Teams notification senders."""

import os
import smtplib
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict

from .logging_setup import get_logger
from .console import Colors, colored, icon

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def send_email_notification(config: dict, report_path: str, summary: Dict) -> None:
    """Send email notification with report attached."""
    log = get_logger()

    email_config = config.get('notifications', {}).get('email', {})
    if not email_config.get('enabled', False):
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = email_config['from']
        msg['To'] = ', '.join(email_config['to'])
        msg['Subject'] = f"GPO Audit Report - {datetime.now().strftime('%Y-%m-%d')}"

        body = f"""
GPO Audit Report Summary
========================

Total GPOs: {summary['total_gpos']}
Security Findings: {summary['total_findings']}
  - Critical: {summary['critical']}
  - High: {summary['high']}
  - Medium: {summary['medium']}
Unused GPOs: {summary['unused']}
Inconsistencies: {summary['inconsistencies']}

Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please review the attached HTML report for details.
"""
        msg.attach(MIMEText(body, 'plain'))

        if os.path.exists(report_path):
            with open(report_path, 'rb') as f:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(report_path)}"')
                msg.attach(part)

        server = smtplib.SMTP(email_config['smtp_server'], email_config.get('smtp_port', 587))
        server.starttls()
        if email_config.get('username') and email_config.get('password'):
            server.login(email_config['username'], email_config['password'])
        server.send_message(msg)
        server.quit()

        log.info("Email notification sent successfully")
        print(colored(f"  {icon('📧', '[EMAIL]')} Email notification sent", Colors.GREEN))

    except Exception as e:
        log.error(f"Failed to send email: {e}")
        print(colored(f"  {icon('⚠️', '!')} Email notification failed: {e}", Colors.WARNING))


def send_teams_notification(config: dict, summary: Dict) -> None:
    """Send Microsoft Teams notification via webhook."""
    log = get_logger()

    if not HAS_REQUESTS:
        return

    teams_config = config.get('notifications', {}).get('teams', {})
    if not teams_config.get('enabled', False):
        return

    webhook_url = teams_config.get('webhook_url')
    if not webhook_url:
        return

    try:
        # Determine color based on findings
        if summary['critical'] > 0:
            color = "dc3545"
        elif summary['high'] > 0:
            color = "fd7e14"
        elif summary['medium'] > 0:
            color = "ffc107"
        else:
            color = "28a745"

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": "GPO Audit Report",
            "sections": [{
                "activityTitle": "🔍 GPO Security Audit Complete",
                "activitySubtitle": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "facts": [
                    {"name": "Total GPOs", "value": str(summary['total_gpos'])},
                    {"name": "🔴 Critical", "value": str(summary['critical'])},
                    {"name": "🟠 High", "value": str(summary['high'])},
                    {"name": "🟡 Medium", "value": str(summary['medium'])},
                    {"name": "Unused GPOs", "value": str(summary['unused'])},
                    {"name": "Inconsistencies", "value": str(summary['inconsistencies'])}
                ],
                "markdown": True
            }]
        }

        response = requests.post(webhook_url, json=payload, timeout=10)

        if response.status_code == 200:
            log.info("Teams notification sent successfully")
            print(colored(f"  {icon('📱', '[TEAMS]')} Teams notification sent", Colors.GREEN))
        else:
            log.warning(f"Teams notification failed: {response.status_code}")

    except Exception as e:
        log.error(f"Failed to send Teams notification: {e}")
