"""Security analysis of GPO settings for vulnerabilities."""

import re
from pathlib import Path
from typing import Dict, List

from .logging_setup import get_logger

try:
    import pyregpol
except ImportError:
    pyregpol = None

try:
    from lxml import etree
    HAS_LXML = True
except ImportError:
    HAS_LXML = False


class SecurityAnalyzer:
    """
    Analyzes GPO settings for security vulnerabilities.
    Detects: cpassword, weak policies, SMBv1, NTLMv1, RDP issues, etc.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    # Severity scores for overall risk calculation
    SEVERITY_SCORES = {
        CRITICAL: 10,
        HIGH: 5,
        MEDIUM: 3,
        LOW: 1,
        INFO: 0
    }

    def __init__(self):
        self.findings: List[Dict] = []
        self.log = get_logger()
        self._findings_by_gpo: Dict[str, List[Dict]] = {}

    def analyze_gpo(self, gpo: Dict, sysvol_path: str) -> None:
        """Run all security checks on a GPO."""
        try:
            gpo_path = Path(sysvol_path) / f"{{{gpo['guid']}}}"

            if not gpo_path.exists():
                return

            # Run all checks
            self._check_cpassword(gpo, gpo_path)
            self._check_registry_policies(gpo, gpo_path)
            self._check_scripts(gpo, gpo_path)
            self._check_gpp_preferences(gpo, gpo_path)

        except Exception as e:
            self.log.error(f"Error analyzing GPO {gpo.get('name', 'unknown')}: {e}")

    def _add_finding(self, finding: Dict) -> None:
        """Add a finding and index it by GPO."""
        self.findings.append(finding)
        gpo_guid = finding.get('gpo_guid', 'unknown')
        if gpo_guid not in self._findings_by_gpo:
            self._findings_by_gpo[gpo_guid] = []
        self._findings_by_gpo[gpo_guid].append(finding)

    def _check_cpassword(self, gpo: Dict, gpo_path: Path) -> None:
        """Check for cpassword (encrypted passwords) in GPP XML files."""
        for xml_file in gpo_path.rglob('*.xml'):
            try:
                with open(xml_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                if 'cpassword' in content.lower():
                    matches = re.findall(r'cpassword="([^"]+)"', content, re.IGNORECASE)
                    for match in matches:
                        if match and len(match) > 0:
                            self._add_finding({
                                'gpo_name': gpo['name'],
                                'gpo_guid': gpo['guid'],
                                'severity': self.CRITICAL,
                                'category': 'Credential Exposure',
                                'finding': 'GPP Password (cpassword) Found',
                                'description': f'Encrypted password found in {xml_file.name}. '
                                              f'These can be trivially decrypted using published AES key (MS14-025).',
                                'file': str(xml_file),
                                'recommendation': 'Remove GPP with passwords immediately. Use LAPS for local admin passwords.',
                                'cve': 'MS14-025'
                            })
                            self.log.warning(f"[SECURITY] CRITICAL: cpassword found in {gpo['name']}")
            except Exception as e:
                self.log.debug(f"Error reading {xml_file}: {e}")

    def _check_registry_policies(self, gpo: Dict, gpo_path: Path) -> None:
        """Check registry.pol for dangerous settings."""
        dangerous_settings = {
            # UAC settings
            'EnableLUA': {
                'dangerous_value': '0',
                'severity': self.HIGH,
                'category': 'User Account Control',
                'finding': 'UAC Disabled',
                'description': 'User Account Control is disabled, reducing system security.',
                'recommendation': 'Enable UAC to protect against privilege escalation.'
            },
            # Firewall
            'EnableFirewall': {
                'dangerous_value': '0',
                'severity': self.HIGH,
                'category': 'Windows Firewall',
                'finding': 'Firewall Disabled',
                'description': 'Windows Firewall is disabled via GPO.',
                'recommendation': 'Enable Windows Firewall and configure appropriate rules.'
            },
            # AutoLogon
            'AutoAdminLogon': {
                'dangerous_value': '1',
                'severity': self.HIGH,
                'category': 'Authentication',
                'finding': 'Auto Admin Logon Enabled',
                'description': 'Automatic administrator logon is enabled.',
                'recommendation': 'Disable automatic logon for privileged accounts.'
            },
            # SMB Signing
            'RequireSecuritySignature': {
                'dangerous_value': '0',
                'severity': self.MEDIUM,
                'category': 'Network Security',
                'finding': 'SMB Signing Not Required',
                'description': 'SMB signing is not required, allowing potential MITM attacks.',
                'recommendation': 'Enable SMB signing requirement.'
            },
            # SMBv1
            'SMB1': {
                'dangerous_value': '1',
                'severity': self.HIGH,
                'category': 'Network Security',
                'finding': 'SMBv1 Enabled',
                'description': 'SMBv1 is enabled, vulnerable to EternalBlue and other exploits.',
                'recommendation': 'Disable SMBv1 protocol.'
            },
            # LLMNR
            'EnableMulticast': {
                'dangerous_value': '1',
                'severity': self.MEDIUM,
                'category': 'Network Security',
                'finding': 'LLMNR Enabled',
                'description': 'LLMNR is enabled, vulnerable to poisoning attacks (Responder).',
                'recommendation': 'Disable LLMNR via GPO.'
            },
            # WDigest
            'UseLogonCredential': {
                'dangerous_value': '1',
                'severity': self.HIGH,
                'category': 'Credential Protection',
                'finding': 'WDigest Credentials Cached',
                'description': 'WDigest authentication stores plaintext credentials in memory (Mimikatz target).',
                'recommendation': 'Disable WDigest credential caching.'
            },
            # LM Hash
            'NoLMHash': {
                'dangerous_value': '0',
                'severity': self.HIGH,
                'category': 'Password Security',
                'finding': 'LM Hash Storage Enabled',
                'description': 'LM hashes are being stored, which are easily cracked.',
                'recommendation': 'Disable LM hash storage (set NoLMHash to 1).'
            },
            # NTLMv1
            'LmCompatibilityLevel': {
                'dangerous_values': ['0', '1', '2'],
                'severity': self.HIGH,
                'category': 'Authentication',
                'finding': 'NTLMv1 Allowed',
                'description': 'NTLMv1 is allowed, which is vulnerable to relay attacks.',
                'recommendation': 'Set LmCompatibilityLevel to 5 (NTLMv2 only).'
            },
            # Anonymous access
            'RestrictAnonymous': {
                'dangerous_value': '0',
                'severity': self.MEDIUM,
                'category': 'Access Control',
                'finding': 'Anonymous Access Allowed',
                'description': 'Anonymous enumeration of SAM accounts is allowed.',
                'recommendation': 'Restrict anonymous access.'
            },
            # RDP NLA
            'UserAuthentication': {
                'dangerous_value': '0',
                'severity': self.MEDIUM,
                'category': 'Remote Access',
                'finding': 'RDP Without NLA',
                'description': 'Remote Desktop allows connections without Network Level Authentication.',
                'recommendation': 'Enable NLA for RDP connections.'
            },
            # AllowUnencryptedPassword
            'AllowUnencryptedTraffic': {
                'dangerous_value': '1',
                'severity': self.HIGH,
                'category': 'Authentication',
                'finding': 'Unencrypted Credentials Allowed',
                'description': 'WinRM/WS-Management allows unencrypted traffic.',
                'recommendation': 'Disable unencrypted traffic for WinRM.'
            },
            # AlwaysInstallElevated
            'AlwaysInstallElevated': {
                'dangerous_value': '1',
                'severity': self.CRITICAL,
                'category': 'Privilege Escalation',
                'finding': 'AlwaysInstallElevated Enabled',
                'description': 'MSI packages always install with elevated privileges - easy privesc.',
                'recommendation': 'Disable AlwaysInstallElevated in both User and Computer policies.'
            },
            # Anonymous SID translation
            'LSAAnonymousNameLookup': {
                'dangerous_value': '1',
                'severity': self.MEDIUM,
                'category': 'Access Control',
                'finding': 'Anonymous SID/Name Translation Allowed',
                'description': 'Anonymous users can translate SIDs to names.',
                'recommendation': 'Disable anonymous SID/name translation.'
            },
        }

        for pol_file in ['Machine/Registry.pol', 'User/Registry.pol']:
            pol_path = gpo_path / pol_file
            scope = 'Machine' if 'Machine' in pol_file else 'User'

            if not pol_path.exists() or pyregpol is None:
                continue

            try:
                rp = pyregpol.RegistryPolicyFile(str(pol_path))
                for entry in rp.entries():
                    value_name = entry.value
                    if value_name in dangerous_settings:
                        setting = dangerous_settings[value_name]
                        entry_data = str(entry.data)

                        # Check for dangerous value(s)
                        dangerous_values = setting.get('dangerous_values', [setting.get('dangerous_value')])

                        if entry_data in dangerous_values:
                            self._add_finding({
                                'gpo_name': gpo['name'],
                                'gpo_guid': gpo['guid'],
                                'severity': setting['severity'],
                                'category': setting['category'],
                                'finding': setting['finding'],
                                'description': setting['description'],
                                'file': str(pol_path),
                                'scope': scope,
                                'registry_key': entry.key,
                                'registry_value': value_name,
                                'current_value': entry_data,
                                'recommendation': setting['recommendation']
                            })
                            self.log.warning(f"[SECURITY] {setting['severity']}: {setting['finding']} in {gpo['name']}")

                    # Check for password policy issues
                    if 'MinimumPasswordLength' in entry.key:
                        try:
                            pwd_len = int(entry.data)
                            if pwd_len < 12:
                                self._add_finding({
                                    'gpo_name': gpo['name'],
                                    'gpo_guid': gpo['guid'],
                                    'severity': self.MEDIUM,
                                    'category': 'Password Policy',
                                    'finding': 'Weak Minimum Password Length',
                                    'description': f'Minimum password length is {pwd_len}, recommended is 12+.',
                                    'file': str(pol_path),
                                    'scope': scope,
                                    'registry_key': entry.key,
                                    'current_value': str(pwd_len),
                                    'recommendation': 'Set minimum password length to 12 or higher.'
                                })
                        except ValueError:
                            pass

            except Exception as e:
                self.log.debug(f"Error parsing {pol_path}: {e}")

    def _check_scripts(self, gpo: Dict, gpo_path: Path) -> None:
        """Check scripts for hardcoded credentials or sensitive data."""
        sensitive_patterns = [
            (r'password\s*[=:]\s*["\'][^"\']+["\']', 'Hardcoded Password', self.HIGH),
            (r'pwd\s*[=:]\s*["\'][^"\']+["\']', 'Hardcoded Password', self.HIGH),
            (r'secret\s*[=:]\s*["\'][^"\']+["\']', 'Hardcoded Secret', self.HIGH),
            (r'api[_-]?key\s*[=:]\s*["\'][^"\']+["\']', 'Hardcoded API Key', self.HIGH),
            (r'token\s*[=:]\s*["\'][^"\']+["\']', 'Hardcoded Token', self.HIGH),
            (r'ConvertTo-SecureString\s+["\'][^"\']+["\']', 'Plaintext SecureString', self.HIGH),
            (r'net\s+user\s+\w+\s+\S+', 'Net User Command with Password', self.CRITICAL),
            (r'-Credential\s+', 'Credential Parameter Usage', self.MEDIUM),
            (r'Invoke-WebRequest.*-Headers.*Authorization', 'API Authorization Header', self.MEDIUM),
            (r'[A-Za-z0-9+/]{40,}={0,2}', 'Potential Base64 Encoded Secret', self.LOW),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key', self.CRITICAL),
            (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'Private Key', self.CRITICAL),
            (r'mysql://[^:]+:[^@]+@', 'Database Connection String', self.HIGH),
            (r'Server=.*Password=', 'Database Connection String', self.HIGH),
        ]

        script_extensions = ['.ps1', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.py']

        for script_dir in ['Machine/Scripts', 'User/Scripts']:
            scripts_path = gpo_path / script_dir
            if not scripts_path.exists():
                continue

            for script_file in scripts_path.rglob('*'):
                if script_file.suffix.lower() not in script_extensions:
                    continue

                try:
                    with open(script_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    for pattern, finding_name, severity in sensitive_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            self._add_finding({
                                'gpo_name': gpo['name'],
                                'gpo_guid': gpo['guid'],
                                'severity': severity,
                                'category': 'Script Security',
                                'finding': finding_name,
                                'description': f'Potentially sensitive data found in script: {script_file.name}',
                                'file': str(script_file),
                                'match_count': len(matches),
                                'recommendation': 'Review script and remove hardcoded credentials. Use secure credential storage.'
                            })
                            self.log.warning(f"[SECURITY] {severity}: {finding_name} in {gpo['name']}/{script_file.name}")
                            break  # Only report once per script per pattern type

                except Exception as e:
                    self.log.debug(f"Error reading script {script_file}: {e}")

    def _check_gpp_preferences(self, gpo: Dict, gpo_path: Path) -> None:
        """Check GPP for insecure configurations."""
        if not HAS_LXML:
            return

        for prefs_base in ['Machine/Preferences', 'User/Preferences']:
            prefs_path = gpo_path / prefs_base
            if not prefs_path.exists():
                continue

            for xml_file in prefs_path.rglob('*.xml'):
                try:
                    tree = etree.parse(str(xml_file))
                    root = tree.getroot()

                    # Check for scheduled tasks with credentials
                    for elem in root.iter():
                        # RunAs in scheduled tasks
                        if elem.tag == 'Task' or 'ScheduledTask' in elem.tag:
                            principals = elem.find('.//Principal') or elem.find('.//Principals/Principal')
                            if principals is not None:
                                run_as = principals.get('userId') or principals.findtext('UserId')
                                if run_as:
                                    self._add_finding({
                                        'gpo_name': gpo['name'],
                                        'gpo_guid': gpo['guid'],
                                        'severity': self.MEDIUM,
                                        'category': 'Scheduled Tasks',
                                        'finding': 'Scheduled Task with Stored Credentials',
                                        'description': f'Scheduled task runs as {run_as} in {xml_file.name}',
                                        'file': str(xml_file),
                                        'recommendation': 'Use managed service accounts or gMSA instead of stored credentials.'
                                    })

                        # Drive Maps with credentials
                        if elem.tag == 'Drive' or 'DriveMap' in str(elem.tag):
                            if elem.get('cpassword') or elem.get('password'):
                                self._add_finding({
                                    'gpo_name': gpo['name'],
                                    'gpo_guid': gpo['guid'],
                                    'severity': self.CRITICAL,
                                    'category': 'Drive Mappings',
                                    'finding': 'Drive Map with Embedded Password',
                                    'description': f'Drive mapping contains embedded credentials in {xml_file.name}',
                                    'file': str(xml_file),
                                    'recommendation': 'Remove embedded passwords from drive mappings.'
                                })

                        # Printers with credentials
                        if 'Printer' in str(elem.tag):
                            if elem.get('cpassword') or elem.get('password'):
                                self._add_finding({
                                    'gpo_name': gpo['name'],
                                    'gpo_guid': gpo['guid'],
                                    'severity': self.HIGH,
                                    'category': 'Printer Configuration',
                                    'finding': 'Printer with Embedded Password',
                                    'description': f'Printer configuration contains embedded credentials in {xml_file.name}',
                                    'file': str(xml_file),
                                    'recommendation': 'Remove embedded passwords from printer configurations.'
                                })

                except Exception as e:
                    self.log.debug(f"Error parsing GPP {xml_file}: {e}")

    def get_summary(self) -> Dict[str, int]:
        """Get summary of security findings."""
        summary = {
            self.CRITICAL: 0,
            self.HIGH: 0,
            self.MEDIUM: 0,
            self.LOW: 0,
            self.INFO: 0
        }

        for finding in self.findings:
            severity = finding.get('severity', self.INFO)
            summary[severity] = summary.get(severity, 0) + 1

        return summary

    def get_risk_score(self) -> int:
        """Calculate overall risk score."""
        score = 0
        for finding in self.findings:
            severity = finding.get('severity', self.INFO)
            score += self.SEVERITY_SCORES.get(severity, 0)
        return score

    def get_findings(self) -> List[Dict]:
        """Return all findings."""
        return self.findings

    def get_findings_by_gpo(self, gpo_guid: str) -> List[Dict]:
        """Return findings for a specific GPO."""
        return self._findings_by_gpo.get(gpo_guid, [])

    def get_top_risky_gpos(self, top_n: int = 10) -> List[Dict]:
        """Get top N GPOs by risk score."""
        gpo_scores = {}
        for finding in self.findings:
            gpo_guid = finding.get('gpo_guid', 'unknown')
            gpo_name = finding.get('gpo_name', 'Unknown')
            severity = finding.get('severity', self.INFO)
            score = self.SEVERITY_SCORES.get(severity, 0)

            if gpo_guid not in gpo_scores:
                gpo_scores[gpo_guid] = {'name': gpo_name, 'guid': gpo_guid, 'score': 0, 'findings': 0}

            gpo_scores[gpo_guid]['score'] += score
            gpo_scores[gpo_guid]['findings'] += 1

        sorted_gpos = sorted(gpo_scores.values(), key=lambda x: x['score'], reverse=True)
        return sorted_gpos[:top_n]
