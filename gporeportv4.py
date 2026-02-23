#!/usr/bin/env python3
"""
🔍 GPO Audit System Pro v3.1
Advanced Group Policy Objects Security Auditing Tool for Active Directory

Features:
- Security vulnerability detection (cpassword, weak settings, SMBv1, NTLMv1, etc.)
- Beautiful HTML dashboard with charts
- Excel reports with formatting
- Email/Teams notifications
- Change tracking between scans
- Progress bars and colored output
- Comprehensive logging and diagnostics
- Orphaned GPO detection
- Password from ENV/prompt support

Author: Pawel
Created for UK Job Interview Portfolio
"""

import os
import json
import csv
import re
import sys
import argparse
import logging
import hashlib
import smtplib
import html
import getpass
import pickle
import base64
from pathlib import Path
from datetime import datetime
from multiprocessing import Pool, cpu_count, freeze_support
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import Optional, Dict, List, Tuple, Any
import pandas as pd
from ldap3 import Server, Connection, ALL, SUBTREE, Tls, SIMPLE
from ldap3.core.exceptions import LDAPException
import yaml
from logging.handlers import RotatingFileHandler
import ssl

try:
    import pyregpol
except ImportError:
    pyregpol = None

try:
    from lxml import etree
    HAS_LXML = True
except ImportError:
    HAS_LXML = False

try:
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    from openpyxl.chart import PieChart, BarChart, Reference
    from openpyxl.chart.label import DataLabelList
    HAS_OPENPYXL_STYLES = True
except ImportError:
    HAS_OPENPYXL_STYLES = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# =============== GLOBAL FLAGS ===============
ARGS_REQUIRE_LDAPS = False
LAST_CONNECTION_MODE = None


# =============== HTML ESCAPE HELPER ===============
def h(text: Any) -> str:
    """Safely escape HTML entities."""
    if text is None:
        return ''
    return html.escape(str(text))


# =============== CONSOLE COLORS ===============
class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'
    
    _supports_color = None
    _supports_unicode = None
    
    @classmethod
    def supports_color(cls) -> bool:
        """Check if terminal supports colors."""
        if cls._supports_color is not None:
            return cls._supports_color
        
        # Check for NO_COLOR env variable
        if os.environ.get('NO_COLOR'):
            cls._supports_color = False
            return False
        
        # Check for FORCE_COLOR env variable
        if os.environ.get('FORCE_COLOR'):
            cls._supports_color = True
            return True
        
        if sys.platform == 'win32':
            try:
                import ctypes
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
                cls._supports_color = True
            except:
                cls._supports_color = False
        else:
            cls._supports_color = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        
        return cls._supports_color
    
    @classmethod
    def supports_unicode(cls) -> bool:
        """Check if terminal supports Unicode."""
        if cls._supports_unicode is not None:
            return cls._supports_unicode
        
        try:
            # Try to encode some unicode characters
            '🔍📊✅❌'.encode(sys.stdout.encoding or 'utf-8')
            cls._supports_unicode = True
        except (UnicodeEncodeError, LookupError):
            cls._supports_unicode = False
        
        return cls._supports_unicode


def colored(text: str, color: str) -> str:
    """Return colored text if supported."""
    if Colors.supports_color():
        return f"{color}{text}{Colors.END}"
    return text


def icon(unicode_icon: str, ascii_fallback: str = '*') -> str:
    """Return unicode icon or ASCII fallback."""
    if Colors.supports_unicode():
        return unicode_icon
    return ascii_fallback


def print_banner():
    """Print application banner."""
    if Colors.supports_unicode():
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗ ██████╗  ██████╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗        ║
║  ██╔════╝ ██╔══██╗██╔═══██╗    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝        ║
║  ██║  ███╗██████╔╝██║   ██║    ███████║██║   ██║██║  ██║██║   ██║           ║
║  ██║   ██║██╔═══╝ ██║   ██║    ██╔══██║██║   ██║██║  ██║██║   ██║           ║
║  ╚██████╔╝██║     ╚██████╔╝    ██║  ██║╚██████╔╝██████╔╝██║   ██║           ║
║   ╚═════╝ ╚═╝      ╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝           ║
║                                                                              ║
║                    🔍 Security Audit System Pro v3.1                         ║
║                    Group Policy Objects Analyzer                             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    else:
        banner = """
================================================================================
                         GPO AUDIT SYSTEM PRO v3.1
                      Group Policy Objects Analyzer
================================================================================
"""
    print(colored(banner, Colors.CYAN))


class ProgressBar:
    """Simple progress bar for console output."""
    
    def __init__(self, total: int, prefix: str = 'Progress', length: int = 40):
        self.total = max(total, 1)  # Prevent division by zero
        self.prefix = prefix
        self.length = length
        self.current = 0
        
    def update(self, current: Optional[int] = None, suffix: str = ''):
        if current is not None:
            self.current = current
        else:
            self.current += 1
        
        percent = min(self.current / self.total, 1.0)
        filled = int(self.length * percent)
        
        if Colors.supports_unicode():
            bar = '█' * filled + '░' * (self.length - filled)
        else:
            bar = '#' * filled + '-' * (self.length - filled)
        
        line = f'\r{self.prefix} |{bar}| {self.current}/{self.total} ({percent:.0%}) {suffix[:30]}'
        
        if Colors.supports_color():
            if percent < 0.5:
                line = colored(line, Colors.WARNING)
            else:
                line = colored(line, Colors.GREEN)
        
        print(line, end='', flush=True)
        
        if self.current >= self.total:
            print()
    
    def finish(self):
        self.update(self.total)


# =============== LOGGING ===============
logger = None

def setup_logging(log_dir: str = 'logs', log_level: str = 'INFO', 
                  console_level: str = 'WARNING', log_to_file: bool = True) -> logging.Logger:
    """Configure logging to console and file with rotation."""
    global logger
    
    if logger is not None:
        return logger
    
    if log_to_file and not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    logger = logging.getLogger('gpo_audit')
    logger.setLevel(logging.DEBUG)
    logger.handlers = []
    
    # Formatter
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    simple_formatter = logging.Formatter('%(levelname)s: %(message)s')
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, console_level.upper(), logging.WARNING))
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)
    
    # File handler
    if log_to_file:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, f'gpo_audit_{timestamp}.log'),
            maxBytes=5*1024*1024,
            backupCount=10,
            encoding='utf-8'
        )
        file_handler.setLevel(getattr(logging, log_level.upper(), logging.DEBUG))
        file_handler.setFormatter(detailed_formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger() -> logging.Logger:
    """Return logger instance, initialize if needed."""
    global logger
    if logger is None:
        logger = setup_logging()
    return logger


# =============== CONFIGURATION ===============
class ConfigError(Exception):
    """Configuration error exception."""
    pass


def get_password_from_env_or_prompt(config: dict) -> str:
    """Get password from config, environment variable, or prompt."""
    ad_config = config.get('ad', {})
    password = ad_config.get('password', '')
    
    # Check if password is an env variable reference
    if password.startswith('${') and password.endswith('}'):
        env_var = password[2:-1]
        password = os.environ.get(env_var, '')
        if not password:
            get_logger().warning(f"Environment variable {env_var} not set")
    
    # Check for ENV: prefix
    if password.startswith('ENV:'):
        env_var = password[4:]
        password = os.environ.get(env_var, '')
        if not password:
            get_logger().warning(f"Environment variable {env_var} not set")
    
    # Check for PROMPT keyword
    if password.upper() == 'PROMPT' or not password:
        try:
            password = getpass.getpass(f"Enter password for {ad_config.get('user', 'AD user')}: ")
        except Exception:
            password = ''
    
    return password


def load_config(config_path: str = 'config.yaml') -> dict:
    """Load configuration from YAML file."""
    log = get_logger()
    
    if not os.path.exists(config_path):
        log.error(f"Configuration file not found: {config_path}")
        raise ConfigError(f"{icon('❌', 'X')} Configuration file not found: {config_path}")
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        log.info(f"Configuration loaded from: {config_path}")
    except yaml.YAMLError as e:
        log.error(f"YAML parsing error: {e}")
        raise ConfigError(f"{icon('❌', 'X')} YAML parsing error: {e}")
    except Exception as e:
        log.error(f"Error reading config file: {e}")
        raise ConfigError(f"{icon('❌', 'X')} Error reading config file: {e}")
    
    return config


def validate_config(config: dict) -> bool:
    """Validate configuration structure."""
    log = get_logger()
    errors = []
    warnings = []
    
    # Validate AD section
    if 'ad' not in config:
        errors.append("Missing 'ad' section in configuration")
    else:
        ad = config['ad']
        required_keys = ['server', 'user', 'base_dn', 'ldap_ou_base']
        for key in required_keys:
            if key not in ad or not ad[key]:
                errors.append(f"Missing or empty 'ad.{key}'")
        
        # Password can be empty if using ENV or PROMPT
        if 'password' not in ad:
            warnings.append("'ad.password' not set - will prompt for password")
    
    # Validate paths section
    if 'paths' not in config:
        errors.append("Missing 'paths' section in configuration")
    else:
        paths = config['paths']
        
        # Validate sysvol path
        sysvol = paths.get('sysvol', '')
        if not sysvol:
            errors.append("Missing or empty 'paths.sysvol'")
        elif not os.path.exists(sysvol):
            warnings.append(f"SYSVOL path does not exist: {sysvol}")
        elif not os.path.isdir(sysvol):
            errors.append(f"SYSVOL path is not a directory: {sysvol}")
        
        # Validate output_dir
        output_dir = paths.get('output_dir', '')
        if not output_dir:
            errors.append("Missing or empty 'paths.output_dir'")
        else:
            # Check if writable
            try:
                if os.path.exists(output_dir):
                    test_file = os.path.join(output_dir, '.write_test')
                    with open(test_file, 'w') as f:
                        f.write('test')
                    os.remove(test_file)
            except PermissionError:
                errors.append(f"Output directory is not writable: {output_dir}")
            except Exception:
                pass  # Directory doesn't exist yet, will be created
    
    # Validate options section
    if 'options' not in config:
        warnings.append("Missing 'options' section, using defaults")
    
    # Validate logging section
    logging_config = config.get('logging', {})
    valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    if logging_config.get('level', 'INFO').upper() not in valid_levels:
        warnings.append(f"Invalid logging level, using INFO")
    if logging_config.get('console_level', 'WARNING').upper() not in valid_levels:
        warnings.append(f"Invalid console logging level, using WARNING")
    
    # Print errors and warnings
    for error in errors:
        print(colored(f"  {icon('❌', 'X')} {error}", Colors.FAIL))
        log.error(error)
    
    for warning in warnings:
        print(colored(f"  {icon('⚠️', '!')} {warning}", Colors.WARNING))
        log.warning(warning)
    
    if errors:
        raise ConfigError("Configuration contains critical errors!")
    
    print(colored(f"  {icon('✅', 'OK')} Configuration validated successfully!", Colors.GREEN))
    log.info("Configuration validated successfully!")
    return True


def security_lint(config: dict, args: argparse.Namespace) -> None:
    """Check for security concerns in configuration."""
    ad = config.get('ad', {})
    insecure_ldap = bool(ad.get('allow_insecure_ldap', True))
    tls_cfg = ad.get('tls', {})
    cert_validate = tls_cfg.get('validate', False)
    
    if not getattr(args, 'accept_insecure_ldap', False):
        if not cert_validate:
            print(colored(f"  {icon('⚠️', '!')} TLS certificate validation is DISABLED (CERT_NONE).", Colors.WARNING))
            print(colored("     This is OK for lab/POC, but risky in production.", Colors.DIM))
            print(colored("     Tip: add ad.tls.validate: true in config.yaml", Colors.CYAN))
        
        if insecure_ldap:
            print(colored(f"  {icon('⚠️', '!')} Plain LDAP:389 is ALLOWED as a fallback.", Colors.WARNING))
            print(colored("     Tip: set ad.allow_insecure_ldap: false when infra is ready.", Colors.CYAN))
    
    if getattr(args, 'require_ldaps', False):
        print(colored(f"  {icon('🔒', '[LOCK]')} --require-ldaps enabled: tool will FAIL if secure bind is not possible.", Colors.BOLD))


def ensure_output_dir(output_dir: str) -> str:
    """Create output directory if it doesn't exist."""
    log = get_logger()
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            log.info(f"Created directory: {output_dir}")
            print(colored(f"  {icon('📁', '[DIR]')} Created directory: {output_dir}", Colors.CYAN))
        except PermissionError:
            raise ConfigError(f"Cannot create output directory (permission denied): {output_dir}")
        except Exception as e:
            raise ConfigError(f"Cannot create output directory: {e}")
    return output_dir


# =============== AD CONNECTION CLASS ===============
class ADConnection:
    """
    Robust AD connection handler with automatic fallback and retry logic.
    Supports: ldaps://, ldap://, host, host:port
    Fallback order: LDAPS:636 -> LDAP+StartTLS:389 -> LDAP:389 (if allowed)
    """

    def __init__(self, ad_config: dict):
        self.ad_config = ad_config
        self.connection: Optional[Connection] = None
        self.server: Optional[Server] = None
        self._last_success: Optional[dict] = None
        self._last_mode: Optional[str] = None  # 'ldaps' | 'starttls' | 'ldap_insecure'
        self._connect_timeout = ad_config.get('connect_timeout', 30)
        self._receive_timeout = ad_config.get('receive_timeout', 30)
        self._retry_count = ad_config.get('retry_count', 3)
        self._retry_delay = ad_config.get('retry_delay', 2)
        self._page_size = ad_config.get('page_size', 1000)

    def _normalize_host(self, host: str) -> str:
        """Normalize hostname."""
        if host.strip().lower() == "localhost":
            return "127.0.0.1"
        return host.strip()

    def _parse_server(self) -> Tuple[str, str, int, bool]:
        """Parse server URL into components."""
        raw = (self.ad_config.get("server") or "").strip()
        if not raw:
            raise ValueError("Missing ad.server in config.yaml")

        lower = raw.lower()
        use_ssl_from_url = lower.startswith("ldaps://")

        hostport = raw.replace("ldaps://", "").replace("ldap://", "")
        host = hostport
        port = 636 if use_ssl_from_url else 389

        if ":" in hostport:
            host, port_str = hostport.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                pass

        host = self._normalize_host(host)
        return raw, host, port, use_ssl_from_url

    def _tls(self) -> Tls:
        """Create TLS configuration."""
        tls_config = self.ad_config.get('tls', {})
        validate = ssl.CERT_REQUIRED if tls_config.get('validate', False) else ssl.CERT_NONE
        ca_file = tls_config.get('ca_file')
        
        return Tls(
            validate=validate, 
            version=ssl.PROTOCOL_TLSv1_2,
            ca_certs_file=ca_file
        )

    def _attempt_connect(self, *, host: str, port: int, use_ssl: bool, 
                         start_tls: bool, label: str, retry: int = 0) -> bool:
        """Attempt to connect with retry logic."""
        log = get_logger()
        user = self.ad_config["user"]
        password = self.ad_config.get("_resolved_password", self.ad_config.get("password", ""))

        try:
            self.server = Server(
                host,
                get_info=ALL,
                use_ssl=use_ssl,
                port=port,
                tls=self._tls(),
                connect_timeout=self._connect_timeout
            )

            self.connection = Connection(
                self.server,
                user=user,
                password=password,
                auto_bind=False,
                receive_timeout=self._receive_timeout,
                authentication=SIMPLE
            )

            log.info(f"[AD_CONNECT_ATTEMPT] Attempting: {label} (retry {retry})")
            print(colored(f"  {icon('🔌', '[CONN]')} Attempting: {label}", Colors.CYAN))

            self.connection.open()
            log.debug(f"open() done; closed={getattr(self.connection, 'closed', None)}")

            if start_tls:
                log.info("[AD_STARTTLS] Attempting StartTLS...")
                self.connection.start_tls()
                log.info("[AD_STARTTLS_OK] StartTLS successful")

            if not self.connection.bind():
                raise LDAPException(f"bind() failed: {self.connection.result}")

            # Set connection mode
            if use_ssl and not start_tls:
                self._last_mode = 'ldaps'
            elif (not use_ssl) and start_tls:
                self._last_mode = 'starttls'
            else:
                self._last_mode = 'ldap_insecure'

            log.info(f"[AD_CONNECTED] Connected: {label} (mode: {self._last_mode})")
            
            # Print connection status with appropriate message
            if self._last_mode == 'ldap_insecure':
                print(colored(f"  {icon('⚠️', '!')} Connected over INSECURE LDAP:389 (no TLS).", Colors.WARNING))
            elif self._last_mode == 'starttls':
                print(colored(f"  {icon('🔐', '[TLS]')} Connected with LDAP+StartTLS (secured).", Colors.GREEN))
            elif self._last_mode == 'ldaps':
                print(colored(f"  {icon('🔐', '[TLS]')} Connected with LDAPS:636 (secured).", Colors.GREEN))
            
            return True
            
        except Exception as e:
            log.warning(f"[AD_CONNECT_FAILED] {label} -> {e}")
            
            # Retry logic for transient errors
            transient_errors = ['timeout', 'connection refused', 'network', 'socket']
            if any(err in str(e).lower() for err in transient_errors):
                if retry < self._retry_count:
                    log.info(f"[AD_RETRY] Retrying in {self._retry_delay}s... ({retry + 1}/{self._retry_count})")
                    import time
                    time.sleep(self._retry_delay)
                    return self._attempt_connect(
                        host=host, port=port, use_ssl=use_ssl, 
                        start_tls=start_tls, label=label, retry=retry + 1
                    )
            
            raise

    def connect(self) -> bool:
        """Connect to AD with fallback methods."""
        global ARGS_REQUIRE_LDAPS, LAST_CONNECTION_MODE
        log = get_logger()
        
        try:
            raw, host, port_from_cfg, use_ssl_from_url = self._parse_server()
            allow_insecure = bool(self.ad_config.get("allow_insecure_ldap", True))

            attempts = []

            # Use cached successful method first
            if self._last_success:
                attempts.append({**self._last_success, "label": f"{self._last_success['label']} (cached)"})

            if use_ssl_from_url:
                attempts.append({
                    "host": host, "port": port_from_cfg, "use_ssl": True, 
                    "start_tls": False, "label": f"LDAPS {host}:{port_from_cfg}"
                })
            else:
                attempts.append({"host": host, "port": 636, "use_ssl": True, "start_tls": False, "label": f"LDAPS {host}:636"})
                attempts.append({"host": host, "port": 389, "use_ssl": False, "start_tls": True, "label": f"LDAP+StartTLS {host}:389"})
                if allow_insecure:
                    attempts.append({"host": host, "port": 389, "use_ssl": False, "start_tls": False, "label": f"LDAP (insecure) {host}:389"})

            # Deduplicate attempts
            seen = set()
            uniq = []
            for a in attempts:
                key = (a["host"], a["port"], a["use_ssl"], a["start_tls"])
                if key not in seen:
                    seen.add(key)
                    uniq.append(a)
            attempts = uniq

            last_error = None

            for a in attempts:
                try:
                    if self._attempt_connect(**a):
                        self._last_success = {k: a[k] for k in ["host", "port", "use_ssl", "start_tls", "label"]}
                        LAST_CONNECTION_MODE = self._last_mode
                        
                        # Check --require-ldaps flag
                        if ARGS_REQUIRE_LDAPS and self._last_mode not in ('ldaps', 'starttls'):
                            print(colored(f"  {icon('❌', 'X')} --require-ldaps: secure channel not established.", Colors.FAIL))
                            log.error("--require-ldaps flag set but connection is insecure")
                            return False
                        
                        return True
                except Exception as e:
                    last_error = e
                    print(colored(f"  {icon('⚠️', '!')} Failed: {a['label']}", Colors.WARNING))
                    try:
                        if self.connection:
                            self.connection.unbind()
                    except:
                        pass
                    self.connection = None
                    self.server = None

            log.error(f"[AD_CONNECT_ALL_FAILED] Last error: {last_error}")
            print(colored(f"  {icon('❌', 'X')} All connection methods failed", Colors.FAIL))
            return False

        except Exception as e:
            log.exception("[AD_CONNECT_ERROR] AD connection error")
            return False

    def disconnect(self) -> None:
        """Disconnect from AD."""
        log = get_logger()
        try:
            if self.connection:
                self.connection.unbind()
                log.info("[AD_DISCONNECTED] Disconnected from AD")
        except Exception as e:
            log.debug(f"[AD_DISCONNECT_ERROR] {e}")

    def search(self, search_base: str, search_filter: str, 
               attributes: Optional[List[str]] = None) -> List:
        """Search AD with paged results for large environments."""
        log = get_logger()
        try:
            if not self.connection or not self.connection.bound:
                log.warning("[AD_RECONNECT] Connection lost, reconnecting...")
                if not self.connect():
                    return []

            # Use paged search for large results
            all_entries = []
            cookie = None
            
            while True:
                self.connection.search(
                    search_base,
                    search_filter,
                    search_scope=SUBTREE,
                    attributes=attributes or ['*'],
                    paged_size=self._page_size,
                    paged_cookie=cookie
                )
                
                all_entries.extend(self.connection.entries)
                
                # Get cookie for next page
                cookie = self.connection.result.get('controls', {}).get(
                    '1.2.840.113556.1.4.319', {}
                ).get('value', {}).get('cookie')
                
                if not cookie:
                    break
            
            log.debug(f"Search: {search_filter} - found {len(all_entries)} results")
            return all_entries

        except Exception as e:
            log.exception(f"[AD_SEARCH_ERROR] Search error: {search_filter}")
            return []

    @property
    def connection_mode(self) -> Optional[str]:
        """Return the connection mode used."""
        return self._last_mode


# =============== SECURITY ANALYZER ===============
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


# =============== GPO FUNCTIONS ===============
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


def parse_registry_pol(pol_path: str, scope: str = 'Unknown') -> List[Dict]:
    """Parse Registry.pol file from GPO with scope information."""
    log = get_logger()
    entries = []
    
    if not os.path.exists(pol_path):
        return entries
    
    if pyregpol is None:
        log.warning(f"pyregpol not installed, skipping: {pol_path}")
        return entries
    
    try:
        rp = pyregpol.RegistryPolicyFile(pol_path)
        for elem in rp.entries():
            entries.append({
                'key': elem.key,
                'value': elem.value,
                'type': str(elem.type),
                'data': str(elem.data),
                'scope': scope,
                'pol_file': pol_path,
            })
        log.debug(f"Parsed {len(entries)} entries from {pol_path}")
    except Exception as e:
        log.error(f"Error parsing {pol_path}: {e}")
    
    return entries


def parse_gpp_preferences(preferences_xmls: List[str]) -> List[Dict]:
    """Parse Group Policy Preferences XML files with full paths."""
    log = get_logger()
    prefs = []
    
    if not HAS_LXML:
        return prefs
    
    for xml_path in preferences_xmls:
        try:
            tree = etree.parse(xml_path)
            root_el = tree.getroot()
            
            # Handle namespaces
            nsmap = root_el.nsmap.copy()
            if None in nsmap:
                nsmap['default'] = nsmap.pop(None)
            
            for elem in root_el:
                attrs = dict(elem.attrib)
                attrs_json = json.dumps(attrs)
                # Truncate very long JSON
                if len(attrs_json) > 1000:
                    attrs_json = attrs_json[:997] + '...'
                
                pref = {
                    'file': os.path.basename(xml_path),
                    'full_path': xml_path,
                    'element': elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag,
                    'action': attrs.get('action', attrs.get('clsid', '')),
                    'attributes': attrs_json
                }
                
                targeting = elem.find('Properties') or elem.find('.//Properties')
                if targeting is not None:
                    target_attrs = json.dumps(dict(targeting.attrib))
                    if len(target_attrs) > 500:
                        target_attrs = target_attrs[:497] + '...'
                    pref['targeting'] = target_attrs
                
                prefs.append(pref)
            log.debug(f"Parsed preferences from {xml_path}")
        except etree.XMLSyntaxError as e:
            log.warning(f"XML syntax error in {xml_path}: {e}")
        except Exception as e:
            log.error(f"Error parsing GPP {xml_path}: {e}")
    
    return prefs


def parse_scripts(scripts_dict: Dict[str, List[str]]) -> List[Dict]:
    """Extract script information."""
    lst = []
    for scr_type, files in scripts_dict.items():
        for i, fpath in enumerate(files):
            lst.append({
                'type': scr_type, 
                'path': fpath, 
                'name': os.path.basename(fpath), 
                'order': i + 1
            })
    return lst


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


# =============== CHANGE TRACKING ===============
def load_previous_scan(output_dir: str) -> Optional[List[Dict]]:
    """Load the most recent previous scan for comparison."""
    log = get_logger()
    scan_files = list(Path(output_dir).glob('gpos_*.json'))
    
    if len(scan_files) < 2:
        return None
    
    # Sort by modification time
    scan_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    
    try:
        with open(scan_files[1], 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        log.error(f"Error loading previous scan: {e}")
        return None


def save_scan_cache(data: Dict, output_dir: str) -> None:
    """Save scan results to cache for faster subsequent runs."""
    log = get_logger()
    cache_file = os.path.join(output_dir, '.gpo_cache.pkl')
    
    try:
        cache_data = {
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        with open(cache_file, 'wb') as f:
            pickle.dump(cache_data, f)
        log.debug(f"Cache saved to {cache_file}")
    except Exception as e:
        log.debug(f"Could not save cache: {e}")


def load_scan_cache(output_dir: str, max_age_hours: int = 24) -> Optional[Dict]:
    """Load scan cache if not too old."""
    log = get_logger()
    cache_file = os.path.join(output_dir, '.gpo_cache.pkl')
    
    if not os.path.exists(cache_file):
        return None
    
    try:
        with open(cache_file, 'rb') as f:
            cache_data = pickle.load(f)
        
        cache_time = datetime.fromisoformat(cache_data['timestamp'])
        age = datetime.now() - cache_time
        
        if age.total_seconds() > max_age_hours * 3600:
            log.debug("Cache expired")
            return None
        
        log.info(f"Using cached data from {cache_time}")
        return cache_data['data']
        
    except Exception as e:
        log.debug(f"Could not load cache: {e}")
        return None


def compare_scans(current_gpos: List[Dict], previous_gpos: List[Dict]) -> Optional[Dict]:
    """Compare current scan with previous scan to detect changes."""
    if not previous_gpos:
        return None
    
    changes = {
        'new_gpos': [],
        'deleted_gpos': [],
        'modified_gpos': [],
        'timestamp': datetime.now().isoformat()
    }
    
    current_guids = {g['guid'].upper(): g for g in current_gpos}
    previous_guids = {g['guid'].upper(): g for g in previous_gpos}
    
    # New GPOs
    for guid in set(current_guids.keys()) - set(previous_guids.keys()):
        changes['new_gpos'].append(current_guids[guid])
    
    # Deleted GPOs
    for guid in set(previous_guids.keys()) - set(current_guids.keys()):
        changes['deleted_gpos'].append(previous_guids[guid])
    
    # Modified GPOs
    for guid in set(current_guids.keys()) & set(previous_guids.keys()):
        curr = current_guids[guid]
        prev = previous_guids[guid]
        
        if curr['version'] != prev['version'] or curr['whenChanged'] != prev['whenChanged']:
            changes['modified_gpos'].append({
                'name': curr['name'],
                'guid': guid,
                'old_version': prev['version'],
                'new_version': curr['version'],
                'old_modified': prev['whenChanged'],
                'new_modified': curr['whenChanged']
            })
    
    return changes


# =============== REPORTS ===============
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
               unused: List[Dict], security_findings: List[Dict], path: str) -> None:
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
                     top_risky_gpos: List[Dict], path: str) -> None:
    """Generate interactive HTML dashboard with charts, security findings, and timeline."""
    log = get_logger()
    
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

    html = f"""<!DOCTYPE html>
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
            html += f'''<tr class="{row_class}">
                <td><span class="badge {badge_class}">{h(severity)}</span></td>
                <td><strong>{h(f.get('gpo_name', 'N/A'))}</strong></td>
                <td>{h(f.get('category', 'N/A'))}</td>
                <td>{h(f.get('finding', 'N/A'))}</td>
                <td>{rec}...</td>
            </tr>'''
    else:
        html += '<tr><td colspan="5"><div class="empty-state"><div class="icon">✅</div>No security issues found!</div></td></tr>'
    
    html += """</table></div></div></div>
            
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
        
        html += f'''<tr class="{row_class}">
            <td><strong>{h(g['name'])}</strong></td>
            <td><code>{h(g['guid'][:15])}...</code></td>
            <td>{g['version']} (U:{g['user_version']} C:{g['comp_version']})</td>
            <td>{h(g['whenChanged'])}</td>
            <td>{size}</td>
            <td>{status_badge}</td>
        </tr>'''
    
    html += """</table></div></div></div>
            
            <div id="issues" class="tab-content">
                <div class="section">
                    <h2 class="section-title">⚠️ Version Inconsistencies</h2>
                    <div class="table-wrapper">
                        <table>
                            <tr><th>GPO Name</th><th>GUID</th><th>User Version</th><th>Computer Version</th></tr>"""
    
    if inconsistencies:
        for g in inconsistencies:
            html += f'<tr class="severity-medium"><td><strong>{h(g["name"])}</strong></td><td><code>{h(g["guid"][:20])}...</code></td><td>{g["user_version"]}</td><td>{g["comp_version"]}</td></tr>'
    else:
        html += '<tr><td colspan="4"><div class="empty-state"><div class="icon">✅</div>No inconsistencies found</div></td></tr>'
    
    html += """</table></div></div>
                <div class="section">
                    <h2 class="section-title">🚫 Unused GPOs</h2>
                    <div class="table-wrapper">
                        <table>
                            <tr><th>GPO Name</th><th>GUID</th><th>Version</th><th>Last Modified</th></tr>"""
    
    if unused:
        for g in unused:
            html += f'<tr><td><strong>{h(g["name"])}</strong></td><td><code>{h(g["guid"][:20])}...</code></td><td>{g["version"]}</td><td>{h(g["whenChanged"])}</td></tr>'
    else:
        html += '<tr><td colspan="4"><div class="empty-state"><div class="icon">✅</div>All GPOs are linked</div></td></tr>'
    
    html += """</table></div></div></div>
            
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
        html += f'<tr><td><span class="badge badge-info">{scope}</span></td><td><code>{key}</code></td><td><strong>{h(r.get("value", ""))}</strong></td><td>{h(r.get("type", ""))}</td><td>{data}</td></tr>'
    
    if len(registry) > 200:
        html += f'<tr><td colspan="5" style="text-align:center;padding:20px;color:#666;">Showing 200 of {len(registry)} entries</td></tr>'
    if not registry:
        html += '<tr><td colspan="5"><div class="empty-state"><div class="icon">📭</div>No registry entries found</div></td></tr>'
    
    html += """</table></div></div></div>
            
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
        html += f'''<tr>
            <td><span class="badge" style="background:{color};color:white;">{h(s.get('type', ''))}</span></td>
            <td><strong>{h(s.get('name', ''))}</strong></td>
            <td>{s.get('order', '')}</td>
            <td><code>{path_display}</code></td>
        </tr>'''
    
    if not scripts:
        html += '<tr><td colspan="4"><div class="empty-state"><div class="icon">📭</div>No scripts found</div></td></tr>'
    
    html += f"""</table></div></div></div>
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
        f.write(html)
    log.info(f"HTML report saved: {path}")
    print(colored(f"  {icon('✅', 'OK')} HTML: {path}", Colors.GREEN))


# =============== NOTIFICATIONS ===============
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


# =============== CLI ===============
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


# =============== MAIN ===============
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

    notif_cfg = config.get("notifications", {})

    # Jeśli powiadomienia globalnie wyłączone → nic nie robimy
    if not notif_cfg.get("enabled", False):
        return args

    # Automatyczny email
    if notif_cfg.get("auto_email_on_double_click", False):
        args.notify = True
        args.email_only = True

    # Automatyczny Teams
    if notif_cfg.get("auto_teams_on_double_click", False):
        args.notify = True
        args.teams_only = True

    return args

def main():
    """Main entry point."""
    global ARGS_REQUIRE_LDAPS, LAST_CONNECTION_MODE
    # Parse arguments first
    args = parse_arguments()

    # Load configuration (rzeczywisty plik z --config)
    print(colored(f"\n{icon('📋', '[CFG]')} Loading Configuration...", Colors.BOLD))
    config = load_config(args.config)

    # Ustal auto‑powiadomienia po wczytaniu WŁAŚCIWEGO config.yaml
    args = apply_auto_notifications(config, args)
    
    # Set global flags
    ARGS_REQUIRE_LDAPS = getattr(args, 'require_ldaps', False)
    
    # Initialize logging based on args
    log_level = 'DEBUG' if args.debug else 'INFO'
    console_level = 'DEBUG' if args.debug else ('WARNING' if args.quiet else 'INFO')
    setup_logging(log_level=log_level, console_level=console_level)
    log = get_logger()
    
    try:
        # Print banner
        if not args.quiet:
            print_banner()
        
        # Load configuration
        print(colored(f"\n{icon('📋', '[CFG]')} Loading Configuration...", Colors.BOLD))
        
        
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
                      os.path.join(output_dir, f'gpo_audit_{timestamp}.xlsx'))
        
        html_path = None
        if options.get('generate_html', True):
            html_path = os.path.join(output_dir, f'gpo_report_{timestamp}.html')
            save_html_report(gpo_list, registry_entries, gpprefs, scripts,
                           inconsistencies, unused, security_findings, changes,
                           blocked_inheritance, connection_mode, top_risky_gpos, html_path)
        
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
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    freeze_support()
    main()