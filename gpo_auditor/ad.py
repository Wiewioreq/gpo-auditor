"""Active Directory connection handler with fallback and retry logic."""

import ssl
import time
from typing import Optional, List, Tuple

from ldap3 import Server, Connection, ALL, SUBTREE, Tls, SIMPLE
from ldap3.core.exceptions import LDAPException

from .logging_setup import get_logger
from .console import Colors, colored, icon

# =============== GLOBAL FLAGS ===============
ARGS_REQUIRE_LDAPS = False
LAST_CONNECTION_MODE = None


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
