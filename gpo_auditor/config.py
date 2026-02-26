"""Configuration loading, validation, and security lint utilities."""

import os
import argparse
import getpass
import yaml

from .logging_setup import get_logger
from .console import Colors, colored, icon


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
