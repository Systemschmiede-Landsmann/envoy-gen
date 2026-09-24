#!/usr/bin/env python3
"""
Envoy-Gen Preflight Check
Verifies that all requirements are met before attempting to issue
Let's Encrypt certificates.

Checks performed:
  - Required system binaries present (certbot, python3, systemctl)
  - Required Python modules available (jinja2, yaml)
  - config.yaml readable and valid
  - Envoy service exists and is running
  - Port 80 is bound and listening
  - Port 443 is bound and listening
  - Webroot directory is writable
  - cert_dir is writable
  - Log directory is writable (or creatable)
  - All enabled host domains resolve to this machine's public IP
  - All enabled host domains are reachable on port 80 from localhost
  - Certbot deploy hook installed
"""

import os
import sys
import shutil
import socket
import subprocess
import argparse
import urllib.request
import urllib.error
import yaml


# ============================================================
# Result tracking
# ============================================================

PASS  = "PASS"
FAIL  = "FAIL"
WARN  = "WARN"
INFO  = "INFO"

results = []


def record(status: str, category: str, message: str) -> None:
    results.append((status, category, message))
    icon = {"PASS": "[ OK ]", "FAIL": "[FAIL]", "WARN": "[WARN]", "INFO": "[INFO]"}[status]
    print(f"{icon} [{category}] {message}")


# ============================================================
# Helpers
# ============================================================

def load_config(path: str) -> dict | None:
    """Load config.yaml, return None on failure."""
    if not os.path.exists(path):
        record(FAIL, "config", f"Config file not found: {path}")
        return None
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        record(FAIL, "config", f"Config file is not valid YAML: {e}")
        return None


def get_public_ip() -> str | None:
    """Try to determine the public IP of this machine."""
    for url in [
        "https://api4.my-ip.io/ip",
        "https://ipv4.icanhazip.com",
    ]:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                return resp.read().decode().strip()
        except Exception:
            continue
    return None


def resolve_domain(domain: str) -> list[str]:
    """Resolve a domain to its IP addresses."""
    try:
        infos = socket.getaddrinfo(domain, None)
        return list({i[4][0] for i in infos})
    except socket.gaierror:
        return []


def port_listening(port: int) -> bool:
    """Check if a local port is bound and listening."""
    result = subprocess.run(
        ['ss', '-tlnp', f'sport = :{port}'],
        capture_output=True, text=True
    )
    return str(port) in result.stdout


def check_http_challenge_route(domain: str) -> bool:
    """
    Check if the ACME challenge route is reachable on port 80.
    Expects a non-connection-refused response for /.well-known/acme-challenge/test
    (any HTTP status except connection errors is acceptable).
    """
    url = f"http://{domain}/.well-known/acme-challenge/preflight-test"
    try:
        req = urllib.request.Request(url, headers={"Host": domain})
        urllib.request.urlopen(req, timeout=5)
        return True
    except urllib.error.HTTPError:
        # Any HTTP error (404, 500 etc.) means the route is reachable
        return True
    except Exception:
        return False


def dir_writable(path: str) -> bool:
    """Check if a directory exists and is writable, or can be created."""
    if os.path.exists(path):
        return os.access(path, os.W_OK)
    try:
        os.makedirs(path, exist_ok=True)
        return True
    except PermissionError:
        return False


# ============================================================
# Check functions
# ============================================================

def check_binaries() -> None:
    """Check that required system binaries are available."""
    required = {
        'certbot':  'apt install certbot',
        'python3':  'apt install python3',
        'systemctl':'(systemd required)',
        'ss':       'apt install iproute2',
    }
    for binary, hint in required.items():
        if shutil.which(binary):
            record(PASS, "binaries", f"{binary} found at: {shutil.which(binary)}")
        else:
            record(FAIL, "binaries", f"{binary} not found — install with: {hint}")


def check_python_modules() -> None:
    """Check that required Python modules are importable."""
    modules = {
        'jinja2': 'pip3 install jinja2',
        'yaml':   'pip3 install pyyaml',
    }
    for module, hint in modules.items():
        try:
            __import__(module)
            record(PASS, "python", f"Module '{module}' available")
        except ImportError:
            record(FAIL, "python", f"Module '{module}' not found — install with: {hint}")


def check_config(cfg: dict) -> None:
    """Validate required fields in config.yaml."""
    required_keys = {
        'envoy.log_dir':            lambda c: c.get('envoy', {}).get('log_dir'),
        'envoy.service_user':       lambda c: c.get('envoy', {}).get('service_user'),
        'envoy.config_output':      lambda c: c.get('envoy', {}).get('config_output'),
        'envoy.restart_command':    lambda c: c.get('envoy', {}).get('restart_command'),
        'envoy.upstream.address':   lambda c: c.get('envoy', {}).get('upstream', {}).get('address'),
        'envoy.upstream.port':      lambda c: c.get('envoy', {}).get('upstream', {}).get('port'),
        'letsencrypt.enabled':      lambda c: c.get('letsencrypt', {}).get('enabled') is not None,
        'letsencrypt.email':        lambda c: c.get('letsencrypt', {}).get('email'),
        'letsencrypt.webroot_dir':  lambda c: c.get('letsencrypt', {}).get('webroot_dir'),
        'letsencrypt.acme_port':    lambda c: c.get('letsencrypt', {}).get('acme_port'),
        'certificates.mode':        lambda c: c.get('certificates', {}).get('mode'),
        'certificates.cert_dir':    lambda c: c.get('certificates', {}).get('cert_dir'),
    }
    for key, getter in required_keys.items():
        if getter(cfg):
            record(PASS, "config", f"Key present: {key}")
        else:
            record(FAIL, "config", f"Missing or empty: {key}")

    # Validate restart_command value
    restart_cmd = cfg.get('envoy', {}).get('restart_command', '')
    if restart_cmd in ('restart', 'reload'):
        record(PASS, "config", f"restart_command is valid: '{restart_cmd}'")
    else:
        record(FAIL, "config", f"restart_command must be 'restart' or 'reload', got: '{restart_cmd}'")

    # Report staging mode
    staging = cfg.get('letsencrypt', {}).get('staging', False)
    if staging:
        record(WARN, "config", "letsencrypt.staging is true — certificates will not be trusted by browsers")
    else:
        record(PASS, "config", "letsencrypt.staging is false — production mode")

    # Report http_protocol_options
    if cfg.get('envoy', {}).get('http_protocol_options'):
        record(INFO, "config", "http_protocol_options defined — HTTP/1.0 support enabled")
    else:
        record(INFO, "config", "http_protocol_options not set — HTTP/1.0 support disabled")

    # Check at least one enabled host
    hosts = cfg.get('hosts', [])
    active = [h for h in hosts if h.get('enabled', True)]
    if active:
        record(PASS, "config", f"{len(active)} enabled host(s) defined")
    else:
        record(FAIL, "config", "No enabled hosts found in config")

    # Check cert blocks on per_host mode
    if cfg.get('certificates', {}).get('mode') == 'per_host':
        for host in active:
            if 'cert' in host:
                record(PASS, "config", f"Host '{host['name']}': cert block present")
            else:
                record(FAIL, "config", f"Host '{host['name']}': missing cert block (required for per_host mode)")


def check_envoy_service() -> None:
    """Check that the envoy systemd service exists and is active."""
    result = subprocess.run(
        ['systemctl', 'list-unit-files', 'envoy.service'],
        capture_output=True, text=True
    )
    if 'envoy.service' not in result.stdout:
        record(FAIL, "envoy", "envoy.service not found in systemd")
        return
    record(PASS, "envoy", "envoy.service found in systemd")

    result = subprocess.run(
        ['systemctl', 'is-active', 'envoy'],
        capture_output=True, text=True
    )
    status = result.stdout.strip()
    if status == 'active':
        record(PASS, "envoy", "envoy.service is active (running)")
    else:
        record(FAIL, "envoy", f"envoy.service is not active — status: {status}")


def check_ports() -> None:
    """Check that ports 80 and 443 are listening."""
    for port in [80, 443]:
        if port_listening(port):
            record(PASS, "ports", f"Port {port} is listening")
        else:
            record(FAIL, "ports", f"Port {port} is not listening — is envoy running?")


def check_directories(cfg: dict) -> None:
    """Check that required directories are writable."""
    dirs = {
        'log_dir':    cfg.get('envoy', {}).get('log_dir'),
        'webroot_dir':cfg.get('letsencrypt', {}).get('webroot_dir'),
        'cert_dir':   cfg.get('certificates', {}).get('cert_dir'),
    }
    for label, path in dirs.items():
        if not path:
            continue
        if dir_writable(path):
            record(PASS, "dirs", f"{label} is writable: {path}")
        else:
            record(FAIL, "dirs", f"{label} is not writable: {path}")


def check_dns_and_routing(cfg: dict) -> None:
    """
    For each enabled host:
      - Resolve all domains and check they point to this machine
      - Check the ACME challenge route is reachable on port 80
    """
    print("\n[INFO] [dns] Determining public IP of this machine...")
    public_ip = get_public_ip()
    if public_ip:
        record(INFO, "dns", f"Public IP of this machine: {public_ip}")
    else:
        record(WARN, "dns", "Could not determine public IP — DNS checks will be skipped")

    hosts = cfg.get('hosts', [])
    active = [h for h in hosts if h.get('enabled', True)]

    for host in active:
        for domain in host.get('domains', []):
            resolved = resolve_domain(domain)
            if not resolved:
                record(FAIL, "dns", f"{domain} — does not resolve")
            elif public_ip and public_ip not in resolved:
                record(WARN, "dns", f"{domain} — resolves to {resolved}, expected {public_ip}")
            elif public_ip:
                record(PASS, "dns", f"{domain} — resolves to {public_ip}")
            else:
                record(INFO, "dns", f"{domain} — resolves to {resolved} (public IP unknown)")

            if check_http_challenge_route(domain):
                record(PASS, "routing", f"{domain} — port 80 ACME route reachable")
            else:
                record(FAIL, "routing", f"{domain} — port 80 not reachable or connection refused")


def check_deploy_hook() -> None:
    """Check whether the certbot deploy hook is installed."""
    hook_path = '/etc/letsencrypt/renewal-hooks/deploy/envoy-deploy.sh'
    if os.path.exists(hook_path):
        record(PASS, "hook", f"Certbot deploy hook installed: {hook_path}")
        if os.access(hook_path, os.X_OK):
            record(PASS, "hook", "Deploy hook is executable")
        else:
            record(WARN, "hook", "Deploy hook exists but is not executable — run: chmod +x " + hook_path)
    else:
        record(WARN, "hook", f"Certbot deploy hook not installed — run: python3 acme.py --install-hook")


def check_certbot_version() -> None:
    """Report the installed certbot version."""
    result = subprocess.run(['certbot', '--version'], capture_output=True, text=True)
    version = (result.stdout + result.stderr).strip()
    if result.returncode == 0 or version:
        record(INFO, "certbot", f"Version: {version}")
    else:
        record(WARN, "certbot", "Could not determine certbot version")


# ============================================================
# Summary
# ============================================================

def print_summary() -> int:
    """Print a summary and return exit code (0 = all pass, 1 = failures present)."""
    total  = len(results)
    passed = sum(1 for r in results if r[0] == PASS)
    failed = sum(1 for r in results if r[0] == FAIL)
    warned = sum(1 for r in results if r[0] == WARN)

    print()
    print("=" * 60)
    print(f"  Preflight summary: {passed}/{total} checks passed")
    if warned:
        print(f"  Warnings:  {warned}")
    if failed:
        print(f"  Failures:  {failed}")
        print()
        print("  Failed checks:")
        for status, category, message in results:
            if status == FAIL:
                print(f"    [FAIL] [{category}] {message}")
    print("=" * 60)

    if failed:
        print("\n  Result: NOT READY — resolve failures before issuing certificates.\n")
        return 1
    elif warned:
        print("\n  Result: READY WITH WARNINGS — review warnings before proceeding.\n")
        return 0
    else:
        print("\n  Result: READY — all checks passed.\n")
        return 0


# ============================================================
# Main
# ============================================================

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(
        description='Envoy-Gen Preflight Check — verifies all requirements before certificate issuance'
    )
    parser.add_argument(
        '--config',
        default=os.path.join(script_dir, 'config.yaml'),
        help='Path to config.yaml (default: config.yaml next to this script)'
    )
    parser.add_argument(
        '--skip-dns',
        action='store_true',
        help='Skip DNS resolution and port 80 reachability checks'
    )
    args = parser.parse_args()

    print(f"Envoy-Gen Preflight Check")
    print(f"Config: {args.config}")
    print("=" * 60)

    check_binaries()
    check_python_modules()

    cfg = load_config(args.config)
    if cfg is None:
        print("\n[FAIL] Cannot continue without a valid config file.")
        sys.exit(1)

    check_config(cfg)
    check_envoy_service()
    check_ports()
    check_directories(cfg)
    check_certbot_version()
    check_deploy_hook()

    if not args.skip_dns:
        check_dns_and_routing(cfg)
    else:
        record(INFO, "dns", "DNS and routing checks skipped (--skip-dns)")

    sys.exit(print_summary())


if __name__ == '__main__':
    main()
