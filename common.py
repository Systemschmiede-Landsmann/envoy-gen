"""
Shared helpers for envoy-gen (used by generate.py, acme.py and preflight.py).

Certificate sources
-------------------
Each enabled host gets its certificate from one of two sources:

  * Let's Encrypt (managed by acme.py)
  * Provided      (you supply ready-made certificate files)

Which hosts use Let's Encrypt is decided by get_le_hosts():
  - letsencrypt.enabled: false           -> no host uses Let's Encrypt
  - letsencrypt.all_hosts: true          -> every enabled host uses Let's Encrypt
  - letsencrypt.all_hosts: false         -> only hosts with "letsencrypt: true"

All remaining enabled hosts use provided certificate files.
"""

import os
import shutil
import subprocess
from datetime import datetime, timezone

# Warn when a certificate expires in fewer days than this
EXPIRY_WARN_DAYS = 14


# ============================================================
# Certificate source selection
# ============================================================

def get_active_hosts(cfg: dict) -> list:
    """Return all hosts with enabled: true (default true)."""
    return [h for h in cfg.get('hosts', []) if h.get('enabled', True)]


def get_le_hosts(cfg: dict) -> list:
    """Return the enabled hosts whose certificate is managed by Let's Encrypt."""
    le_cfg = cfg.get('letsencrypt', {})
    if not le_cfg.get('enabled', False):
        return []

    all_hosts_flag = le_cfg.get('all_hosts', True)
    result = []
    for host in get_active_hosts(cfg):
        if all_hosts_flag or host.get('letsencrypt', False):
            result.append(host)
    return result


def get_provided_hosts(cfg: dict) -> list:
    """Return the enabled hosts that use provided (non Let's Encrypt) certificates."""
    le_names = {h['name'] for h in get_le_hosts(cfg)}
    return [h for h in get_active_hosts(cfg) if h['name'] not in le_names]


def le_active(cfg: dict) -> bool:
    """True if at least one enabled host is managed by Let's Encrypt."""
    return bool(get_le_hosts(cfg))


# ============================================================
# Certificate path resolution
# ============================================================

def resolve_cert_file(cert_dir: str, filename: str) -> str:
    """
    Resolve a certificate filename from config.yaml.
    Absolute paths are used as they are, relative names are placed in cert_dir.
    """
    if os.path.isabs(filename):
        return filename
    return os.path.join(cert_dir, filename)


def get_cert_paths(host: dict, cfg: dict) -> tuple:
    """
    Return (fullchain_path, privkey_path) for a host, depending on certificates.mode.
    Raises ValueError if the required config keys are missing.
    """
    certs     = cfg['certificates']
    cert_dir  = certs['cert_dir']
    cert_mode = certs.get('mode', 'per_host')

    if cert_mode == 'shared':
        shared = certs.get('shared') or {}
        if not shared.get('fullchain') or not shared.get('privkey'):
            raise ValueError("certificates.mode is 'shared' but certificates.shared.fullchain/privkey is not defined")
        src = shared
    else:
        src = host.get('cert') or {}
        if not src.get('fullchain') or not src.get('privkey'):
            raise ValueError(f"Host '{host.get('name', '?')}' is missing cert.fullchain/privkey (required for per_host mode)")

    return (resolve_cert_file(cert_dir, src['fullchain']),
            resolve_cert_file(cert_dir, src['privkey']))


# ============================================================
# Certificate inspection (uses the openssl CLI, no extra Python modules)
# ============================================================

def _openssl(args: list) -> subprocess.CompletedProcess:
    return subprocess.run(['openssl'] + args, capture_output=True, text=True)


def _parse_not_after(value: str) -> datetime:
    """Parse the openssl notAfter format, e.g. 'Dec 23 12:56:20 2026 GMT'."""
    return datetime.strptime(' '.join(value.split()), '%b %d %H:%M:%S %Y GMT').replace(tzinfo=timezone.utc)


def domain_covered(domain: str, sans: list) -> bool:
    """Check a domain against certificate SANs (exact match or single-label wildcard)."""
    domain = domain.lower()
    for san in sans:
        san = san.lower()
        if san == domain:
            return True
        if san.startswith('*.') and '.' in domain and domain.split('.', 1)[1] == san[2:]:
            return True
    return False


def inspect_certificate(fullchain: str, privkey: str, domains: list) -> dict:
    """
    Inspect a certificate/key pair and return a dict:
      errors:   problems that make the certificate unusable
      warnings: problems worth a look (expiring soon, domain not covered)
      info:     facts (expiry date, SANs)

    Checks: files exist and are readable, certificate parses, key matches the
    certificate, certificate is not expired, domains are covered by the SANs.
    """
    result = {'errors': [], 'warnings': [], 'info': []}

    for label, path in (('certificate', fullchain), ('private key', privkey)):
        if not os.path.isfile(path):
            result['errors'].append(f"{label} file not found: {path}")
        elif not os.access(path, os.R_OK):
            result['errors'].append(f"{label} file not readable: {path}")
    if result['errors']:
        return result

    if not shutil.which('openssl'):
        result['warnings'].append("openssl not found - content checks skipped (only file existence verified)")
        return result

    # Certificate: expiry + SANs (first certificate in the file = leaf)
    proc = _openssl(['x509', '-in', fullchain, '-noout', '-enddate', '-ext', 'subjectAltName'])
    if proc.returncode != 0:
        result['errors'].append(f"cannot parse certificate {fullchain}: {proc.stderr.strip()}")
        return result

    sans = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith('notAfter='):
            try:
                not_after = _parse_not_after(line.split('=', 1)[1])
                days_left = (not_after - datetime.now(timezone.utc)).days
                result['info'].append(f"expires {not_after:%Y-%m-%d} ({days_left} days left)")
                if days_left < 0:
                    result['errors'].append(f"certificate expired on {not_after:%Y-%m-%d}: {fullchain}")
                elif days_left < EXPIRY_WARN_DAYS:
                    result['warnings'].append(f"certificate expires in {days_left} days: {fullchain}")
            except ValueError:
                result['warnings'].append(f"could not parse expiry date: {line}")
        elif 'DNS:' in line:
            sans += [p.strip()[4:] for p in line.split(',') if p.strip().startswith('DNS:')]

    # Key must belong to the certificate
    cert_pub = _openssl(['x509', '-in', fullchain, '-noout', '-pubkey'])
    key_pub  = _openssl(['pkey', '-in', privkey, '-pubout'])
    if key_pub.returncode != 0:
        result['errors'].append(f"cannot read private key {privkey} (encrypted or invalid): {key_pub.stderr.strip()}")
    elif cert_pub.stdout.strip() != key_pub.stdout.strip():
        result['errors'].append(f"private key does not match certificate: {privkey} <-> {fullchain}")

    # Domains must be covered
    if sans:
        result['info'].append(f"SANs: {', '.join(sans)}")
        for domain in domains:
            if not domain_covered(domain, sans):
                result['warnings'].append(f"domain '{domain}' is not covered by the certificate SANs")
    else:
        result['warnings'].append("certificate has no DNS SANs - cannot verify domain coverage")

    return result


def collect_cert_checks(cfg: dict, hosts: list) -> list:
    """
    Inspect the certificates of the given hosts.
    Returns a list of (label, result) - one entry per unique certificate/key pair,
    with all domains that use it checked against the SANs.
    """
    groups = {}
    for host in hosts:
        try:
            fullchain, privkey = get_cert_paths(host, cfg)
        except ValueError as e:
            groups[('config-error', host['name'])] = {
                'label': host['name'], 'domains': [], 'error': str(e), 'paths': None}
            continue
        entry = groups.setdefault((fullchain, privkey), {
            'label': [], 'domains': [], 'error': None, 'paths': (fullchain, privkey)})
        entry['label'].append(host['name'])
        entry['domains'] += host.get('domains', [])

    checks = []
    for entry in groups.values():
        if entry['error']:
            checks.append((entry['label'], {'errors': [entry['error']], 'warnings': [], 'info': []}))
            continue
        label = ', '.join(entry['label'])
        checks.append((label, inspect_certificate(*entry['paths'], entry['domains'])))
    return checks


# ============================================================
# Config file hint
# ============================================================

def missing_config_hint(path: str) -> str:
    """Return a hint for a missing config file (points to config.example.yaml if present)."""
    example = os.path.join(os.path.dirname(os.path.abspath(path)), 'config.example.yaml')
    if os.path.isfile(example):
        return f"Create it from the example: cp {example} {path}  (then edit it)"
    return "Create the file or pass the correct path with --config"
