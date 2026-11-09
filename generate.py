#!/usr/bin/env python3
"""
Envoy Config Generator
Generates envoy.yaml from a config.yaml and Jinja2 templates.
Also handles log directory creation and file ownership setup.

Bootstrap mode (--bootstrap):
  Generates a reduced HTTP-only config without TLS.
  Use this for the initial setup when certificates do not exist yet.
  Full setup sequence:
    1. sudo python3 generate.py --bootstrap   # HTTP only, no certs needed
    2. sudo systemctl restart envoy           # starts without TLS
    3. sudo python3 acme.py                   # issue certificates via ACME
    4. sudo python3 generate.py               # full config with TLS
    5. sudo systemctl restart envoy           # TLS active
"""

import yaml
import os
import subprocess
import argparse
import sys
from jinja2 import Environment, FileSystemLoader

from common import (
    get_active_hosts,
    get_le_hosts,
    get_provided_hosts,
    le_active,
    get_cert_paths,
    collect_cert_checks,
)


# Default config path — resolved relative to this script's location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG = os.path.join(SCRIPT_DIR, 'config.yaml')
DEFAULT_TEMPLATES = os.path.join(SCRIPT_DIR, 'templates')
FALLBACK_OUTPUT = '/etc/envoy/envoy.yaml'


def load_config(path: str) -> dict:
    """Load and parse the YAML configuration file."""
    if not os.path.exists(path):
        print(f"[ERROR] Config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)


def get_output_path(cfg: dict, cli_output: str | None) -> str:
    """
    Resolve the output path for the generated envoy.yaml.
    Priority:
      1. --output CLI argument (explicit override)
      2. envoy.config_output from config.yaml
      3. Fallback default
    """
    if cli_output:
        return cli_output
    return cfg.get('envoy', {}).get('config_output', FALLBACK_OUTPUT)


def get_restart_command(cfg: dict) -> str:
    """
    Read the systemctl command to apply a new envoy config.
    Defaults to 'restart' if not set in config.yaml.
    """
    return cfg.get('envoy', {}).get('restart_command', 'restart')


def setup_logdir(cfg: dict) -> None:
    """
    Create the log directory and log files if they do not exist.
    Set ownership to the configured envoy service user.
    Requires root privileges.
    """
    log_dir = cfg['envoy']['log_dir']
    service_user = cfg['envoy']['service_user']

    print(f"[+] Creating log directory: {log_dir}")
    os.makedirs(log_dir, exist_ok=True)

    for logfile in ['access.log', 'access_http.log']:
        path = os.path.join(log_dir, logfile)
        if not os.path.exists(path):
            open(path, 'a').close()
            print(f"[+] Created log file: {path}")
        else:
            print(f"[~] Log file already exists: {path}")

    print(f"[+] Setting ownership to: {service_user}:{service_user}")
    try:
        subprocess.run(
            ['chown', '-R', f'{service_user}:{service_user}', log_dir],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] chown failed: {e}", file=sys.stderr)
        sys.exit(1)


def validate_config(cfg: dict, bootstrap: bool = False) -> None:
    """
    Basic validation of the configuration.
    In bootstrap mode, certificate-related checks are skipped.
    Exits with an error if required fields are missing or invalid.
    """
    errors = []

    # Check required top-level keys
    for key in ['envoy', 'certificates', 'hosts']:
        if key not in cfg:
            errors.append(f"Missing required config key: '{key}'")

    # Check config_output is defined
    if not cfg.get('envoy', {}).get('config_output'):
        errors.append("Missing required config key: 'envoy.config_output'")

    # Let's Encrypt settings are only required if at least one host uses Let's Encrypt
    if le_active(cfg):
        for key in ('email', 'webroot_dir', 'acme_port'):
            if not cfg.get('letsencrypt', {}).get(key):
                errors.append(f"Missing required config key: 'letsencrypt.{key}' (Let's Encrypt is used by at least one host)")

    # Bootstrap mode only exists to issue Let's Encrypt certificates
    if bootstrap and not le_active(cfg):
        errors.append("--bootstrap is only needed for Let's Encrypt, but no host uses it "
                      "(letsencrypt.enabled is false or no host has letsencrypt: true). "
                      "Generate the full config instead.")

    # Validate restart_command value
    restart_cmd = cfg.get('envoy', {}).get('restart_command', 'restart')
    if restart_cmd not in ('restart', 'reload'):
        errors.append(f"envoy.restart_command must be 'restart' or 'reload', got: '{restart_cmd}'")

    # Certificate checks are only relevant in full (non-bootstrap) mode
    if not bootstrap:
        cert_mode = cfg.get('certificates', {}).get('mode')
        if cert_mode not in ('shared', 'per_host'):
            errors.append(f"certificates.mode must be 'shared' or 'per_host', got: '{cert_mode}'")

        if cert_mode == 'shared':
            shared = cfg.get('certificates', {}).get('shared') or {}
            if not shared.get('fullchain') or not shared.get('privkey'):
                errors.append("certificates.mode is 'shared' but certificates.shared.fullchain/privkey is not defined")

    # Check hosts
    hosts = cfg.get('hosts', [])
    if not hosts:
        errors.append("No hosts defined in configuration")

    active_hosts = [h for h in hosts if h.get('enabled', True)]
    if not active_hosts:
        errors.append("No enabled hosts found - at least one host must be enabled")

    for host in hosts:
        if not host.get('name'):
            errors.append("A host entry is missing the 'name' field")
        if not host.get('domains'):
            errors.append(f"Host '{host.get('name', '?')}' has no domains defined")
        if not bootstrap:
            cert_mode = cfg.get('certificates', {}).get('mode')
            if cert_mode == 'per_host' and host.get('enabled', True):
                if 'cert' not in host:
                    errors.append(f"Host '{host.get('name')}' is missing 'cert' block (required for per_host mode)")

    if errors:
        print("[ERROR] Configuration validation failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    mode_label = "bootstrap (HTTP only)" if bootstrap else "full (HTTP + TLS)"
    print(f"[+] Configuration valid — {len(active_hosts)} active host(s) — mode: {mode_label}")


def render_template(cfg: dict, template_dir: str, bootstrap: bool = False) -> str:
    """
    Render the envoy.yaml Jinja2 template with the provided configuration.
    In bootstrap mode, use the HTTP-only template (no TLS, no cert files required).
    """
    if not os.path.isdir(template_dir):
        print(f"[ERROR] Template directory not found: {template_dir}", file=sys.stderr)
        sys.exit(1)

    env = Environment(
        loader=FileSystemLoader(template_dir),
        trim_blocks=True,
        lstrip_blocks=True
    )

    template_file = 'envoy.bootstrap.yaml.j2' if bootstrap else 'envoy.yaml.j2'
    print(f"[+] Using template: {template_file}")
    template = env.get_template(template_file)

    active_hosts = get_active_hosts(cfg)
    le_names     = {h['name'] for h in get_le_hosts(cfg)}

    # Resolve certificate paths per host (not needed in bootstrap mode)
    hosts = []
    for host in active_hosts:
        entry = dict(host)
        entry['cert_source'] = 'letsencrypt' if host['name'] in le_names else 'provided'
        if not bootstrap:
            fullchain, privkey = get_cert_paths(host, cfg)
            entry['cert_paths'] = {'fullchain': fullchain, 'privkey': privkey}
        hosts.append(entry)

    return template.render(
        envoy=cfg['envoy'],
        letsencrypt=cfg.get('letsencrypt', {}),
        certificates=cfg['certificates'],
        hosts=hosts,
        le_active=le_active(cfg),
        acme_port=cfg.get('letsencrypt', {}).get('acme_port'),
    )


def check_certificates(cfg: dict) -> bool:
    """
    Verify all certificate/key pairs referenced by the config:
    files exist, key matches certificate, not expired, domains covered by SANs.
    Prints a report and returns True if no errors were found.
    """
    hosts  = get_active_hosts(cfg)
    checks = collect_cert_checks(cfg, hosts)
    le_names = {h['name'] for h in get_le_hosts(cfg)}
    provided = [h['name'] for h in get_provided_hosts(cfg)]

    print(f"[+] Certificate check — Let's Encrypt hosts: {', '.join(sorted(le_names)) or '-'}; "
          f"provided-certificate hosts: {', '.join(provided) or '-'}")

    ok = True
    for label, result in checks:
        for line in result['info']:
            print(f"[i]   [{label}] {line}")
        for line in result['warnings']:
            print(f"[WARNING] [{label}] {line}")
        for line in result['errors']:
            print(f"[ERROR] [{label}] {line}", file=sys.stderr)
            ok = False
    if ok:
        print("[+] Certificate check passed")
    return ok


def validate_envoy_binary(output_path: str) -> None:
    """
    Run 'envoy --mode validate' against the generated config file.
    Skipped if the envoy binary is not found in PATH.
    """
    envoy_bin = None
    for path in os.environ.get('PATH', '').split(':'):
        candidate = os.path.join(path, 'envoy')
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            envoy_bin = candidate
            break

    if not envoy_bin:
        print("[~] envoy binary not found in PATH — skipping config validation")
        return

    print(f"[+] Validating config with: {envoy_bin}")
    result = subprocess.run(
        [envoy_bin, '--mode', 'validate', '-c', output_path],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print("[+] Envoy config validation passed")
    else:
        print("[ERROR] Envoy config validation failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)


def apply_envoy_config(cfg: dict) -> None:
    """Apply the new envoy config via systemctl using the configured restart_command."""
    cmd = get_restart_command(cfg)
    print(f"[+] Applying config via: systemctl {cmd} envoy")
    try:
        subprocess.run(['systemctl', cmd, 'envoy'], check=True)
        print(f"[+] Envoy {cmd}ed successfully")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] systemctl {cmd} envoy failed: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='Envoy Config Generator — builds envoy.yaml from config.yaml and Jinja2 templates'
    )
    parser.add_argument(
        '--config',
        default=DEFAULT_CONFIG,
        help=f'Path to config.yaml (default: {DEFAULT_CONFIG})'
    )
    parser.add_argument(
        '--templates',
        default=DEFAULT_TEMPLATES,
        help=f'Path to templates directory (default: {DEFAULT_TEMPLATES})'
    )
    parser.add_argument(
        '--output',
        default=None,
        help=(
            'Output path for generated envoy.yaml. '
            'Overrides envoy.config_output from config.yaml. '
            f'Final fallback: {FALLBACK_OUTPUT}'
        )
    )
    parser.add_argument(
        '--bootstrap',
        action='store_true',
        help=(
            'Generate a HTTP-only config without TLS (no certificates required). '
            'Use this for initial setup before certificates have been issued.'
        )
    )
    parser.add_argument(
        '--no-logdir',
        action='store_true',
        help='Skip log directory creation and chown'
    )
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Run envoy --mode validate after writing the config'
    )
    parser.add_argument(
        '--reload',
        action='store_true',
        help=(
            'Apply the new config via systemctl after generation. '
            'Uses envoy.restart_command from config.yaml (default: restart).'
        )
    )
    parser.add_argument(
        '--skip-cert-check',
        action='store_true',
        help=(
            'Do not verify certificate files before writing the full config. '
            'By default a missing file, a key/certificate mismatch or an expired certificate aborts the run.'
        )
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Print generated config to stdout, do not write any files'
    )
    args = parser.parse_args()

    # Load config first — output path may come from it
    cfg = load_config(args.config)

    # Resolve output path: CLI arg > config.yaml > fallback
    output_path = get_output_path(cfg, args.output)
    print(f"[+] Output path: {output_path}")

    # Validate config
    validate_config(cfg, bootstrap=args.bootstrap)

    # Verify certificate files (full mode only — bootstrap runs without certificates)
    if not args.bootstrap and not args.skip_cert_check:
        cert_ok = check_certificates(cfg)
        if not cert_ok and not args.dry_run:
            print("[ERROR] Certificate check failed — envoy.yaml was NOT written. "
                  "Fix the certificates or use --skip-cert-check to override.", file=sys.stderr)
            sys.exit(1)

    # Set up log directory (requires root, skip in dry-run)
    if not args.no_logdir and not args.dry_run:
        setup_logdir(cfg)

    # Render template
    rendered = render_template(cfg, args.templates, bootstrap=args.bootstrap)

    if args.dry_run:
        print("# ===== DRY RUN — output not written to disk =====")
        print(rendered)
        return

    # Write output file
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(rendered)

    mode_label = "bootstrap" if args.bootstrap else "full"
    print(f"[+] envoy.yaml ({mode_label}) written to: {output_path}")

    if args.bootstrap:
        print("[i] Bootstrap config written. Next steps:")
        print("[i]   1. sudo systemctl restart envoy")
        print("[i]   2. sudo python3 acme.py --staging   # test with staging first")
        print("[i]   3. sudo python3 acme.py             # production certificates")
        print("[i]   4. sudo python3 generate.py")
        print("[i]   5. sudo systemctl restart envoy")

    # Optional: validate via envoy binary
    if args.validate or args.reload:
        validate_envoy_binary(output_path)

    # Optional: apply config via systemctl
    if args.reload:
        apply_envoy_config(cfg)


if __name__ == '__main__':
    main()
