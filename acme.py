#!/usr/bin/env python3
"""
Envoy ACME Certificate Manager
Reads config.yaml and issues/renews Let's Encrypt certificates
for all qualifying hosts using certbot in webroot mode.

Certificate issuance targets are determined by:
  - letsencrypt.enabled must be true
  - host.enabled must be true
  - if letsencrypt.all_hosts is true:  all enabled hosts get a cert
  - if letsencrypt.all_hosts is false: only hosts with letsencrypt: true

Flags:
  --expand        Pass --expand to certbot to add new domains to existing certs
  --deploy-only   Only copy certificates and restart envoy, skip certbot
  --install-hook  Install certbot pre/post/deploy hooks for automatic renewal
  --staging       Override config and force use of LE staging server
  --production    Override config and force use of LE production server
"""

import yaml
import os
import sys
import shutil
import subprocess
import argparse
import time


DEPLOY_HOOK_DIR  = '/etc/letsencrypt/renewal-hooks/deploy'
PRE_HOOK_DIR     = '/etc/letsencrypt/renewal-hooks/pre'
POST_HOOK_DIR    = '/etc/letsencrypt/renewal-hooks/post'
DEPLOY_HOOK_NAME = 'envoy-deploy.sh'
PRE_HOOK_NAME    = 'start-webroot.sh'
POST_HOOK_NAME   = 'stop-webroot.sh'
LE_STAGING_URL   = 'https://acme-staging-v02.api.letsencrypt.org/directory'
WEBROOT_PID_FILE = '/tmp/certbot-webroot.pid'


def load_config(path: str) -> dict:
    """Load and parse the YAML configuration file."""
    if not os.path.exists(path):
        print(f"[ERROR] Config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)


def get_restart_command(cfg: dict) -> str:
    """Read the systemctl command to apply a new envoy config."""
    return cfg.get('envoy', {}).get('restart_command', 'restart')


def get_le_hosts(cfg: dict) -> list:
    """Return the list of hosts that should receive a Let's Encrypt certificate."""
    all_hosts_flag = cfg['letsencrypt'].get('all_hosts', True)
    result = []
    for host in cfg['hosts']:
        if not host.get('enabled', True):
            continue
        if all_hosts_flag:
            result.append(host)
        else:
            if host.get('letsencrypt', False):
                result.append(host)
    return result


def is_staging(cfg: dict, cli_staging) -> bool:
    """
    Determine whether to use the LE staging server.
    Priority: CLI flag > config.yaml > default (False)
    """
    if cli_staging is not None:
        return cli_staging
    return cfg.get('letsencrypt', {}).get('staging', False)


def get_cert_paths(host: dict, cfg: dict) -> tuple[str, str]:
    """
    Resolve destination cert paths based on certificate mode.
    Returns (dst_fullchain, dst_privkey).

    In shared mode:  uses certificates.shared.fullchain / privkey
    In per_host mode: uses host.cert.fullchain / privkey
    """
    cert_dir  = cfg['certificates']['cert_dir']
    cert_mode = cfg['certificates'].get('mode', 'per_host')

    if cert_mode == 'shared':
        shared = cfg['certificates'].get('shared', {})
        if not shared:
            print("[ERROR] certificates.mode is 'shared' but certificates.shared is not defined", file=sys.stderr)
            sys.exit(1)
        dst_fullchain = os.path.join(cert_dir, shared['fullchain'])
        dst_privkey   = os.path.join(cert_dir, shared['privkey'])
    else:
        if 'cert' not in host:
            print(f"[ERROR] Host '{host['name']}' is missing 'cert' block (required for per_host mode)", file=sys.stderr)
            sys.exit(1)
        dst_fullchain = os.path.join(cert_dir, host['cert']['fullchain'])
        dst_privkey   = os.path.join(cert_dir, host['cert']['privkey'])

    return dst_fullchain, dst_privkey


def ensure_webroot(webroot_dir: str) -> None:
    """Create the webroot directory if it does not exist."""
    if not os.path.exists(webroot_dir):
        print(f"[+] Creating webroot directory: {webroot_dir}")
        os.makedirs(webroot_dir, exist_ok=True)
    else:
        print(f"[~] Webroot directory already exists: {webroot_dir}")


def start_webroot_server(webroot_dir: str, port: int) -> subprocess.Popen:
    """Start a local HTTP server to serve ACME challenge files."""
    print(f"[+] Starting webroot server on port {port} serving: {webroot_dir}")
    proc = subprocess.Popen(
        [sys.executable, '-m', 'http.server', str(port), '--directory', webroot_dir],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1)
    if proc.poll() is not None:
        print(f"[ERROR] Webroot server failed to start (exit code: {proc.returncode})", file=sys.stderr)
        sys.exit(1)
    print(f"[+] Webroot server running (PID {proc.pid})")
    return proc


def stop_webroot_server(proc: subprocess.Popen) -> None:
    """Stop the local webroot HTTP server."""
    if proc and proc.poll() is None:
        print(f"[+] Stopping webroot server (PID {proc.pid})")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def issue_certificate(host: dict, cfg: dict, dry_run: bool = False,
                      expand: bool = False, staging: bool = False) -> bool:
    """Run certbot to issue or renew a certificate for a single host."""
    le_cfg      = cfg['letsencrypt']
    webroot_dir = le_cfg['webroot_dir']
    email       = le_cfg['email']
    domains     = host['domains']

    cmd = [
        'certbot', 'certonly',
        '--webroot',
        '--webroot-path', webroot_dir,
        '--email', email,
        '--agree-tos',
        '--non-interactive',
        '--keep-until-expiring',
    ]

    if staging:
        cmd += ['--server', LE_STAGING_URL]
    if expand:
        cmd.append('--expand')
    for domain in domains:
        cmd += ['-d', domain]
    if dry_run:
        cmd.append('--dry-run')

    domain_str = ', '.join(domains)
    flags = []
    if staging:
        flags.append('staging')
    if expand:
        flags.append('expand')
    if dry_run:
        flags.append('dry-run')
    flag_note = f" ({', '.join(flags)})" if flags else ""

    print(f"[+] Requesting certificate for: {domain_str}{flag_note}")
    if staging:
        print(f"[i] Using LE staging server — certificate will NOT be trusted by browsers")

    result = subprocess.run(cmd, capture_output=False)
    if result.returncode == 0:
        print(f"[+] Certificate issued/renewed successfully for: {domain_str}")
        return True
    else:
        print(f"[ERROR] certbot failed for: {domain_str}", file=sys.stderr)
        if not expand:
            print(f"[HINT] If you added new domains to an existing certificate, re-run with --expand", file=sys.stderr)
        return False


def deploy_certificate(host: dict, cfg: dict, dry_run: bool = False,
                       staging: bool = False) -> None:
    """
    Copy the issued Let's Encrypt certificate files into the envoy cert directory.
    Uses the primary domain (first in list) as the certbot certificate name.
    Respects certificates.mode (shared or per_host) for destination paths.
    Skipped in staging mode.
    """
    if staging:
        primary_domain = host['domains'][0]
        le_live = f"/etc/letsencrypt/live/{primary_domain}"
        print(f"[i] Staging mode — skipping certificate deployment to envoy cert_dir")
        print(f"[i] Staging cert stored at: {le_live}")
        return

    primary_domain = host['domains'][0]
    le_live        = f"/etc/letsencrypt/live/{primary_domain}"
    src_fullchain  = os.path.join(le_live, 'fullchain.pem')
    src_privkey    = os.path.join(le_live, 'privkey.pem')

    dst_fullchain, dst_privkey = get_cert_paths(host, cfg)

    print(f"[+] Deploying certificate for: {host['name']}")
    print(f"    {src_fullchain} -> {dst_fullchain}")
    print(f"    {src_privkey}   -> {dst_privkey}")

    if dry_run:
        print(f"[~] Dry-run mode — skipping file copy")
        return

    if not os.path.exists(src_fullchain) or not os.path.exists(src_privkey):
        print(f"[ERROR] Certificate source files not found in: {le_live}", file=sys.stderr)
        return

    cert_dir = cfg['certificates']['cert_dir']
    os.makedirs(cert_dir, exist_ok=True)
    shutil.copy2(src_fullchain, dst_fullchain)
    shutil.copy2(src_privkey,   dst_privkey)
    print(f"[+] Certificate files deployed for: {host['name']}")


def deploy_only(cfg: dict, dry_run: bool = False) -> None:
    """
    Copy certificates into the envoy cert directory and restart envoy.
    Does not run certbot. Used by the certbot deploy hook.
    """
    le_hosts = get_le_hosts(cfg)
    if not le_hosts:
        print("[INFO] No hosts qualify — nothing to deploy")
        return

    failed = []
    for host in le_hosts:
        deploy_certificate(host, cfg, dry_run=dry_run, staging=False)

    if not failed:
        apply_envoy_config(cfg, dry_run=dry_run)
    else:
        print(f"[WARNING] Deploy failed for: {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)


def apply_envoy_config(cfg: dict, dry_run: bool = False, staging: bool = False) -> None:
    """Apply the new envoy config via systemctl using the configured restart_command."""
    if staging:
        print(f"[i] Staging mode — skipping envoy restart (no production certs deployed)")
        return

    cmd = get_restart_command(cfg)
    print(f"[+] Applying config via: systemctl {cmd} envoy")
    if dry_run:
        print(f"[~] Dry-run mode — skipping systemctl {cmd} envoy")
        return
    try:
        subprocess.run(['systemctl', cmd, 'envoy'], check=True)
        print(f"[+] Envoy {cmd}ed successfully")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] systemctl {cmd} envoy failed: {e}", file=sys.stderr)
        sys.exit(1)


def install_hooks(config_path: str, cfg: dict, dry_run: bool = False) -> None:
    """
    Install certbot pre/post/deploy hooks for automatic renewal.

    pre hook:    starts the webroot server before certbot runs
    post hook:   stops the webroot server after certbot finishes
    deploy hook: copies certs and restarts envoy after successful renewal
                 calls acme.py --deploy-only (no certbot, no recursion)
    """
    script_path = os.path.abspath(__file__)
    webroot_dir = cfg['letsencrypt']['webroot_dir']
    acme_port   = cfg['letsencrypt']['acme_port']

    hooks = {
        os.path.join(PRE_HOOK_DIR, PRE_HOOK_NAME): f"""#!/bin/bash
# Certbot pre-hook — start webroot server before ACME challenge
# Managed by envoy-gen/acme.py — do not edit manually
nohup python3 -m http.server {acme_port} --directory {webroot_dir} > /tmp/certbot-webroot.log 2>&1 &
echo $! > {WEBROOT_PID_FILE}
""",
        os.path.join(POST_HOOK_DIR, POST_HOOK_NAME): f"""#!/bin/bash
# Certbot post-hook — stop webroot server after ACME challenge
# Managed by envoy-gen/acme.py — do not edit manually
if [ -f {WEBROOT_PID_FILE} ]; then
    kill $(cat {WEBROOT_PID_FILE}) 2>/dev/null
    rm -f {WEBROOT_PID_FILE}
fi
""",
        os.path.join(DEPLOY_HOOK_DIR, DEPLOY_HOOK_NAME): f"""#!/bin/bash
# Certbot deploy-hook — deploy certs and restart envoy after renewal
# Managed by envoy-gen/acme.py — do not edit manually
python3 {script_path} \\
  --deploy-only \\
  --config {config_path}
""",
    }

    for hook_path, content in hooks.items():
        hook_dir = os.path.dirname(hook_path)
        print(f"[+] Installing hook: {hook_path}")
        if dry_run:
            print(f"[~] Dry-run — content would be:")
            print(content)
            continue
        os.makedirs(hook_dir, exist_ok=True)
        with open(hook_path, 'w') as f:
            f.write(content)
        os.chmod(hook_path, 0o755)
        print(f"[+] Hook installed: {hook_path}")

    if not dry_run:
        print(f"[i] All hooks installed. Certbot will use them automatically on renewal.")


def check_deploy_hook() -> None:
    """Warn if the deploy hook is not installed."""
    hook_path = os.path.join(DEPLOY_HOOK_DIR, DEPLOY_HOOK_NAME)
    if not os.path.exists(hook_path):
        print(f"[HINT] No certbot deploy hook found — run with --install-hook to set it up.")


def main():
    script_dir     = os.path.dirname(os.path.abspath(__file__))
    default_config = os.path.join(script_dir, 'config.yaml')

    parser = argparse.ArgumentParser(
        description='Envoy ACME Certificate Manager'
    )
    parser.add_argument(
        '--config',
        default=default_config,
        help='Path to config.yaml (default: config.yaml next to this script)'
    )
    parser.add_argument(
        '--expand',
        action='store_true',
        help='Pass --expand to certbot (required when adding new domains to existing cert)'
    )
    parser.add_argument(
        '--install-hook',
        action='store_true',
        help='Install certbot pre/post/deploy hooks for automatic renewal'
    )
    parser.add_argument(
        '--deploy-only',
        action='store_true',
        help='Only copy certificates and restart envoy — skip certbot entirely (used by deploy hook)'
    )

    staging_group = parser.add_mutually_exclusive_group()
    staging_group.add_argument(
        '--staging',
        action='store_true',
        default=None,
        help='Force use of LE staging server (untrusted cert, no rate limits)'
    )
    staging_group.add_argument(
        '--production',
        action='store_true',
        default=None,
        help='Force use of LE production server'
    )

    parser.add_argument('--dry-run',          action='store_true', help='Show what would be done without changes')
    parser.add_argument('--no-reload',        action='store_true', help='Skip envoy restart after deployment')
    parser.add_argument('--no-webroot-server',action='store_true', help='Do not start the built-in webroot server')
    args = parser.parse_args()

    cfg = load_config(args.config)

    # Resolve staging flag
    if args.staging:
        cli_staging = True
    elif args.production:
        cli_staging = False
    else:
        cli_staging = None
    use_staging = is_staging(cfg, cli_staging)

    # Install hooks if requested
    if args.install_hook:
        install_hooks(os.path.abspath(args.config), cfg, dry_run=args.dry_run)

    # Deploy-only mode — used by certbot deploy hook
    if args.deploy_only:
        print("[+] Deploy-only mode — copying certificates and restarting envoy")
        deploy_only(cfg, dry_run=args.dry_run)
        return

    # Check master LE switch
    if not cfg.get('letsencrypt', {}).get('enabled', False):
        print("[INFO] letsencrypt.enabled is false — nothing to do")
        sys.exit(0)

    le_cfg      = cfg['letsencrypt']
    webroot_dir = le_cfg['webroot_dir']
    acme_port   = le_cfg['acme_port']

    le_hosts = get_le_hosts(cfg)
    if not le_hosts:
        print("[INFO] No hosts qualify for LE certificate issuance — nothing to do")
        sys.exit(0)

    all_hosts_flag = le_cfg.get('all_hosts', True)
    mode_label     = "all enabled hosts" if all_hosts_flag else "per-host letsencrypt flag"
    restart_cmd    = get_restart_command(cfg)

    print(f"[+] LE target selection mode: {mode_label}")
    print(f"[+] Hosts to process: {', '.join(h['name'] for h in le_hosts)}")
    print(f"[+] Envoy apply command: systemctl {restart_cmd} envoy")

    if use_staging:
        print(f"[i] STAGING MODE — using LE staging server, certificates will not be trusted")
    else:
        print(f"[+] PRODUCTION MODE — using LE production server")

    if args.expand:
        print(f"[+] Expand mode enabled — new domains will be added to existing certificates")

    ensure_webroot(webroot_dir)

    webroot_proc = None
    if not args.no_webroot_server:
        webroot_proc = start_webroot_server(webroot_dir, acme_port)

    failed_hosts = []

    try:
        for host in le_hosts:
            success = issue_certificate(
                host, cfg,
                dry_run=args.dry_run,
                expand=args.expand,
                staging=use_staging
            )
            if success:
                deploy_certificate(host, cfg, dry_run=args.dry_run, staging=use_staging)
            else:
                failed_hosts.append(host['name'])
    finally:
        if webroot_proc:
            stop_webroot_server(webroot_proc)

    if not failed_hosts and not args.no_reload:
        apply_envoy_config(cfg, dry_run=args.dry_run, staging=use_staging)
    elif failed_hosts:
        print(f"[WARNING] Certificate issuance failed for: {', '.join(failed_hosts)}", file=sys.stderr)
        print("[WARNING] Skipping envoy apply due to errors", file=sys.stderr)
        sys.exit(1)

    if not use_staging and not args.install_hook and not args.no_reload:
        check_deploy_hook()


if __name__ == '__main__':
    main()
