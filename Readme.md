# envoy-gen

A lightweight toolchain for generating [Envoy](https://www.envoyproxy.io/) reverse proxy configurations and managing [Let's Encrypt](https://letsencrypt.org/) TLS certificates — designed for Envoy instances running as a systemd service in front of a Kubernetes cluster.

## Overview

`envoy-gen` solves a specific problem: managing Envoy configurations across multiple systems with different hostnames, active services, and certificate setups — without editing YAML by hand each time.

Everything is driven by a single `config.yaml`. All scripts read from it, so there is one place to change things.

```
envoy-gen/
├── config.yaml                      # Single source of truth for all scripts
├── generate.py                      # Generates envoy.yaml from templates
├── acme.py                          # Issues and renews Let's Encrypt certificates
├── preflight.py                     # Checks all requirements before cert issuance
└── templates/
    ├── envoy.yaml.j2                # Full config template (HTTP + TLS)
    └── envoy.bootstrap.yaml.j2     # Bootstrap template (HTTP only, no TLS)
```

## Architecture

```
Internet
   │
   ▼
Firewall / Router (NAT port 80 + 443)
   │
   ▼
Envoy (systemd service, Debian host)
   │  ├── TLS termination per hostname (SNI)
   │  ├── HTTP → HTTPS redirect
   │  └── ACME challenge routing (/.well-known/acme-challenge/)
   │
   ▼
Kubernetes NodePort upstream
```

Envoy runs **outside** the Kubernetes cluster as a bare systemd service. It handles TLS termination and routes all traffic to a Kubernetes NodePort.

## Requirements

- Debian/Ubuntu Linux
- Python 3.11+
- Envoy proxy installed as a systemd service
- Public DNS pointing to this host for all configured domains

```bash
apt install python3-pip certbot
pip3 install jinja2 pyyaml
```

## Quick Start

### First deployment (no certificates yet)

Certificates don't exist yet — Envoy can't start with TLS. Use bootstrap mode first:

```bash
# 1. Generate HTTP-only config (no certificates required)
sudo python3 generate.py --bootstrap

# 2. Start Envoy — works without TLS
sudo systemctl restart envoy

# 3. Verify everything is ready
sudo python3 preflight.py

# 4. Test with LE staging server first (no rate limits)
sudo python3 acme.py --staging

# 5. Issue production certificates
sudo python3 acme.py --production

# 6. Install renewal hooks
sudo python3 acme.py --install-hook

# 7. Generate full config with TLS
sudo python3 generate.py

# 8. Restart Envoy — TLS now active
sudo systemctl restart envoy
```

### Subsequent deployments (certificates already exist)

```bash
sudo python3 generate.py
sudo systemctl restart envoy
```

## Configuration (`config.yaml`)

All scripts share this file. Copy and adapt it for each system.

```yaml
envoy:
  log_dir: /var/log/envoy
  service_user: root
  config_output: /usr/local/etc/envoy/envoy.yaml
  restart_command: restart        # "restart" or "reload"
  upstream:
    address: 10.0.0.1
    port: 30080
  # Optional: enable if upstream proxy downgrades to HTTP/1.0
  http_protocol_options:
    accept_http_10: true
    default_host_for_http_10: "localhost"

letsencrypt:
  enabled: true
  acme_port: 8888
  email: admin@example.com
  webroot_dir: /var/www
  staging: false                  # true = staging server, false = production
  all_hosts: true                 # false = per-host control via letsencrypt: flag

certificates:
  mode: per_host                  # "shared" or "per_host"
  cert_dir: /usr/local/etc/envoy
  # For mode: shared — one cert for all hosts:
  # shared:
  #   fullchain: shared-tls.fullchain.pem
  #   privkey:   shared-tls.privkey.pem

hosts:
  - name: main
    domains:
      - example.com
      - dav.example.com
    enabled: true
    letsencrypt: true             # only relevant when all_hosts: false
    cert:
      fullchain: main-tls.fullchain.pem
      privkey:   main-tls.privkey.pem

  - name: grafana
    domains:
      - grafana.example.com
    enabled: true
    letsencrypt: true
    cert:
      fullchain: grafana-tls.fullchain.pem
      privkey:   grafana-tls.privkey.pem

  - name: prometheus
    domains:
      - prometheus.example.com
    enabled: false                # set true to activate
    letsencrypt: false
    cert:
      fullchain: prometheus-tls.fullchain.pem
      privkey:   prometheus-tls.privkey.pem
```

### Key config options

| Key | Description |
|---|---|
| `certificates.mode` | `shared` — one cert for all hosts / `per_host` — individual cert per host |
| `letsencrypt.staging` | `true` = LE staging server (untrusted cert, no rate limits) |
| `letsencrypt.all_hosts` | `true` = all enabled hosts get a cert / `false` = per-host control |
| `envoy.http_protocol_options` | Enable if an upstream proxy downgrades requests to HTTP/1.0 |
| `envoy.restart_command` | `restart` if Envoy has no `ExecReload` handler (most setups) |

## Scripts

### `generate.py`

Generates `envoy.yaml` from templates and `config.yaml`. Also creates log directories.

```bash
# Full config with TLS
sudo python3 generate.py

# HTTP-only bootstrap config (use before certs exist)
sudo python3 generate.py --bootstrap

# Preview without writing
python3 generate.py --dry-run

# Generate and restart Envoy
sudo python3 generate.py --reload
```

### `acme.py`

Issues and renews Let's Encrypt certificates via the ACME HTTP-01 challenge.

```bash
# Issue/renew certificates
sudo python3 acme.py

# Test with staging server first (recommended)
sudo python3 acme.py --staging

# Force production server
sudo python3 acme.py --production

# Add new domains to an existing certificate
sudo python3 acme.py --expand

# Install renewal hooks (run once after first cert issuance)
sudo python3 acme.py --install-hook

# Only deploy certs and restart Envoy, skip certbot (used by renewal hook)
sudo python3 acme.py --deploy-only
```

**Renewal hooks** (`--install-hook`) installs three hooks:

| Hook | Location | Purpose |
|---|---|---|
| pre | `/etc/letsencrypt/renewal-hooks/pre/start-webroot.sh` | Starts webroot server before challenge |
| post | `/etc/letsencrypt/renewal-hooks/post/stop-webroot.sh` | Stops webroot server after challenge |
| deploy | `/etc/letsencrypt/renewal-hooks/deploy/envoy-deploy.sh` | Copies certs and restarts Envoy |

After installation, renewals are fully automatic via `certbot.timer`.

### `preflight.py`

Checks all requirements before attempting certificate issuance.

```bash
sudo python3 preflight.py

# Skip DNS/reachability checks (useful in restricted networks)
sudo python3 preflight.py --skip-dns
```

Checks: required binaries, Python modules, config validity, Envoy service status, ports 80/443, directory permissions, DNS resolution, ACME challenge route reachability, renewal hook installation.

## Adding a new domain

```bash
# 1. Add the domain to the relevant host entry in config.yaml
# 2. Regenerate envoy.yaml
sudo python3 generate.py

# 3. Expand the existing certificate
sudo python3 acme.py --expand
```

## Known considerations

**Upstream proxy downgrades to HTTP/1.0** — Some reverse proxies (nginx in certain configurations) forward requests as HTTP/1.0. Enable `http_protocol_options` in `config.yaml` to handle this. The bootstrap template also strips `Upgrade-Insecure-Requests` headers that can cause Envoy to respond with HTTP 426.

**Bootstrap sequence** — Envoy requires certificate files to start in TLS mode. If certificates don't exist yet, generate the bootstrap config first (HTTP only), issue certificates, then switch to the full config.

**OPNsense WAF** — If an OPNsense firewall sits in front of this host with Web Application Firewall rules active, the ACME challenge path `/.well-known/acme-challenge/` must be whitelisted.

## License

MIT
