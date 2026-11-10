# envoy-gen

A lightweight toolchain for generating [Envoy](https://www.envoyproxy.io/) reverse proxy configurations and managing [Let's Encrypt](https://letsencrypt.org/) TLS certificates — designed for Envoy instances running as a systemd service in front of a Kubernetes cluster.

## Overview

`envoy-gen` solves a specific problem: managing Envoy configurations across multiple systems with different hostnames, active services, and certificate setups — without editing YAML by hand each time.

Everything is driven by a single `config.yaml`. All scripts read from it, so there is one place to change things.

```
envoy-gen/
├── config.example.yaml              # Example configuration (copy to config.yaml)
├── config.yaml                      # Your host-specific configuration (not in git)
├── generate.py                      # Generates envoy.yaml from templates
├── acme.py                          # Issues and renews Let's Encrypt certificates
├── common.py                        # Shared helpers (certificate selection, paths, checks)
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

### Create your configuration

`config.yaml` is host-specific and therefore **not** part of the repository (it is listed in `.gitignore`). Create it from the example and adapt it:

```bash
cp config.example.yaml config.yaml
nano config.yaml
```

Because the file is untracked, `git pull` never overwrites or conflicts with it.


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

# Skip the certificate verification
sudo python3 generate.py --skip-cert-check
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

## Keycloak (Open-Xchange login)

If Keycloak is deployed together with Open-Xchange, it listens on its own NodePort (default `31537`; Open-Xchange stays on `30080`) and is reached under its own hostname (default `keycloak.domain.example`). Enable it in `config.yaml`:

```yaml
keycloak:
  enabled: true
  domains:
    - keycloak.example.com
  upstream:
    # address: 10.0.0.1       # optional, default: envoy.upstream.address
    port: 31537
  letsencrypt: true           # only relevant when letsencrypt.all_hosts is false
  cert:                       # only for certificates.mode: per_host
    fullchain: keycloak-tls.fullchain.pem
    privkey:   keycloak-tls.privkey.pem
```

Keycloak then behaves like an additional host with its own upstream:

- own HTTPS filter chain (SNI match on `keycloak.domains`) routing to a separate `keycloak-http` cluster
- own certificate: the `cert` block in `per_host` mode, the shared certificate in `shared` mode (it must then also cover the Keycloak hostname — `generate.py` warns if it does not)
- takes part in the Let's Encrypt selection: with `all_hosts: true` it always gets a Let's Encrypt certificate, with `all_hosts: false` only if `letsencrypt: true` is set
- `acme.py` and `preflight.py` include the Keycloak hostname automatically (DNS check, certificate issuance, certificate verification)

With `enabled: false` (default) nothing Keycloak-related is generated. The name `keycloak` is reserved and cannot be used for an entry in `hosts`. Envoy talks plain HTTP to the Keycloak upstream, like for Open-Xchange.

## Using your own certificates (no Let's Encrypt)

Each enabled host gets its certificate from one of two sources: **Let's Encrypt** (managed by `acme.py`) or **provided** files that you supply yourself, for example from an internal CA or a commercial certificate. Both can be combined.

### Only provided certificates

```yaml
letsencrypt:
  enabled: false                  # the whole letsencrypt section may be omitted

certificates:
  mode: per_host                  # or "shared" for a single certificate
  cert_dir: /usr/local/etc/envoy

hosts:
  - name: main
    domains: [example.com, dav.example.com]
    cert:
      fullchain: main.fullchain.pem                 # relative -> cert_dir
      privkey:   /etc/ssl/private/main.key          # absolute path is used as it is
  - name: grafana
    domains: [grafana.example.com]
    cert:
      fullchain: grafana.fullchain.pem
      privkey:   grafana.key
```

Copy the files to the configured locations, then:

```bash
sudo python3 generate.py          # no --bootstrap needed
sudo systemctl restart envoy
```

`fullchain` must contain the server certificate first, followed by the intermediates. `acme.py` has nothing to do in this mode and exits with a message.

### Mixing Let's Encrypt and provided certificates

```yaml
letsencrypt:
  enabled: true
  all_hosts: false                # decide per host
  ...

hosts:
  - name: main
    letsencrypt: true             # issued and renewed by acme.py
    ...
  - name: legacy
    letsencrypt: false            # uses the provided files in its cert block
    cert:
      fullchain: legacy.fullchain.pem
      privkey:   legacy.key
```

`acme.py` only touches the hosts with `letsencrypt: true`; the files of all other hosts are never modified. The ACME challenge route is only added to the Envoy config if at least one host uses Let's Encrypt.

### Certificate verification

Before writing a full `envoy.yaml`, `generate.py` checks every certificate/key pair (using `openssl`):

| Check | Result |
|---|---|
| Files exist and are readable | error |
| Private key matches the certificate | error |
| Certificate is not expired | error |
| Certificate expires within 14 days | warning |
| Every host domain is covered by the certificate SANs (wildcards supported) | warning |

An error aborts the run and `envoy.yaml` is **not** written, so a broken certificate never reaches a running Envoy. `--skip-cert-check` overrides this, for example to generate the file before the certificates have been copied. `preflight.py` runs the same checks.

## Updating an installation

```bash
cd /opt/envoy-gen
git pull
sudo python3 acme.py --install-hook   # rewrites the renewal hooks (Let's Encrypt only)
sudo python3 generate.py --reload     # regenerate envoy.yaml and restart Envoy
```

New options are documented in `config.example.yaml`. Compare it with your `config.yaml` after an update:

```bash
diff config.example.yaml config.yaml
```

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
