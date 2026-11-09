# envoy-gen

A small generator that builds an `envoy.yaml` from a `config.yaml` and Jinja2 templates.
All scripts share the same `config.yaml` as single source of truth.

## Directory Structure

```
envoy-gen/
├── config.yaml                      # Shared configuration input for all scripts
├── generate.py                      # Envoy config generator
├── acme.py                          # Let's Encrypt certificate manager
├── README.md
└── templates/
    ├── envoy.yaml.j2                # Full config template (HTTP + TLS)
    └── envoy.bootstrap.yaml.j2     # Bootstrap template (HTTP only, no TLS)
```

## Requirements

```bash
apt install python3-pip
pip3 install jinja2 pyyaml
```

## Initial Setup (first deployment)

Certificates do not exist yet — Envoy cannot start with TLS. Use bootstrap mode:

```bash
# 1. Generate HTTP-only config (no certificates required)
sudo python3 generate.py --bootstrap

# 2. Start envoy — works without certificates
sudo systemctl restart envoy

# 3. Issue certificates via ACME
sudo python3 acme.py

# 4. Generate full config with TLS
sudo python3 generate.py

# 5. Reload envoy — TLS now active
sudo systemctl reload envoy
```

## generate.py Usage

```bash
# Generate full config and set up log directory (requires root)
sudo python3 generate.py

# Bootstrap mode: HTTP only, no TLS (use before certificates exist)
sudo python3 generate.py --bootstrap

# Dry-run: print generated config to stdout without writing files
python3 generate.py --dry-run

# Custom config and output paths
sudo python3 generate.py --config /path/to/config.yaml --output /etc/envoy/envoy.yaml

# Skip log directory creation
sudo python3 generate.py --no-logdir

# Validate with envoy binary after generation
sudo python3 generate.py --validate

# Validate and reload envoy service after generation
sudo python3 generate.py --reload
```

## acme.py Usage

```bash
# Issue/renew certs for all qualifying hosts and reload envoy
sudo python3 acme.py

# Dry-run: show what would happen without making changes
python3 acme.py --dry-run

# Custom config path
sudo python3 acme.py --config /path/to/config.yaml

# Skip envoy reload after deployment
sudo python3 acme.py --no-reload

# Skip built-in webroot server (if another server is already running on acme_port)
sudo python3 acme.py --no-webroot-server
```

## Configuration Reference (`config.yaml`)

### `envoy`
| Key | Description |
|---|---|
| `log_dir` | Path where access log files are created |
| `service_user` | OS user that owns the log directory |
| `upstream.address` | IP of the Kubernetes NodePort upstream |
| `upstream.port` | Port of the Kubernetes NodePort upstream |

### `letsencrypt`
| Key | Description |
|---|---|
| `enabled` | `true` / `false` — master switch for all LE/ACME functionality |
| `acme_port` | Local port where certbot webroot server listens |
| `email` | Email address for certbot account registration |
| `webroot_dir` | Local directory served by the certbot webroot server |
| `all_hosts` | `true` = all enabled hosts get a LE cert / `false` = per-host control |

### `certificates`
| Key | Description |
|---|---|
| `mode` | `shared` — one cert for all hosts / `per_host` — individual cert per host |
| `cert_dir` | Directory where certificate files are stored |
| `shared.fullchain` | (shared mode only) fullchain PEM filename |
| `shared.privkey` | (shared mode only) private key PEM filename |

### `hosts`
Each entry generates one `filter_chain` block in the HTTPS listener.

| Key | Description |
|---|---|
| `name` | Identifier (used in comments) |
| `domains` | List of SNI domain names for this chain |
| `enabled` | `true` / `false` — exclude host from generated config when false |
| `letsencrypt` | `true` / `false` — issue LE cert for this host (only when `all_hosts: false`) |
| `cert.fullchain` | (per_host mode) fullchain PEM filename |
| `cert.privkey` | (per_host mode) private key PEM filename |

## Certificate Target Selection

| `letsencrypt.all_hosts` | Behaviour |
|---|---|
| `true` | Every `enabled: true` host gets a LE certificate |
| `false` | Only hosts with `letsencrypt: true` get a LE certificate |
