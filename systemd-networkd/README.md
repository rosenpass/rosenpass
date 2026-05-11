# systemd-networkd integration for Rosenpass

This directory contains systemd unit files and example configurations for
integrating Rosenpass with [systemd-networkd](https://www.freedesktop.org/software/systemd/man/systemd-networkd.html),
the network manager built into systemd.

## Overview

systemd-networkd manages WireGuard interfaces via `.netdev` and `.network` files
in `/etc/systemd/network/`. Rosenpass is started after the WireGuard interface
comes up, using a template service unit that binds to the network device:

- **rosenpass-networkd@.service** — template unit that starts the Rosenpass key
  exchange daemon for a given WireGuard interface. It binds to the device so
  that stopping or removing the interface also stops Rosenpass.

## Installation

```bash
# Install the systemd service unit
install -Dm644 rosenpass-networkd@.service /usr/lib/systemd/system/rosenpass-networkd@.service

# Install the shared rosenpass.target (if not already installed)
install -Dm644 ../systemd/rosenpass.target /usr/lib/systemd/system/rosenpass.target

# Reload systemd
systemctl daemon-reload
```

## Usage

1. Create your WireGuard `.netdev` and `.network` files in `/etc/systemd/network/`
   (see `examples/wg0.netdev` and `examples/wg0.network`).

2. Generate Rosenpass keys:
   ```bash
   rosenpass gen-keys \
     --secret-key /etc/rosenpass/wg0/pqsk \
     --public-key /etc/rosenpass/wg0/pqpk
   ```

3. Write a Rosenpass config (see `examples/rosenpass-wg0.toml`) and place it at
   `/etc/rosenpass/wg0.toml` (the filename must match the interface name).

4. Enable and start the service:
   ```bash
   systemctl enable --now rosenpass-networkd@wg0.service
   ```

   The service will automatically start when the `wg0` interface appears and
   stop when it is removed.

5. Restart networkd to bring up the interface:
   ```bash
   systemctl restart systemd-networkd
   ```

## How it works

The `rosenpass-networkd@.service` unit uses `BindsTo=sys-subsystem-net-devices-%i.device`
to tie its lifecycle to the WireGuard interface. When systemd-networkd creates
the interface from the `.netdev` file, systemd detects the device and the
rosenpass service can start. When the interface is removed, the service stops
automatically.

The service reads its configuration from `/etc/rosenpass/%i.toml` and loads
the secret key via systemd's `LoadCredential=` mechanism from
`/etc/rosenpass/%i/pqsk`.

## Security hardening

The service unit includes the same security hardening as the existing
`rosenpass@.service` unit:
- `DynamicUser=true` — runs as an ephemeral unprivileged user
- Minimal capability set (only `CAP_NET_ADMIN`)
- Filesystem, network, and syscall restrictions

## Examples

See the `examples/` subdirectory for:
- `wg0.netdev` — client-side WireGuard interface definition
- `wg0-server.netdev` — server-side WireGuard interface definition
- `wg0.network` — network configuration (addresses and routes)
- `rosenpass-wg0.toml` — Rosenpass daemon configuration
