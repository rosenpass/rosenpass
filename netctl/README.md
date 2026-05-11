# netctl integration for Rosenpass

This directory contains scripts and example profiles for integrating Rosenpass
with [netctl](https://wiki.archlinux.org/title/Netctl), the profile-based
network manager for Arch Linux.

## Overview

netctl manages WireGuard interfaces via `Connection=wireguard` profiles stored
in `/etc/netctl/`. Rosenpass is hooked into the interface lifecycle using
netctl's `ExecUpPost` and `ExecDownPre` directives:

- **rosenpass-setup** — started after the WireGuard interface comes up; launches
  the Rosenpass key exchange daemon in the background.
- **rosenpass-teardown** — called before the interface goes down; gracefully
  stops the Rosenpass daemon.

## Installation

```bash
# Install the hook scripts
install -Dm755 rosenpass-setup   /usr/lib/rosenpass/rosenpass-setup
install -Dm755 rosenpass-teardown /usr/lib/rosenpass/rosenpass-teardown
```

## Usage

1. Create your WireGuard configuration as usual (either inline in the netctl
   profile or via a `WGConfigFile`).

2. Generate Rosenpass keys:
   ```bash
   rosenpass gen-keys \
     --secret-key /etc/rosenpass/wg0/pqsk \
     --public-key /etc/rosenpass/wg0/pqpk
   ```

3. Write a Rosenpass config (see `examples/rosenpass-wg0.toml`).

4. Add the Rosenpass hooks to your netctl profile:
   ```
   ROSENPASS_CONFIG='/etc/rosenpass/wg0.toml'
   ExecUpPost='/usr/lib/rosenpass/rosenpass-setup'
   ExecDownPre='/usr/lib/rosenpass/rosenpass-teardown'
   ```

5. Start the profile:
   ```bash
   netctl start wg0-rosenpass
   ```

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `INTERFACE` | yes (set by netctl) | — | WireGuard interface name |
| `ROSENPASS_CONFIG` | yes | — | Path to Rosenpass TOML config |
| `ROSENPASS_BIN` | no | `rosenpass` | Path to the rosenpass binary |
| `ROSENPASS_PIDFILE` | no | `/run/rosenpass-$INTERFACE.pid` | PID file path |

## Examples

See the `examples/` subdirectory for complete netctl profiles and a matching
Rosenpass configuration file.
