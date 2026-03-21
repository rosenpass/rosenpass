# Rosenpass + WireGuard + systemd-networkd

This directory contains an example setup for integrating **Rosenpass** post-quantum key exchange with **WireGuard** tunnels managed by **systemd-networkd**.

## Overview

```
 Server                                         Client
+-------------------------------------------+  +-------------------------------------------+
| systemd-networkd                          |  | systemd-networkd                          |
|   wg0.netdev  → creates WireGuard device  |  |   wg0.netdev  → creates WireGuard device  |
|   wg0.network → assigns tunnel IP         |  |   wg0.network → assigns tunnel IP         |
|                                           |  |                                           |
| Rosenpass                                 |  | Rosenpass                                 |
|   config.toml → PSK delivery via wg set   |  |   config.toml → PSK delivery via wg set   |
+--------------------WireGuard tunnel-------+--+-------------------------------------------+
```

systemd-networkd creates and owns the WireGuard device through `.netdev` and
`.network` unit files. Rosenpass runs alongside as a companion service,
performing a post-quantum key exchange and continuously rotating the WireGuard
preshared key (PSK) via `wg set`. The two do not conflict: systemd-networkd
handles device lifecycle and IP configuration, while Rosenpass handles runtime
PSK updates through the WireGuard netlink API.

## Layout

```
systemd-networkd/
  server/
    config.toml          Rosenpass server configuration
  client/
    config.toml          Rosenpass client configuration
  setup.sh               Generate keys, write .netdev/.network, write Rosenpass config
  teardown.sh            Stop services, remove config files
  validate.sh            Check configuration consistency
```

## Prerequisites

- `rosenpass` installed and in `$PATH`
- `wg` (wireguard-tools) installed
- `systemd-networkd` enabled and running
- Kernel WireGuard support
- Root privileges

## Quick start

On **both** machines (server and client):

```bash
# 1. Run the setup script
sudo TUNNEL_IP=10.0.0.1/24 ./setup.sh wg0 server   # on the server
sudo TUNNEL_IP=10.0.0.2/24 ./setup.sh wg0 client   # on the client

# 2. Exchange public keys
#    Copy /etc/rosenpass/wg0/pqpk        → other side's peers/<name>/pqpk
#    Copy /etc/rosenpass/wg0/wg.pub      → use in WireGuard peer config

# 3. Add [WireGuardPeer] to /etc/systemd/network/50-wg0.netdev:
#    [WireGuardPeer]
#    PublicKey=<PEER_WG_PUBLIC_KEY>
#    AllowedIPs=<PEER_TUNNEL_CIDR>
#    Endpoint=<PEER_IP>:<WG_PORT>     # client side only

# 4. Add [[peers]] to /etc/rosenpass/wg0/config.toml (see comments in file)

# 5. Reload systemd-networkd
sudo networkctl reload

# 6. Start Rosenpass
rosenpass exchange-config /etc/rosenpass/wg0/config.toml
# or use the systemd service:
sudo systemctl start rosenpass@wg0
```

## Verifying

```bash
# Check networkd status
networkctl status wg0

# Check WireGuard handshake and PSK
wg show wg0

# Validate config consistency
sudo ./validate.sh wg0
```

## How it works

1. `setup.sh` generates WireGuard and Rosenpass keys, then writes
   systemd-networkd `.netdev` and `.network` files plus a Rosenpass
   `config.toml`.

2. systemd-networkd reads the `.netdev` file and creates the WireGuard
   interface with the configured private key and peer(s). The `.network`
   file assigns the tunnel IP address.

3. Rosenpass performs its post-quantum key exchange and delivers the
   resulting PSK to WireGuard via `wg set <dev> peer <id> preshared-key`.
   Keys are rotated approximately every two minutes.

4. **Important**: Do NOT set `PresharedKey=` in the `.netdev` file.
   Rosenpass manages PSK rotation at runtime. A static PSK in the
   `.netdev` would be overwritten and serves no purpose.

## systemd-networkd-specific considerations

- systemd-networkd `.netdev` files with `Kind=wireguard` support
  `PrivateKeyFile=` for secure key storage (no key in the unit file).
- The `[WireGuardPeer]` section in `.netdev` configures static peer
  information (public key, endpoint, allowed IPs). PSK rotation is
  handled by Rosenpass at runtime, not by networkd.
- Use `networkctl reload` after modifying `.netdev`/`.network` files
  to apply changes without restarting the service.
- Interface lifecycle is tied to networkd. If networkd restarts, it
  recreates the interface. Rosenpass should be configured to restart
  alongside it (the existing `rosenpass@.service` handles this via
  `Restart=on-failure`).
