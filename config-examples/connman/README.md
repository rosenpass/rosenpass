# Rosenpass + WireGuard + ConnMan

This directory contains an example setup for integrating **Rosenpass** post-quantum key exchange with **WireGuard** tunnels managed by **ConnMan**.

## Overview

```
 Server                                         Client
+-------------------------------------------+  +-------------------------------------------+
| ConnMan + connman-vpn                     |  | ConnMan + connman-vpn                     |
|   wg0.config → VPN provisioning file      |  |   wg0.config → VPN provisioning file      |
|   creates & manages WireGuard interface   |  |   creates & manages WireGuard interface   |
|                                           |  |                                           |
| Rosenpass                                 |  | Rosenpass                                 |
|   config.toml → PSK delivery via wg set   |  |   config.toml → PSK delivery via wg set   |
+--------------------WireGuard tunnel-------+--+-------------------------------------------+
```

ConnMan manages WireGuard VPN connections through provisioning files placed in
`/var/lib/connman-vpn/`. Its VPN daemon (`connman-vpnd`) reads these files and
creates the WireGuard interface with the specified private key, endpoint, and
peer configuration. Rosenpass runs alongside as a companion service, performing
a post-quantum key exchange and continuously rotating the WireGuard preshared
key (PSK) via `wg set`.

## Layout

```
connman/
  server/
    config.toml          Rosenpass server configuration
  client/
    config.toml          Rosenpass client configuration
  setup.sh               Generate keys, write ConnMan provisioning file, write Rosenpass config
  teardown.sh            Stop services, remove provisioning files
  validate.sh            Check configuration consistency
```

## Prerequisites

- `rosenpass` installed and in `$PATH`
- `wg` (wireguard-tools) installed
- `connman` and `connman-vpn` enabled and running
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

# 3. Update ConnMan provisioning file with peer info:
#    Edit /var/lib/connman-vpn/wg0.config, uncomment and fill in:
#    WireGuard.PublicKey = <PEER_WG_PUBLIC_KEY>
#    WireGuard.AllowedIPs = <PEER_TUNNEL_CIDR>
#    WireGuard.EndpointPort = <PEER_WG_PORT>     # client side only

# 4. Add [[peers]] to /etc/rosenpass/wg0/config.toml (see comments in file)

# 5. Restart ConnMan VPN daemon
sudo systemctl restart connman-vpn

# 6. Start Rosenpass
rosenpass exchange-config /etc/rosenpass/wg0/config.toml
# or use the systemd service:
sudo systemctl start rosenpass@wg0
```

## Verifying

```bash
# Check ConnMan VPN services
connmanctl services

# Check WireGuard handshake and PSK
wg show wg0

# Validate config consistency
sudo ./validate.sh wg0
```

## How it works

1. `setup.sh` generates WireGuard and Rosenpass keys, then writes a ConnMan
   VPN provisioning file plus a Rosenpass `config.toml`.

2. ConnMan's VPN daemon (`connman-vpnd`) reads the provisioning file from
   `/var/lib/connman-vpn/` and creates the WireGuard interface with the
   configured private key and peer(s).

3. Rosenpass performs its post-quantum key exchange and delivers the
   resulting PSK to WireGuard via `wg set <dev> peer <id> preshared-key`.
   Keys are rotated approximately every two minutes.

4. **Important**: Do NOT set `WireGuard.PresharedKey` in the provisioning
   file. Rosenpass manages PSK rotation at runtime. A static PresharedKey
   would be immediately overwritten and serves no purpose.

## ConnMan-specific considerations

### PSK rotation and ConnMan

ConnMan's WireGuard provisioning format supports a static
`WireGuard.PresharedKey` field, but this key is only applied once when the
VPN connection is established. Rosenpass rotates PSKs approximately every
two minutes via `wg set`, which writes directly to the WireGuard kernel
module through netlink. ConnMan does not interfere with these runtime
updates -- once the interface exists, `wg set` operates independently of
ConnMan's state.

If ConnMan reconnects the VPN (e.g., after a network change), it will
re-apply the provisioning file. Since we leave `WireGuard.PresharedKey`
unset, ConnMan will create the interface without a PSK, and Rosenpass will
deliver a fresh one on the next key exchange cycle. There is a brief window
(seconds) between reconnection and PSK delivery where the tunnel runs
without a PSK -- this is acceptable because WireGuard's own Noise protocol
still provides strong encryption; the PSK is an additional post-quantum
hardening layer.

### connman-vpnd

ConnMan delegates VPN management to a separate daemon, `connman-vpnd`. Make
sure the `connman-vpn` systemd unit is enabled and running. Without it,
provisioning files in `/var/lib/connman-vpn/` are ignored.

### Provisioning file format

ConnMan provisioning files use INI-style syntax. The `[provider_<name>]`
section header identifies the VPN connection. Key fields for WireGuard:

- `Type = WireGuard` (required)
- `Host` -- remote endpoint IP (client side) or `0.0.0.0` (server side)
- `WireGuard.Address` -- tunnel IP with CIDR prefix
- `WireGuard.PrivateKey` -- WireGuard private key (plaintext in file; ensure 0600 permissions)
- `WireGuard.ListenPort` -- server listen port
- `WireGuard.PublicKey` -- peer's WireGuard public key
- `WireGuard.AllowedIPs` -- allowed IP ranges for the peer
- `WireGuard.EndpointPort` -- peer's WireGuard port (client side)

### File permissions

The provisioning file contains the WireGuard private key in plaintext.
The setup script sets permissions to `0600`. The validate script checks this.
