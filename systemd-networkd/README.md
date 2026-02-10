# Rosenpass with systemd-networkd

This directory contains systemd service files, example configurations, and a
setup script for running Rosenpass alongside WireGuard interfaces managed by
[systemd-networkd](https://www.freedesktop.org/software/systemd/man/latest/systemd-networkd.html).

## Overview

systemd-networkd can natively create and configure WireGuard interfaces using
`.netdev` and `.network` files. Rosenpass adds post-quantum security on top of
WireGuard by continuously rotating the pre-shared key (PSK) that WireGuard uses
for an additional layer of symmetric encryption.

The integration works as follows:

1. **systemd-networkd** creates the WireGuard device (via the `.netdev` file)
   and configures addressing (via the `.network` file).
2. **Rosenpass** performs a post-quantum key exchange with the remote peer and
   supplies the resulting symmetric key to WireGuard as a PSK using `wg set`.
   This key is rotated approximately every two minutes.
3. The **`rosenpass-networkd@.service`** template ties the Rosenpass daemon to
   the systemd-networkd managed interface, ensuring correct startup ordering
   and lifecycle management.

Because Rosenpass provides keys through WireGuard's PSK mechanism, using
Rosenpass is cryptographically no less secure than using WireGuard alone
("hybrid security"). If the post-quantum key exchange were somehow broken,
WireGuard's own Curve25519-based key exchange still protects the tunnel.

## Quick Start

### Prerequisites

- A Linux system running systemd-networkd
- `rosenpass` and `wg` (wireguard-tools) installed
- Root access

### Automated Setup

The `setup-rosenpass-networkd.sh` script generates all configuration files:

```sh
sudo ./setup-rosenpass-networkd.sh rp0
```

This creates:
- `/etc/systemd/network/rp0.netdev` -- WireGuard device definition
- `/etc/systemd/network/rp0.network` -- Network addressing
- `/etc/rosenpass/rp0.toml` -- Rosenpass configuration
- `/etc/rosenpass/rp0/pqsk` -- Rosenpass secret key
- `/etc/rosenpass/rp0/pqpk` -- Rosenpass public key
- `/etc/wireguard/rp0.key` -- WireGuard private key
- `/etc/wireguard/rp0.pub` -- WireGuard public key

### Manual Setup

#### 1. Generate keys

```sh
# WireGuard keys
wg genkey | sudo tee /etc/wireguard/rp0.key | wg pubkey | sudo tee /etc/wireguard/rp0.pub
sudo chmod 0600 /etc/wireguard/rp0.key

# Rosenpass keys
sudo mkdir -p /etc/rosenpass/rp0/peers
sudo rosenpass gen-keys --secret-key /etc/rosenpass/rp0/pqsk \
                        --public-key /etc/rosenpass/rp0/pqpk
sudo chmod 0600 /etc/rosenpass/rp0/pqsk
```

#### 2. Create the .netdev file

Create `/etc/systemd/network/rp0.netdev`:

```ini
[NetDev]
Name=rp0
Kind=wireguard

[WireGuard]
PrivateKeyFile=/etc/wireguard/rp0.key
ListenPort=51820

[WireGuardPeer]
PublicKey=<PEER_WG_PUBLIC_KEY>
Endpoint=<PEER_IP>:51820
AllowedIPs=10.0.0.2/32
PersistentKeepalive=25
# Do NOT set PresharedKey -- Rosenpass manages it.
```

**Important:** Do not set `PresharedKey` or `PresharedKeyFile` in the
`[WireGuardPeer]` section. Rosenpass rotates the PSK automatically using
`wg set`.

#### 3. Create the .network file

Create `/etc/systemd/network/rp0.network`:

```ini
[Match]
Name=rp0

[Network]
Address=10.0.0.1/24
```

#### 4. Create the Rosenpass configuration

Create `/etc/rosenpass/rp0.toml`:

```toml
public_key = "/etc/rosenpass/rp0/pqpk"
secret_key = "/etc/rosenpass/rp0/pqsk"
listen = ["0.0.0.0:9999"]
verbosity = "Quiet"

[[peers]]
public_key = "/etc/rosenpass/rp0/peers/peer1-pqpk"
endpoint = "<PEER_IP>:9999"
device = "rp0"
peer = "<PEER_WG_PUBLIC_KEY>"
```

Copy the remote peer's Rosenpass public key to
`/etc/rosenpass/rp0/peers/peer1-pqpk`.

#### 5. Install the service template and start

```sh
sudo cp rosenpass-networkd@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl restart systemd-networkd
sudo systemctl enable --now rosenpass-networkd@rp0.service
```

#### 6. Verify

```sh
# Check the Rosenpass service
systemctl status rosenpass-networkd@rp0.service

# Check the WireGuard interface
wg show rp0

# Watch PSK rotation (updates every ~2 minutes)
watch -n 5 'wg show rp0 preshared-keys'
```

## Two-Peer Example

See the `examples/` directory for a complete two-peer setup:

- **Peer A** (server at 198.51.100.1): `peer-a.netdev`, `peer-a.network`,
  `peer-a-rosenpass.toml`
- **Peer B** (client): `peer-b.netdev`, `peer-b.network`,
  `peer-b-rosenpass.toml`

### On Peer A (server)

```sh
# 1. Generate keys
sudo ./setup-rosenpass-networkd.sh rp0

# 2. Edit /etc/systemd/network/rp0.netdev: add Peer B's WireGuard public key
# 3. Edit /etc/systemd/network/rp0.network: set Address=10.0.0.1/24
# 4. Edit /etc/rosenpass/rp0.toml: add listen, peer section with Peer B's keys
# 5. Copy Peer B's Rosenpass public key to /etc/rosenpass/rp0/peers/peer-b-pqpk

sudo systemctl daemon-reload
sudo systemctl restart systemd-networkd
sudo systemctl enable --now rosenpass-networkd@rp0.service
```

### On Peer B (client)

```sh
# 1. Generate keys
sudo ./setup-rosenpass-networkd.sh rp0

# 2. Edit /etc/systemd/network/rp0.netdev: add Peer A's WireGuard public key, endpoint
# 3. Edit /etc/systemd/network/rp0.network: set Address=10.0.0.2/24
# 4. Edit /etc/rosenpass/rp0.toml: add peer section with Peer A's keys + endpoint
# 5. Copy Peer A's Rosenpass public key to /etc/rosenpass/rp0/peers/peer-a-pqpk

sudo systemctl daemon-reload
sudo systemctl restart systemd-networkd
sudo systemctl enable --now rosenpass-networkd@rp0.service
```

### Test

```sh
# From Peer B
ping 10.0.0.1
```

## How It Works

### Service Lifecycle

The `rosenpass-networkd@.service` template uses systemd dependency management
to ensure correct ordering:

- **`After=systemd-networkd.service`**: Rosenpass starts only after
  systemd-networkd is running.
- **`BindsTo=sys-subsystem-net-devices-%i.device`**: Rosenpass is bound to the
  network interface. If the interface disappears (e.g., systemd-networkd
  reconfigures), Rosenpass stops.
- **`Requires=systemd-networkd.service`**: If systemd-networkd stops,
  Rosenpass stops too.
- **`PartOf=rosenpass.target`**: All Rosenpass instances can be managed
  together via the rosenpass.target.

### Key Rotation

Rosenpass performs a key exchange approximately every two minutes and writes
the resulting symmetric key to WireGuard as a pre-shared key using:

```
wg set <INTERFACE> peer <PEER_PUBLIC_KEY> preshared-key /dev/stdin
```

This is the same mechanism used by the standalone `rosenpass` tool and is
fully compatible with systemd-networkd managed interfaces because
systemd-networkd only sets the initial device configuration -- runtime PSK
updates via `wg set` work independently.

### Security Hardening

The service template includes the same security hardening as the existing
`rosenpass@.service`:

- Runs as a dynamic user (no persistent system user needed)
- Minimal capability set (only `CAP_NET_ADMIN`)
- System call filtering, namespace restrictions, and device access controls
- Protected kernel tunables, control groups, and home directory

## Differences from Standalone Rosenpass

| Feature | `rosenpass@.service` | `rosenpass-networkd@.service` |
|---|---|---|
| WireGuard device creation | Rosenpass (or `rp`) creates the device | systemd-networkd creates the device |
| Device lifecycle | Rosenpass owns the device | systemd-networkd owns the device |
| Address configuration | Manual (`ip addr add`) or via `rp` | systemd-networkd (`.network` file) |
| Routing | Manual or via `rp` | systemd-networkd (`.network` file) |
| Service dependency | Binds to the device | Binds to device + systemd-networkd |

## Troubleshooting

### Rosenpass fails to start (interface not found)

Make sure the `.netdev` file name matches the interface name in
`systemctl enable rosenpass-networkd@<NAME>`:

```sh
# If your .netdev creates "rp0", use:
systemctl enable --now rosenpass-networkd@rp0.service
```

### PSK is not being updated

Check Rosenpass logs:

```sh
journalctl -u rosenpass-networkd@rp0.service -f
```

Verify the WireGuard peer public key in the Rosenpass config matches the one
in the `.netdev` file:

```sh
wg show rp0
grep peer /etc/rosenpass/rp0.toml
```

### systemd-networkd not picking up configuration

After creating or modifying `.netdev`/`.network` files:

```sh
sudo systemctl restart systemd-networkd
# or
sudo networkctl reload
```

## File Layout

```
/etc/
  systemd/
    network/
      rp0.netdev          # WireGuard device (systemd-networkd)
      rp0.network         # Network config (systemd-networkd)
    system/
      rosenpass-networkd@.service  # Rosenpass service template
  rosenpass/
    rp0.toml              # Rosenpass configuration
    rp0/
      pqsk                # Rosenpass secret key (mode 0600)
      pqpk                # Rosenpass public key
      peers/
        peer1-pqpk        # Remote peer's Rosenpass public key
  wireguard/
    rp0.key               # WireGuard private key (mode 0600)
    rp0.pub               # WireGuard public key
```
