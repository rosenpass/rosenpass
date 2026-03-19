# Rosenpass + WireGuard + Open vSwitch

This directory contains an example setup for integrating **Rosenpass** post-quantum key exchange with **WireGuard** tunnels managed through **Open vSwitch** (OVS).

## Overview

```
 Server                                 Client
+----------------------------+         +----------------------------+
| OVS bridge (br-rp)        |         | OVS bridge (br-rp)        |
|   +--- wg0 (WireGuard) ---|---------|--- wg0 (WireGuard) ---+   |
|   |    PSK via Rosenpass   |  tunnel |    PSK via Rosenpass  |   |
|   +--- other ports ...     |         |     other ports ... --+   |
+----------------------------+         +----------------------------+
```

Rosenpass performs a post-quantum key exchange and continuously rotates the
WireGuard preshared key (PSK). Open vSwitch manages the WireGuard interface
as a port on an OVS bridge, enabling software-defined networking features
such as VLAN tagging, OpenFlow rules, and centralized management via OVSDB.

## Layout

```
openvswitch/
  server/
    config.toml          Rosenpass server configuration
  client/
    config.toml          Rosenpass client configuration
  setup.sh               Create WireGuard interface, OVS bridge, and keys
  teardown.sh            Remove OVS bridge and WireGuard interface
  validate.sh            Check configuration consistency
```

## Prerequisites

- `rosenpass` installed and in `$PATH`
- `wg` (wireguard-tools) installed
- `ovs-vsctl` and `ovsdb-server` (Open vSwitch) installed and running
- Kernel WireGuard support
- Root privileges

## Quick start

On **both** machines (server and client):

```bash
# 1. Run the setup script
sudo ./setup.sh wg0 server   # on the server
sudo ./setup.sh wg0 client   # on the client

# 2. Exchange public keys
#    Copy /etc/rosenpass/wg0/pqpk        -> other side's peers/<name>/pqpk
#    Copy /etc/rosenpass/wg0/wg-*.pub    -> use in WireGuard peer config

# 3. Edit config.toml with the peer's WireGuard public key and endpoint

# 4. Bring the interface up
sudo ip link set wg0 up

# 5. Start Rosenpass
rosenpass exchange-config /etc/rosenpass/wg0/config.toml
# or use the systemd service:
sudo systemctl start rosenpass@wg0
```

## Verifying

```bash
# Check OVS bridge
ovs-vsctl show

# Check WireGuard handshake and PSK
wg show wg0

# Validate config consistency
sudo ./validate.sh wg0
```

## How it works

1. `setup.sh` creates a WireGuard interface, generates Rosenpass and WireGuard
   keys, then creates an OVS bridge and adds the WireGuard interface as a port.

2. Rosenpass runs its post-quantum key exchange protocol and delivers the
   resulting PSK to WireGuard via `wg set <dev> peer <id> preshared-key`.
   This happens continuously -- keys are rotated every two minutes.

3. OVS treats the WireGuard interface like any other port. You can apply VLAN
   tags, OpenFlow rules, or mirror traffic as needed. OVS does not interfere
   with the key exchange; it only sees encrypted WireGuard packets.

## OVS-specific considerations

- The WireGuard interface is added as an **OVS port**, not an OVS internal
  interface. WireGuard manages its own interface type.
- If you need VLAN tagging on the tunnel, set it on the OVS port:
  ```bash
  ovs-vsctl set port wg0 tag=100
  ```
- For OpenFlow-based routing, use `ovs-ofctl` to add flow rules to `br-rp`.
- OVS configuration persists in `ovsdb-server` across reboots. WireGuard and
  Rosenpass configuration is managed separately via their config files and
  systemd units.
