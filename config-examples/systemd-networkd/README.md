# Rosenpass + systemd-networkd example

This directory contains an example setup for integrating **Rosenpass** with **systemd-networkd** using WireGuard as the data channel.

The goals of this example are to:
- let Rosenpass manage WireGuard keys,
- keep systemd-networkd responsible for interface configuration and routing,
- avoid static `PresharedKey` values drifting out of sync with Rosenpass.

## Layout

The directory is structured as follows:

- `client/`
  - `config.toml` – example Rosenpass client configuration.
  - `wg0.netdev` – WireGuard netdev for the client side.
  - `wg0.network` – network configuration (addresses, routes, etc.) for the client.

- `server/`
  - `config.toml` – example Rosenpass server configuration.
  - `rosenpass-networkd@.service` – systemd template unit that binds Rosenpass to a specific WireGuard interface (for example `wg0`).
  - `wg0.netdev` – WireGuard netdev for the server side.
  - `wg0.network` – network configuration for the server.

- `setup.sh` – helper script to scaffold configuration and keys for a given interface.
- `validate.sh` – validation script that checks consistency between Rosenpass and systemd-networkd configuration.

## Prerequisites

- Rosenpass installed and available in `$PATH`.
- WireGuard support in the kernel and tools installed.
- `systemd-networkd` enabled and managing your network interfaces.
- Root privileges (or `sudo`) to write into `/etc` and manage systemd units.

## Usage

The example assumes an interface name of `wg0`. You can adjust this if needed.

1. **Copy the example directory**

   ```bash
   sudo mkdir -p /etc/rosenpass/systemd-networkd
   sudo cp -r config-examples/systemd-networkd/* /etc/rosenpass/systemd-networkd/
   cd /etc/rosenpass/systemd-networkd
