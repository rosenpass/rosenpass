# Rosenpass NetworkManager Plugin

This plugin provides NetworkManager integration for Rosenpass post-quantum secure key exchange.

## Overview

The NetworkManager plugin allows Rosenpass to be managed through NetworkManager's D-Bus interface, enabling seamless integration with Linux desktop environments and system management tools.

## Features

- D-Bus service integration with NetworkManager
- Automatic WireGuard interface management
- Post-quantum secure key exchange for VPN connections
- Configuration through NetworkManager connection profiles
- Support for both system and user connections

## Installation

```bash
cargo build --release
sudo cp target/release/rosenpass-nm-plugin /usr/libexec/
```

## Configuration

The plugin reads configuration from NetworkManager connection profiles with the following structure:

```toml
[rosenpass]
public_key = "/path/to/public.key"
secret_key = "/path/to/secret.key"
listen_port = 9999
peer_endpoint = "peer.example.com:9999"
peer_public_key = "/path/to/peer/public.key"
```

## D-Bus Interface

The plugin exposes the following D-Bus interface:

- **Service**: `eu.rosenpass.NetworkManager`
- **Object Path**: `/eu/rosenpass/NetworkManager`
- **Interface**: `eu.rosenpass.NetworkManager.Plugin`

### Methods

- `ActivateConnection(connection_uuid: s) -> ()`
- `DeactivateConnection(connection_uuid: s) -> ()`
- `GetConnectionStatus(connection_uuid: s) -> (status: s)`

### Signals

- `ConnectionStateChanged(connection_uuid: s, state: s)`

## Usage

The plugin is typically started automatically by NetworkManager when a Rosenpass-enabled connection is activated.

Manual testing:
```bash
rosenpass-nm-plugin --config /etc/NetworkManager/rosenpass.toml
```

## Architecture

The plugin consists of:

1. **D-Bus Service**: Communicates with NetworkManager
2. **Connection Manager**: Handles Rosenpass connection lifecycle
3. **WireGuard Broker**: Manages WireGuard PSK updates
4. **Configuration Parser**: Processes NetworkManager connection profiles