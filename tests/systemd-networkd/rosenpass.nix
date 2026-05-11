# NixOS integration test for the systemd-networkd + Rosenpass integration.
#
# This test verifies that:
# 1. A WireGuard interface can be brought up via systemd-networkd (.netdev/.network)
# 2. The rosenpass-networkd@.service starts after the interface appears
# 3. Preshared keys are exchanged between peers
# 4. Network connectivity works over the WireGuard tunnel
#
# Run with: nix build .#checks.<system>.systemd-networkd
{ pkgs, ... }:

let
  server = {
    ip4 = "192.168.0.1";
    ip6 = "fd00::1";
    wg = {
      ip4 = "10.23.42.1";
      ip6 = "fc00::1";
      public = "mQufmDFeQQuU/fIaB2hHgluhjjm1ypK4hJr1cW3WqAw=";
      secret = "4N5Y1dldqrpsbaEiY8O0XBUGUFf8vkvtBtm8AoOX7Eo=";
      listen = 10000;
    };
  };

  client = {
    ip4 = "192.168.0.2";
    ip6 = "fd00::2";
    wg = {
      ip4 = "10.23.42.2";
      ip6 = "fc00::2";
      public = "Mb3GOlT7oS+F3JntVKiaD7SpHxLxNdtEmWz/9FMnRFU=";
      secret = "uC5dfGMv7Oxf5UDfdPkj6rZiRZT2dRWp5x8IQxrNcUE=";
    };
  };

  server_rp_config = {
    listen = [ "0.0.0.0:9999" ];
    public_key = "/etc/rosenpass/wg0/pqpk";
    secret_key = "/etc/rosenpass/wg0/pqsk";
    verbosity = "Verbose";
    peers = [
      {
        public_key = "/etc/rosenpass/wg0/peers/client/pqpk";
        exchange_command = [
          "wg" "set" "wg0" "peer" client.wg.public "preshared-key" "/dev/stdin"
        ];
      }
    ];
  };

  client_rp_config = {
    listen = [ ];
    public_key = "/etc/rosenpass/wg0/pqpk";
    secret_key = "/etc/rosenpass/wg0/pqsk";
    verbosity = "Verbose";
    peers = [
      {
        public_key = "/etc/rosenpass/wg0/peers/server/pqpk";
        endpoint = "${server.ip4}:9999";
        exchange_command = [
          "wg" "set" "wg0" "peer" server.wg.public "preshared-key" "/dev/stdin"
        ];
      }
    ];
  };

  rpConfig = pkgs.runCommand "rp-config" { } ''
    mkdir -pv $out
    cp -v ${(pkgs.formats.toml { }).generate "wg0.toml" server_rp_config} $out/server
    cp -v ${(pkgs.formats.toml { }).generate "wg0.toml" client_rp_config} $out/client
  '';
in
{
  name = "systemd-networkd-rosenpass";

  nodes =
    let
      shared =
        peer: remotePeer:
        { pkgs, ... }:
        {
          environment.systemPackages = [ pkgs.wireguard-tools ];

          # Use systemd-networkd for network management
          networking.useNetworkd = true;
          systemd.network.enable = true;

          # Disable default NixOS networking for the WireGuard interface
          # (we manage it via systemd-networkd .netdev/.network files)

          # Physical network interface
          networking.interfaces.eth1 = {
            ipv4.addresses = [
              {
                address = peer.ip4;
                prefixLength = 24;
              }
            ];
            ipv6.addresses = [
              {
                address = peer.ip6;
                prefixLength = 64;
              }
            ];
          };

          # WireGuard .netdev configuration via systemd-networkd
          systemd.network.netdevs."90-wg0" = {
            netdevConfig = {
              Name = "wg0";
              Kind = "wireguard";
              Description = "WireGuard tunnel with Rosenpass";
            };
            wireguardConfig = {
              PrivateKeyFile = "/etc/wireguard/wg0-private-key";
            } // (if peer.wg ? listen then {
              ListenPort = peer.wg.listen;
            } else { });
            wireguardPeers = [
              {
                wireguardPeerConfig = {
                  PublicKey = remotePeer.wg.public;
                  AllowedIPs = [ "${remotePeer.wg.ip4}/32" "${remotePeer.wg.ip6}/128" ];
                  PersistentKeepalive = 25;
                } // (if remotePeer ? ip4 && remotePeer.wg ? listen then {
                  Endpoint = "${remotePeer.ip4}:${toString remotePeer.wg.listen}";
                } else { });
              }
            ];
          };

          # WireGuard .network configuration
          systemd.network.networks."90-wg0" = {
            matchConfig.Name = "wg0";
            address = [
              "${peer.wg.ip4}/24"
              "${peer.wg.ip6}/64"
            ];
            networkConfig = {
              IPForward = true;
            };
          };

          # Install the rosenpass-networkd@ service unit
          systemd.packages = [
            (pkgs.runCommand "rosenpass-networkd" { } ''
              mkdir -p $out/lib/systemd/system
              < ${pkgs.rosenpass}/lib/systemd/system/rosenpass.target > $out/lib/systemd/system/rosenpass.target
              < ${pkgs.rosenpass.src}/systemd-networkd/rosenpass-networkd@.service \
              sed 's@^ExecStart=rosenpass @ExecStart='"${pkgs.rosenpass}"'/bin/rosenpass @' |
              sed 's@^\(\[Service]\)$@\1\nEnvironment=PATH=${pkgs.wireguard-tools}/bin@' \
              > $out/lib/systemd/system/rosenpass-networkd@.service
            '')
          ];

          # Deploy WireGuard private key
          environment.etc."wireguard/wg0-private-key" = {
            text = peer.wg.secret;
            mode = "0600";
          };
        };
    in
    {
      server = {
        imports = [ (shared server client) ];
        networking.firewall.allowedUDPPorts = [
          9999
          server.wg.listen
        ];
      };
      client = {
        imports = [ (shared client server) ];
      };
    };

  testScript =
    { ... }:
    ''
      from os import system
      rosenpass = "${pkgs.rosenpass}/bin/rosenpass"

      start_all()

      for machine in [server, client]:
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("systemd-networkd.service")

      with subtest("Generate keys and deploy configs"):
        for name, machine, remote in [
          ("server", server, client),
          ("client", client, server),
        ]:
          # Generate Rosenpass keys
          system(f"{rosenpass} gen-keys --public-key {name}-pqpk --secret-key {name}-pqsk")

          # Deploy keys
          machine.copy_from_host(f"{name}-pqsk", "/etc/rosenpass/wg0/pqsk")
          machine.copy_from_host(f"{name}-pqpk", "/etc/rosenpass/wg0/pqpk")
          remote.copy_from_host(f"{name}-pqpk", f"/etc/rosenpass/wg0/peers/{name}/pqpk")

          # Deploy Rosenpass config
          machine.copy_from_host(f"${rpConfig}/{name}", "/etc/rosenpass/wg0.toml")

      with subtest("Verify WireGuard interface is up via systemd-networkd"):
        for machine in [server, client]:
          machine.wait_until_succeeds("ip link show wg0", timeout=10)
          machine.wait_until_succeeds("wg show wg0", timeout=10)

      with subtest("Start rosenpass-networkd service"):
        for machine in [server, client]:
          machine.succeed("systemctl start rosenpass-networkd@wg0.service")

        for machine in [server, client]:
          machine.wait_for_unit("rosenpass-networkd@wg0.service")

      with subtest("Verify preshared keys are exchanged"):
        server.wait_until_succeeds("wg show wg0 preshared-keys | grep --invert-match none", timeout=10)
        client.wait_until_succeeds("wg show wg0 preshared-keys | grep --invert-match none", timeout=10)

        def get_psk(m):
          psk = m.succeed("wg show wg0 preshared-keys | awk '{print $2}'")
          psk = psk.strip()
          assert len(psk.split()) == 1, "Only one PSK expected"
          return psk

        assert get_psk(client) == get_psk(server), "Preshared keys must match"

      with subtest("Verify network connectivity over WireGuard tunnel"):
        client.succeed("ping -c5 ${server.wg.ip4}")
        server.succeed("ping -c5 ${client.wg.ip6}")

      with subtest("Service stops when interface is removed"):
        client.succeed("ip link del wg0")
        client.wait_until_fails("systemctl is-active rosenpass-networkd@wg0.service", timeout=10)
    '';
}
