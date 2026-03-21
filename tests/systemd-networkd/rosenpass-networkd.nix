# NixOS integration test: Rosenpass + WireGuard + systemd-networkd
#
# Verifies that Rosenpass can perform post-quantum key exchange over a
# WireGuard tunnel whose interfaces are managed entirely by systemd-networkd
# via .netdev and .network unit files.
#
# Topology:
#   server (192.168.0.1) <--eth1--> client (192.168.0.2)
#   WireGuard tunnel: server wg0 (10.23.42.1) <-> client wg0 (10.23.42.2)
#   systemd-networkd manages wg0 on each side via netdev/network units
{ pkgs, ... }:

let
  server = {
    ip4 = "192.168.0.1";
    wg = {
      ip4 = "10.23.42.1";
      public = "mQufmDFeQQuU/fIaB2hHgluhjjm1ypK4hJr1cW3WqAw=";
      secret = "4N5Y1dldqrpsbaEiY8O0XBUGUFf8vkvtBtm8AoOX7Eo=";
      listen = 10000;
    };
  };

  client = {
    ip4 = "192.168.0.2";
    wg = {
      ip4 = "10.23.42.2";
      public = "Mb3GOlT7oS+F3JntVKiaD7SpHxLxNdtEmWz/9FMnRFU=";
      secret = "uC5dfGMv7Oxf5UDfdPkj6rZiRZT2dRWp5x8IQxrNcUE=";
    };
  };

  server_config = {
    listen = [ "0.0.0.0:9999" ];
    public_key = "/etc/rosenpass/wg0/pqpk";
    secret_key = "/etc/rosenpass/wg0/pqsk";
    verbosity = "Verbose";
    peers = [
      {
        device = "wg0";
        peer = client.wg.public;
        public_key = "/etc/rosenpass/wg0/peers/client/pqpk";
      }
    ];
  };

  client_config = {
    listen = [ ];
    public_key = "/etc/rosenpass/wg0/pqpk";
    secret_key = "/etc/rosenpass/wg0/pqsk";
    verbosity = "Verbose";
    peers = [
      {
        device = "wg0";
        peer = server.wg.public;
        public_key = "/etc/rosenpass/wg0/peers/server/pqpk";
        endpoint = "${server.ip4}:9999";
      }
    ];
  };

  config = pkgs.runCommand "config" { } ''
    mkdir -pv $out
    cp -v ${(pkgs.formats.toml { }).generate "wg0.toml" server_config} $out/server
    cp -v ${(pkgs.formats.toml { }).generate "wg0.toml" client_config} $out/client
  '';
in
{
  name = "rosenpass-networkd";

  nodes =
    let
      shared =
        peer:
        { pkgs, ... }:
        {
          virtualisation.vlans = [ 1 ];

          environment.systemPackages = with pkgs; [
            wireguard-tools
            rosenpass
          ];

          # Use systemd-networkd exclusively
          networking = {
            useNetworkd = true;
            useDHCP = false;
            firewall.enable = false;
          };

          # Underlay: assign physical IP to eth1 via networkd
          systemd.network.networks."40-eth1" = {
            name = "eth1";
            networkConfig.Address = "${peer.ip4}/24";
          };
        };

      # Server: WireGuard .netdev with listen port + peer
      serverNode =
        { pkgs, ... }:
        {
          imports = [ (shared server) ];

          # WireGuard private key for systemd-networkd
          environment.etc."wireguard/wg0.key" = {
            text = server.wg.secret;
            mode = "0600";
          };

          # systemd-networkd creates the WireGuard interface
          systemd.network.netdevs."50-wg0" = {
            netdevConfig = {
              Name = "wg0";
              Kind = "wireguard";
            };
            wireguardConfig = {
              ListenPort = server.wg.listen;
              PrivateKeyFile = "/etc/wireguard/wg0.key";
            };
            wireguardPeers = [
              {
                PublicKey = client.wg.public;
                AllowedIPs = [ "${client.wg.ip4}/32" ];
              }
            ];
          };

          # systemd-networkd assigns the tunnel IP
          systemd.network.networks."50-wg0" = {
            name = "wg0";
            address = [ "${server.wg.ip4}/24" ];
          };
        };

      # Client: WireGuard .netdev with endpoint, no listen port
      clientNode =
        { pkgs, ... }:
        {
          imports = [ (shared client) ];

          environment.etc."wireguard/wg0.key" = {
            text = client.wg.secret;
            mode = "0600";
          };

          systemd.network.netdevs."50-wg0" = {
            netdevConfig = {
              Name = "wg0";
              Kind = "wireguard";
            };
            wireguardConfig = {
              PrivateKeyFile = "/etc/wireguard/wg0.key";
            };
            wireguardPeers = [
              {
                PublicKey = server.wg.public;
                AllowedIPs = [ "${server.wg.ip4}/32" ];
                Endpoint = "${server.ip4}:${toString server.wg.listen}";
              }
            ];
          };

          systemd.network.networks."50-wg0" = {
            name = "wg0";
            address = [ "${client.wg.ip4}/24" ];
          };
        };
    in
    {
      server = serverNode;
      client = clientNode;
    };

  testScript =
    { ... }:
    ''
      from os import system
      rosenpass = "${pkgs.rosenpass}/bin/rosenpass"

      start_all()

      for machine in [server, client]:
        machine.wait_for_unit("systemd-networkd.service")
        machine.wait_for_unit("multi-user.target")

      with subtest("systemd-networkd creates WireGuard interface"):
        # Wait for networkd to bring up the wg0 interface
        server.wait_until_succeeds("networkctl status wg0 | grep -i routable", timeout=30)
        client.wait_until_succeeds("networkctl status wg0 | grep -i routable", timeout=30)

        # Verify interface exists and is managed by networkd
        server.succeed("ip link show wg0")
        client.succeed("ip link show wg0")

      with subtest("Underlay connectivity"):
        server.wait_until_succeeds("ping -c1 ${client.ip4}", timeout=30)

      with subtest("WireGuard tunnel connectivity (no PSK yet)"):
        client.succeed("wg show wg0 preshared-keys | grep none")
        client.wait_until_succeeds("ping -c1 ${server.wg.ip4}", timeout=10)

      with subtest("Generate and distribute Rosenpass keys"):
        for name, machine, remote in [("server", server, client), ("client", client, server)]:
          machine.succeed("mkdir -p /etc/rosenpass/wg0/peers")
          system(f"{rosenpass} gen-keys --public-key {name}-pqpk --secret-key {name}-pqsk")
          machine.copy_from_host(f"{name}-pqsk", "/etc/rosenpass/wg0/pqsk")
          machine.copy_from_host(f"{name}-pqpk", "/etc/rosenpass/wg0/pqpk")
          remote.succeed(f"mkdir -p /etc/rosenpass/wg0/peers/{name}")
          remote.copy_from_host(f"{name}-pqpk", f"/etc/rosenpass/wg0/peers/{name}/pqpk")
          machine.copy_from_host(f"${config}/{name}", "/etc/rosenpass/wg0/config.toml")

      with subtest("Start Rosenpass and verify PSK delivery"):
        for machine in [server, client]:
          machine.succeed("rosenpass exchange-config /etc/rosenpass/wg0/config.toml >/dev/null 2>&1 &")

        # Wait for Rosenpass to complete a key exchange and deliver PSKs
        client.wait_until_succeeds(
          "wg show wg0 preshared-keys | grep --invert-match none",
          timeout=30,
        )
        server.wait_until_succeeds(
          "wg show wg0 preshared-keys | grep --invert-match none",
          timeout=30,
        )

      with subtest("PSK match between peers"):
        def get_psk(m):
          psk = m.succeed("wg show wg0 preshared-keys | awk '{print $2}'")
          psk = psk.strip()
          assert len(psk.split()) == 1, "Expected exactly one PSK"
          return psk

        assert get_psk(client) == get_psk(server), "Preshared keys must match between peers"

      with subtest("WireGuard tunnel connectivity with Rosenpass PSK"):
        client.succeed("ping -c3 ${server.wg.ip4}")
        server.succeed("ping -c3 ${client.wg.ip4}")

      with subtest("Interface still managed by systemd-networkd after key exchange"):
        server.succeed("networkctl status wg0 | grep -i routable")
        client.succeed("networkctl status wg0 | grep -i routable")
    '';
}
