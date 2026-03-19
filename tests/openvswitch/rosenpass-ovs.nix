# NixOS integration test: Rosenpass + WireGuard + Open vSwitch
#
# Verifies that Rosenpass can perform post-quantum key exchange over a
# WireGuard tunnel whose interfaces are managed as ports on OVS bridges.
#
# Topology:
#   server (192.168.0.1) <--eth1--> client (192.168.0.2)
#   WireGuard tunnel: server wg0 (10.23.42.1) <-> client wg0 (10.23.42.2)
#   OVS bridge br-rp on each side with wg0 as a port
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
  name = "rosenpass-ovs";

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

          # Use networkd with OVS -- the idiomatic NixOS way
          networking = {
            useNetworkd = true;
            useDHCP = false;
            firewall.enable = false;

            # Create an OVS bridge; eth1 provides L2 connectivity between VMs
            vswitches.br-rp = {
              interfaces = {
                eth1 = { };
              };
            };
          };

          # Assign the underlay IP to the OVS bridge
          systemd.network.networks."40-br-rp" = {
            name = "br-rp";
            networkConfig.Address = "${peer.ip4}/24";
          };
        };
    in
    {
      server = {
        imports = [ (shared server) ];
      };
      client = {
        imports = [ (shared client) ];
      };
    };

  testScript =
    { ... }:
    ''
      from os import system
      rosenpass = "${pkgs.rosenpass}/bin/rosenpass"

      start_all()

      for machine in [server, client]:
        machine.wait_for_unit("ovsdb.service")
        machine.wait_for_unit("ovs-vswitchd.service")
        machine.wait_for_unit("multi-user.target")

      with subtest("Underlay connectivity via OVS bridge"):
        server.wait_until_succeeds("ping -c1 ${client.ip4}", timeout=30)

      with subtest("Create WireGuard interfaces and add to OVS bridge"):
        server.succeed(
          "ip link add dev wg0 type wireguard",
          "wg set wg0 listen-port ${toString server.wg.listen} private-key <(echo '${server.wg.secret}')",
          "wg set wg0 peer '${client.wg.public}' allowed-ips ${client.wg.ip4}/32",
          "ip addr add ${server.wg.ip4}/24 dev wg0",
          "ip link set wg0 up",
          "ovs-vsctl add-port br-rp wg0",
        )
        client.succeed(
          "ip link add dev wg0 type wireguard",
          "wg set wg0 private-key <(echo '${client.wg.secret}')",
          "wg set wg0 peer '${server.wg.public}' allowed-ips ${server.wg.ip4}/32 endpoint ${server.ip4}:${toString server.wg.listen}",
          "ip addr add ${client.wg.ip4}/24 dev wg0",
          "ip link set wg0 up",
          "ovs-vsctl add-port br-rp wg0",
        )

      with subtest("Verify OVS port membership"):
        server.succeed("ovs-vsctl list-ports br-rp | grep wg0")
        client.succeed("ovs-vsctl list-ports br-rp | grep wg0")

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

      with subtest("Start Rosenpass and verify PSK exchange"):
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

        def get_psk(m):
          psk = m.succeed("wg show wg0 preshared-keys | awk '{print $2}'")
          psk = psk.strip()
          assert len(psk.split()) == 1, "Expected exactly one PSK"
          return psk

        assert get_psk(client) == get_psk(server), "Preshared keys must match"

      with subtest("WireGuard tunnel connectivity with Rosenpass PSK"):
        client.succeed("ping -c3 ${server.wg.ip4}")

      with subtest("OVS bridge still intact after key exchange"):
        server.succeed("ovs-vsctl list-ports br-rp | grep wg0")
        client.succeed("ovs-vsctl list-ports br-rp | grep wg0")
    '';
}
