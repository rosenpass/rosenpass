# NixOS integration test for the netctl + Rosenpass integration.
#
# This test verifies that:
# 1. A WireGuard interface can be brought up via netctl
# 2. The rosenpass-setup hook starts the Rosenpass daemon
# 3. Preshared keys are exchanged between peers
# 4. The rosenpass-teardown hook cleanly stops the daemon
#
# Run with: nix build .#checks.<system>.netctl
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

  # netctl profile template for WireGuard
  mkNetctlProfile = peer: remotePeer: ''
    Description='WireGuard with Rosenpass (test)'
    Interface=wg0
    Connection=wireguard
    WGKey='/etc/wireguard/private-key'
    ${if peer ? wg && peer.wg ? listen then "WGListenPort=${toString peer.wg.listen}" else ""}
    Address=('${peer.wg.ip4}/24' '${peer.wg.ip6}/64')
    WGPeer=('${remotePeer.wg.public}' '${remotePeer.wg.ip4}/32,${remotePeer.wg.ip6}/128' '${if remotePeer ? ip4 then "${remotePeer.ip4}:${toString remotePeer.wg.listen}" else ""}' '25')
    ROSENPASS_CONFIG='/etc/rosenpass/wg0.toml'
    ExecUpPost='/usr/lib/rosenpass/rosenpass-setup'
    ExecDownPre='/usr/lib/rosenpass/rosenpass-teardown'
  '';
in
{
  name = "netctl-rosenpass";

  nodes =
    let
      shared =
        peer:
        { pkgs, ... }:
        {
          environment.systemPackages = with pkgs; [
            wireguard-tools
            netctl
            rosenpass
          ];
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
          # Install the rosenpass-setup/teardown scripts
          environment.etc."usr/lib/rosenpass/rosenpass-setup" = {
            source = "${pkgs.rosenpass.src}/netctl/rosenpass-setup";
            mode = "0755";
          };
          environment.etc."usr/lib/rosenpass/rosenpass-teardown" = {
            source = "${pkgs.rosenpass.src}/netctl/rosenpass-teardown";
            mode = "0755";
          };
        };
    in
    {
      server = {
        imports = [ (shared server) ];
        networking.firewall.allowedUDPPorts = [
          9999
          server.wg.listen
        ];
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
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("network-online.target")

      with subtest("Generate keys and deploy configs"):
        for name, machine, remote, peer, remote_peer in [
          ("server", server, client, ${builtins.toJSON server}, ${builtins.toJSON client}),
          ("client", client, server, ${builtins.toJSON client}, ${builtins.toJSON server}),
        ]:
          # Generate Rosenpass keys
          system(f"{rosenpass} gen-keys --public-key {name}-pqpk --secret-key {name}-pqsk")

          # Deploy keys
          machine.copy_from_host(f"{name}-pqsk", "/etc/rosenpass/wg0/pqsk")
          machine.copy_from_host(f"{name}-pqpk", "/etc/rosenpass/wg0/pqpk")
          remote.copy_from_host(f"{name}-pqpk", f"/etc/rosenpass/wg0/peers/{name}/pqpk")

          # Deploy Rosenpass config
          machine.copy_from_host(f"${rpConfig}/{name}", "/etc/rosenpass/wg0.toml")

          # Deploy WireGuard private key
          machine.succeed(f"mkdir -p /etc/wireguard")

        # Write WireGuard private keys
        server.succeed("echo '${server.wg.secret}' > /etc/wireguard/private-key")
        client.succeed("echo '${client.wg.secret}' > /etc/wireguard/private-key")

      with subtest("Create and start netctl profiles"):
        server.succeed("mkdir -p /etc/netctl")
        server.succeed("""cat > /etc/netctl/wg0-rosenpass << 'EOF'
    ${mkNetctlProfile server client}
    EOF""")

        client.succeed("mkdir -p /etc/netctl")
        client.succeed("""cat > /etc/netctl/wg0-rosenpass << 'EOF'
    ${mkNetctlProfile client server}
    EOF""")

        server.succeed("netctl start wg0-rosenpass")
        client.succeed("netctl start wg0-rosenpass")

      with subtest("Verify Rosenpass is running"):
        server.wait_until_succeeds("test -f /run/rosenpass-wg0.pid", timeout=5)
        client.wait_until_succeeds("test -f /run/rosenpass-wg0.pid", timeout=5)
        server.succeed("kill -0 $(cat /run/rosenpass-wg0.pid)")
        client.succeed("kill -0 $(cat /run/rosenpass-wg0.pid)")

      with subtest("Verify preshared keys are exchanged"):
        server.wait_until_succeeds("wg show wg0 preshared-keys | grep --invert-match none", timeout=10)
        client.wait_until_succeeds("wg show wg0 preshared-keys | grep --invert-match none", timeout=10)

        def get_psk(m):
          psk = m.succeed("wg show wg0 preshared-keys | awk '{print $2}'")
          psk = psk.strip()
          assert len(psk.split()) == 1, "Only one PSK expected"
          return psk

        assert get_psk(client) == get_psk(server), "Preshared keys must match"

      with subtest("Verify network connectivity"):
        client.succeed("ping -c5 ${server.wg.ip4}")
        server.succeed("ping -c5 ${client.wg.ip6}")

      with subtest("Teardown via netctl stop"):
        client.succeed("netctl stop wg0-rosenpass")
        client.succeed("test ! -f /run/rosenpass-wg0.pid")
        # Verify the rosenpass process is gone
        client.fail("pgrep -f 'rosenpass exchange-config'")
    '';
}
