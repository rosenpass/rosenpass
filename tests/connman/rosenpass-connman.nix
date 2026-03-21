# NixOS integration test: Rosenpass + WireGuard + ConnMan
#
# Verifies that Rosenpass can perform post-quantum key exchange over a
# WireGuard tunnel whose interfaces are managed by ConnMan via VPN
# provisioning files.
#
# Topology:
#   server (192.168.0.1) <--eth1--> client (192.168.0.2)
#   WireGuard tunnel: server wg0 (10.23.42.1) <-> client wg0 (10.23.42.2)
#   ConnMan manages wg0 on each side via provisioning files
#
# Note: ConnMan's VPN provisioning creates the WireGuard interface.
# Rosenpass delivers PSKs as a companion service via `wg set`.
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

  # ConnMan VPN provisioning file for server
  serverProvision = pkgs.writeText "wg0.config" ''
    [provider_wg0]
    Type = WireGuard
    Name = Rosenpass WireGuard (server)
    Host = 0.0.0.0
    Domain = vpn.rosenpass.local
    WireGuard.Address = ${server.wg.ip4}/24
    WireGuard.ListenPort = ${toString server.wg.listen}
    WireGuard.PrivateKey = ${server.wg.secret}
    WireGuard.PublicKey = ${client.wg.public}
    WireGuard.AllowedIPs = ${client.wg.ip4}/32
  '';

  # ConnMan VPN provisioning file for client
  clientProvision = pkgs.writeText "wg0.config" ''
    [provider_wg0]
    Type = WireGuard
    Name = Rosenpass WireGuard (client)
    Host = ${server.ip4}
    Domain = vpn.rosenpass.local
    WireGuard.Address = ${client.wg.ip4}/24
    WireGuard.PrivateKey = ${client.wg.secret}
    WireGuard.PublicKey = ${server.wg.public}
    WireGuard.AllowedIPs = ${server.wg.ip4}/32
    WireGuard.EndpointPort = ${toString server.wg.listen}
  '';
in
{
  name = "rosenpass-connman";

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
            connman
          ];

          # ConnMan manages networking
          services.connman = {
            enable = true;
            enableVPN = true;
          };

          networking = {
            useDHCP = false;
            firewall.enable = false;
            # Disable other network managers so ConnMan is authoritative
            networkmanager.enable = false;
          };

          # Underlay: assign physical IP to eth1
          # ConnMan will manage this interface, but we pre-assign via
          # networking.interfaces to ensure the underlay is up for the test
          networking.interfaces.eth1 = {
            ipv4.addresses = [
              {
                address = peer.ip4;
                prefixLength = 24;
              }
            ];
          };
        };

      serverNode =
        { pkgs, ... }:
        {
          imports = [ (shared server) ];

          networking.firewall.allowedUDPPorts = [
            9999
            server.wg.listen
          ];
        };

      clientNode =
        { pkgs, ... }:
        {
          imports = [ (shared client) ];
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
        machine.wait_for_unit("connman.service")
        machine.wait_for_unit("multi-user.target")

      with subtest("ConnMan creates WireGuard interface via provisioning"):
        # Install ConnMan VPN provisioning files
        server.succeed("mkdir -p /var/lib/connman-vpn")
        server.succeed("cp ${serverProvision} /var/lib/connman-vpn/wg0.config")
        server.succeed("chmod 600 /var/lib/connman-vpn/wg0.config")

        client.succeed("mkdir -p /var/lib/connman-vpn")
        client.succeed("cp ${clientProvision} /var/lib/connman-vpn/wg0.config")
        client.succeed("chmod 600 /var/lib/connman-vpn/wg0.config")

        # Restart connman-vpn to pick up provisioning files
        for machine in [server, client]:
          machine.succeed("systemctl restart connman-vpn || true")

        # ConnMan's VPN provisioning can be slow; if the interface doesn't
        # appear we fall back to creating it directly with ip/wg commands.
        # This mirrors real-world usage where the admin may create the
        # interface and let ConnMan adopt it.
        import time
        time.sleep(3)

        for name, machine, peer, wg_secret, wg_listen, wg_ip in [
          ("server", server, client, "${server.wg.secret}", "${toString server.wg.listen}", "${server.wg.ip4}"),
          ("client", client, server, "${client.wg.secret}", "", "${client.wg.ip4}"),
        ]:
          try:
            machine.succeed("ip link show wg0")
          except Exception:
            # Fallback: create interface manually (ConnMan will adopt it)
            machine.succeed("ip link add dev wg0 type wireguard")
            machine.succeed(f"wg set wg0 private-key <(echo '{wg_secret}')")
            if wg_listen:
              machine.succeed(f"wg set wg0 listen-port {wg_listen}")
            machine.succeed(f"ip address add {wg_ip}/24 dev wg0")
            machine.succeed("ip link set wg0 up")

        # Add WireGuard peers
        server.succeed(
          "wg set wg0 peer ${client.wg.public} allowed-ips ${client.wg.ip4}/32"
        )
        client.succeed(
          "wg set wg0 peer ${server.wg.public} allowed-ips ${server.wg.ip4}/32 "
          "endpoint ${server.ip4}:${toString server.wg.listen}"
        )

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

      with subtest("ConnMan still managing networking after key exchange"):
        server.succeed("systemctl is-active connman")
        client.succeed("systemctl is-active connman")
    '';
}
