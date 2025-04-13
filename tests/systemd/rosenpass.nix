# This test is largely inspired from:
# https://github.com/NixOS/nixpkgs/blob/master/nixos/tests/rosenpass.nix
# https://github.com/NixOS/nixpkgs/blob/master/nixos/tests/wireguard/basic.nix
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

  server_config = {
    listen = [ "0.0.0.0:9999" ];
    public_key = "/etc/rosenpass/rp0/pqpk";
    secret_key = "/run/credentials/rosenpass@rp0.service/pqsk";
    verbosity = "Verbose";
    peers = [
      {
        device = "rp0";
        peer = client.wg.public;
        public_key = "/etc/rosenpass/rp0/peers/client/pqpk";
      }
    ];
  };
  client_config = {
    listen = [ ];
    public_key = "/etc/rosenpass/rp0/pqpk";
    secret_key = "/run/credentials/rosenpass@rp0.service/pqsk";
    verbosity = "Verbose";
    peers = [
      {
        device = "rp0";
        peer = server.wg.public;
        public_key = "/etc/rosenpass/rp0/peers/server/pqpk";
        endpoint = "${server.ip4}:9999";
      }
    ];
  };

  config = pkgs.runCommand "config" { } ''
    mkdir -pv $out
    cp -v ${(pkgs.formats.toml { }).generate "rp0.toml" server_config} $out/server
    cp -v ${(pkgs.formats.toml { }).generate "rp0.toml" client_config} $out/client
  '';
in
{
  name = "rosenpass unit";

  nodes =
    let
      shared =
        peer:
        {
          config,
          modulesPath,
          pkgs,
          ...
        }:
        {
          # Need to work around a problem in recent systemd changes.
          # It won't be necessary in other distros (for which the systemd file was designed), this is NixOS specific
          # https://github.com/NixOS/nixpkgs/issues/258371#issuecomment-1925672767
          # This can potentially be removed in future nixpkgs updates
          systemd.packages = [
            (pkgs.runCommand "rosenpass" { } ''
              mkdir -p $out/lib/systemd/system
              < ${pkgs.rosenpass}/lib/systemd/system/rosenpass.target > $out/lib/systemd/system/rosenpass.target
              < ${pkgs.rosenpass}/lib/systemd/system/rosenpass@.service \
              sed 's@^\(\[Service]\)$@\1\nEnvironment=PATH=${pkgs.wireguard-tools}/bin@' |
              sed 's@^ExecStartPre=envsubst @ExecStartPre='"${pkgs.envsubst}"'/bin/envsubst @' |
              sed 's@^ExecStart=rosenpass @ExecStart='"${pkgs.rosenpass}"'/bin/rosenpass @' > $out/lib/systemd/system/rosenpass@.service
            '')
          ];
          networking.wireguard = {
            enable = true;
            interfaces.rp0 = {
              ips = [
                "${peer.wg.ip4}/32"
                "${peer.wg.ip6}/128"
              ];
              privateKeyFile = "/etc/wireguard/wgsk";
            };
          };
          environment.etc."wireguard/wgsk".text = peer.wg.secret;
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
        };
    in
    {
      server = {
        imports = [ (shared server) ];
        networking.firewall.allowedUDPPorts = [
          9999
          server.wg.listen
        ];
        networking.wireguard.interfaces.rp0 = {
          listenPort = server.wg.listen;
          peers = [
            {
              allowedIPs = [
                client.wg.ip4
                client.wg.ip6
              ];
              publicKey = client.wg.public;
            }
          ];
        };
      };
      client = {
        imports = [ (shared client) ];
        networking.wireguard.interfaces.rp0 = {
          peers = [
            {
              allowedIPs = [
                "10.23.42.0/24"
                "fc00::/64"
              ];
              publicKey = server.wg.public;
              endpoint = "${server.ip4}:${toString server.wg.listen}";
            }
          ];
        };
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

      with subtest("Key, Config, and Service Setup"):
        for name, machine, remote in [("server", server, client), ("client", client, server)]:
          # generate all the keys
          system(f"{rosenpass} gen-keys --public-key {name}-pqpk --secret-key {name}-pqsk")

          # copy private keys to our side
          machine.copy_from_host(f"{name}-pqsk", "/etc/rosenpass/rp0/pqsk")
          machine.copy_from_host(f"{name}-pqpk", "/etc/rosenpass/rp0/pqpk")

          # copy public keys to other side
          remote.copy_from_host(f"{name}-pqpk", f"/etc/rosenpass/rp0/peers/{name}/pqpk")

          machine.copy_from_host(f"${config}/{name}", "/etc/rosenpass/rp0.toml")

        for machine in [server, client]:
          machine.wait_for_unit("wireguard-rp0.service")

      with subtest("wg network test"):
        client.succeed("wg show all preshared-keys | grep none", timeout=5);
        client.succeed("ping -c5 ${server.wg.ip4}")
        server.succeed("ping -c5 ${client.wg.ip6}")

      with subtest("Set up rosenpass"):
        for machine in [server, client]:
          machine.succeed("systemctl start rosenpass@rp0.service")

        for machine in [server, client]:
          machine.wait_for_unit("rosenpass@rp0.service")


      with subtest("compare preshared keys"):
        client.wait_until_succeeds("wg show all preshared-keys | grep --invert-match none", timeout=5);
        server.wait_until_succeeds("wg show all preshared-keys | grep --invert-match none", timeout=5);

        def get_psk(m):
          psk = m.succeed("wg show rp0 preshared-keys | awk '{print $2}'")
          psk = psk.strip()
          assert len(psk.split()) == 1, "Only one PSK"
          return psk

        assert get_psk(client) == get_psk(server), "preshared keys need to match"

      with subtest("rosenpass network test"):
        client.succeed("ping -c5 ${server.wg.ip4}")
        server.succeed("ping -c5 ${client.wg.ip6}")
    '';
}
