{ pkgs, ... }:

let
  server = {
    ip4 = "192.168.0.1";
    ip6 = "fd00::1";
    wg = {
      ip6 = "fc00::1";
      listen = 10000;
    };
  };

  client = {
    ip4 = "192.168.0.2";
    ip6 = "fd00::2";
    wg = {
      ip6 = "fc00::2";
    };
  };

  server_config = {
    listen = "${server.ip4}:9999";
    private_keys_dir = "/run/credentials/rp@test-rp-device0.service";
    verbose = true;
    dev = "test-rp-device0";
    ip = "fc00::1/64";
    peers = [
      {
        public_keys_dir = "/etc/rosenpass/test-rp-device0/peers/client";
        allowed_ips = "fc00::2";
      }
    ];
  };
  client_config = {
    private_keys_dir = "/run/credentials/rp@test-rp-device0.service";
    verbose = true;
    dev = "test-rp-device0";
    ip = "fc00::2/128";
    peers = [
      {
        public_keys_dir = "/etc/rosenpass/test-rp-device0/peers/server";
        endpoint = "${server.ip4}:9999";
        allowed_ips = "fc00::/64";
      }
    ];
  };

  config = pkgs.runCommand "config" { } ''
    mkdir -pv $out
    cp -v ${(pkgs.formats.toml { }).generate "test-rp-device0.toml" server_config} $out/server
    cp -v ${(pkgs.formats.toml { }).generate "test-rp-device0.toml" client_config} $out/client
  '';
in
{
  name = "rp systemd unit";

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
            (pkgs.runCommand "rp@.service" { } ''
              mkdir -p $out/lib/systemd/system
              < ${pkgs.rosenpass}/lib/systemd/system/rosenpass.target > $out/lib/systemd/system/rosenpass.target
              < ${pkgs.rosenpass}/lib/systemd/system/rp@.service \
              sed 's@^\(\[Service]\)$@\1\nEnvironment=PATH=${pkgs.iproute2}/bin:${pkgs.wireguard-tools}/bin@' |
              sed 's@^ExecStartPre=envsubst @ExecStartPre='"${pkgs.envsubst}"'/bin/envsubst @' |
              sed 's@^ExecStart=rp @ExecStart='"${pkgs.rosenpass}"'/bin/rp @' > $out/lib/systemd/system/rp@.service
            '')
          ];
          environment.systemPackages = [ pkgs.wireguard-tools ];
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
      };
      client = {
        imports = [ (shared client) ];
      };
    };
  testScript =
    { ... }:
    ''
      from os import system
      rp = "${pkgs.rosenpass}/bin/rp"

      start_all()

      for machine in [server, client]:
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("network-online.target")

      with subtest("Key, Config, and Service Setup"):
        for name, machine, remote in [("server", server, client), ("client", client, server)]:
          # create all the keys
          system(f"{rp} genkey {name}-sk")
          system(f"{rp} pubkey {name}-sk {name}-pk")

          # copy secret keys to our side
          for file in ["pqpk", "pqsk", "wgsk"]:
            machine.copy_from_host(f"{name}-sk/{file}", f"/etc/rosenpass/test-rp-device0/{file}")
          # copy public keys to other side
          for file in ["pqpk", "wgpk"]:
            remote.copy_from_host(f"{name}-pk/{file}", f"/etc/rosenpass/test-rp-device0/peers/{name}/{file}")

          machine.copy_from_host(f"${config}/{name}", "/etc/rosenpass/test-rp-device0.toml")

        for machine in [server, client]:
          machine.succeed("systemctl start rp@test-rp-device0.service")

        for machine in [server, client]:
          machine.wait_for_unit("rp@test-rp-device0.service")

      with subtest("compare preshared keys"):
        client.wait_until_succeeds("wg show all preshared-keys | grep --invert-match none", timeout=5);
        server.wait_until_succeeds("wg show all preshared-keys | grep --invert-match none", timeout=5);

        def get_psk(m):
          psk = m.succeed("wg show test-rp-device0 preshared-keys | awk '{print $2}'")
          psk = psk.strip()
          assert len(psk.split()) == 1, "Only one PSK"
          return psk

        assert get_psk(client) == get_psk(server), "preshared keys need to match"

      with subtest("network test"):
        client.succeed("ping -c5 ${server.wg.ip6}")
        server.succeed("ping -c5 ${client.wg.ip6}")
    '';
}
