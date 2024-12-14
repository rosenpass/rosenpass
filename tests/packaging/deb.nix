{ pkgs, rosenpass-deb }:

let
  wg-deb = pkgs.fetchurl {
    url = "http://ftp.de.debian.org/debian/pool/main/w/wireguard/wireguard-tools_1.0.20210914-1.1_amd64.deb";
    hash = "sha256-s/hCUisQLR19kEbV6d8JXzzTAWUPM+NV0APgHizRGA4=";
  };
  pkgsDir = pkgs.runCommand "packages" {} ''
    mkdir $out
    cp ${rosenpass-deb} $out/rosenpass.deb
    cp ${wg-deb} $out/wireguard.deb
    cp ${./prepare-test.sh} $out/prepare-test.sh
  '';

  testAttrs = {
    sharedDirs.share = {
      source = pkgsDir;
      target = "/mnt/share";
    };
    testScript = ''
      vm.wait_for_unit("multi-user.target")
      vm.succeed("dpkg --install /mnt/share/wireguard.deb")
      vm.succeed("dpkg --install /mnt/share/rosenpass.deb")
      vm.succeed("bash /mnt/share/prepare-test.sh")

      vm.succeed(f"systemctl start rp@server")
      vm.succeed(f"systemctl start rp@client")

      vm.wait_for_unit("rp@server.service")
      vm.wait_for_unit("rp@client.service")

      vm.wait_until_succeeds("wg show all preshared-keys | grep --invert-match none", timeout=5);

      psk_server = vm.succeed("wg show rp-server preshared-keys").strip().split()[-1]
      psk_client = vm.succeed("wg show rp-client preshared-keys").strip().split()[-1]

      assert psk_server == psk_client, "preshared-key exchange must be successful"
    '';
  };
in
{
  debian-13 = (pkgs.testers.legacyDistros.debian."13" testAttrs).sandboxed;
  ubuntu-23_10 = (pkgs.testers.legacyDistros.ubuntu."23_10" testAttrs).sandboxed;
}
