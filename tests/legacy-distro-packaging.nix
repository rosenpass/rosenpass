{
  pkgs,
  rosenpass-deb,
  rosenpass-rpm,
}:

let
  wg-deb = pkgs.fetchurl {
    url = "https://ftp.de.debian.org/debian/pool/main/w/wireguard/wireguard-tools_1.0.20210914-1.1_amd64.deb";
    hash = "sha256-s/hCUisQLR19kEbV6d8JXzzTAWUPM+NV0APgHizRGA4=";
  };
  wg-rpm = pkgs.fetchurl {
    url = "https://mirrors.n-ix.net/fedora/linux/releases/40/Everything/x86_64/os/Packages/w/wireguard-tools-1.0.20210914-6.fc40.x86_64.rpm";
    hash = "sha256-lh6kCW5gh9bfuOwzjPv96ol1d6u1JTIr/oKH5QbAlK0=";
  };

  pkgsDirDeb = pkgs.runCommand "packages" { } ''
    mkdir $out
    cp ${rosenpass-deb} $out/rosenpass.deb
    cp ${wg-deb} $out/wireguard.deb
    cp ${./prepare-test.sh} $out/prepare-test.sh
  '';
  pkgsDirRpm = pkgs.runCommand "packages" { } ''
    mkdir $out
    cp ${rosenpass-rpm} $out/rosenpass.rpm
    cp ${wg-rpm} $out/wireguard.rpm
    cp ${./prepare-test.sh} $out/prepare-test.sh
  '';

  test =
    {
      tester,
      installPrefix,
      suffix,
      source,
    }:
    (tester {
      sharedDirs.share = {
        inherit source;
        target = "/mnt/share";
      };
      testScript = ''
        vm.wait_for_unit("multi-user.target")
        vm.succeed("${installPrefix} /mnt/share/wireguard.${suffix}")
        vm.succeed("${installPrefix} /mnt/share/rosenpass.${suffix}")
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
    }).sandboxed;
in
{
  package-deb-debian-13 = test {
    tester = pkgs.testers.nonNixOSDistros.debian."13";
    installPrefix = "dpkg --install";
    suffix = "deb";
    source = pkgsDirDeb;
  };
  package-deb-ubuntu-23_10 = test {
    tester = pkgs.testers.nonNixOSDistros.ubuntu."23_10";
    installPrefix = "dpkg --install";
    suffix = "deb";
    source = pkgsDirDeb;
  };
  package-rpm-fedora_40 = test {
    tester = pkgs.testers.nonNixOSDistros.fedora."40";
    installPrefix = "rpm -i";
    suffix = "rpm";
    source = pkgsDirRpm;
  };
}
