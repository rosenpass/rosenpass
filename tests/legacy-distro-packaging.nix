{
  pkgs,
  rosenpass-deb,
  rosenpass-rpm,
}:

let
  wg-deb = pkgs.fetchurl {
    url = "https://ftp.de.debian.org/debian/pool/main/w/wireguard/wireguard-tools_1.0.20250521-1_amd64.deb";
    hash = "sha256-c8Z1pIAofTxlqOF9XXXnF1w+4PRHRQbCN8xMJlSNunQ=";
    # url = "https://ftp.de.debian.org/debian/pool/main/w/wireguard/wireguard-tools_1.0.20210914-1.1_amd64.deb";
    # hash = "sha256-s/hCUisQLR19kEbV6d8JXzzTAWUPM+NV0APgHizRGA4=";
  };
  wg-rpm = pkgs.fetchurl {
    url = "https://mirrors.n-ix.net/fedora/linux/releases/44/Everything/x86_64/os/Packages/w/wireguard-tools-1.0.20250521-3.fc44.x86_64.rpm";
    hash = "sha256-Tue1yrMgUTUzl+I7KO5fPVAYRNxiBDpGoKYohWrfPM8=";
    # url = "https://mirrors.n-ix.net/fedora/linux/releases/40/Everything/x86_64/os/Packages/w/wireguard-tools-1.0.20210914-6.fc40.x86_64.rpm";
    # hash = "sha256-lh6kCW5gh9bfuOwzjPv96ol1d6u1JTIr/oKH5QbAlK0=";
  };

  pkgsDirDeb = pkgs.runCommand "packages" { } ''
    mkdir $out
    cp ${rosenpass-deb} $out/rosenpass.deb
    cp ${wg-deb} $out/wireguard-tools.deb
    cp ${./prepare-test.sh} $out/prepare-test.sh
  '';
  pkgsDirRpm = pkgs.runCommand "packages" { } ''
    mkdir $out
    cp ${rosenpass-rpm} $out/rosenpass.rpm
    cp ${wg-rpm} $out/wireguard-tools.rpm
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
        vm.succeed("${installPrefix} /mnt/share/wireguard-tools.${suffix}")
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
  package-deb-debian-12 = test {
    tester = pkgs.testers.nonNixOSDistros.debian."12";
    installPrefix = "dpkg --install";
    suffix = "deb";
    source = pkgsDirDeb;
  };
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
  package-deb-ubuntu-24_04 = test {
    tester = pkgs.testers.nonNixOSDistros.ubuntu."24_04";
    installPrefix = "dpkg --install";
    suffix = "deb";
    source = pkgsDirDeb;
  };
  # not yet available:
  # package-deb-ubuntu-26_04 = test {
  #   tester = pkgs.testers.nonNixOSDistros.ubuntu."26_04";
  #   installPrefix = "dpkg --install";
  #   suffix = "deb";
  #   source = pkgsDirDeb;
  # };

  # Fedora 40 is not available for download anymore
  # package-rpm-fedora_40 = test {
  #   tester = pkgs.testers.nonNixOSDistros.fedora."40";
  #   installPrefix = "rpm -i";
  #   suffix = "rpm";
  #   source = pkgsDirRpm;
  # };
  # package-rpm-fedora_41 = test {
  #   tester = pkgs.testers.nonNixOSDistros.fedora."41";
  #   installPrefix = "rpm -i";
  #   suffix = "rpm";
  #   source = pkgsDirRpm;
  # };
  package-rpm-fedora_42 = test {
    tester = pkgs.testers.nonNixOSDistros.fedora."42";
    installPrefix = "rpm -i";
    suffix = "rpm";
    source = pkgsDirRpm;
  };
  package-rpm-fedora_43 = test {
    tester = pkgs.testers.nonNixOSDistros.fedora."43";
    installPrefix = "rpm -i";
    suffix = "rpm";
    source = pkgsDirRpm;
  };
  # not yet available:
  # package-rpm-fedora_44 = test {
  #   tester = pkgs.testers.nonNixOSDistros.fedora."44";
  #   installPrefix = "rpm -i";
  #   suffix = "rpm";
  #   source = pkgsDirRpm;
  # };
}
