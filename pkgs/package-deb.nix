{
  runCommand,
  dpkg,
  rosenpass,
}:

let
  inherit (rosenpass) version;
in

runCommand "rosenpass-${version}.deb" { } ''
  mkdir -p packageroot/DEBIAN

  cat << EOF > packageroot/DEBIAN/control
  Package: rosenpass
  Version: ${version}
  Architecture: all
  Maintainer: Jacek Galowicz <jacek@galowicz.de>
  Depends:
  Description: Post-quantum-secure VPN tool Rosenpass
    Rosenpass is a post-quantum-secure VPN
    that uses WireGuard to transport the actual data.
  EOF


  mkdir -p packageroot/usr/bin
  install -m755 -t packageroot/usr/bin ${rosenpass}/bin/*

  mkdir -p packageroot/etc/rosenpass
  cp -r ${rosenpass}/lib/systemd packageroot/etc/
  cp ${./example.toml} packageroot/etc/rosenpass/example.toml

  ${dpkg}/bin/dpkg --build packageroot $out
''
