{
  lib,
  system,
  runCommand,
  rosenpass,
  rpm,
}:

let
  splitVersion = lib.strings.splitString "-" rosenpass.version;
  version = builtins.head splitVersion;
  release = if builtins.length splitVersion != 2 then "release" else builtins.elemAt splitVersion 1;
  arch = builtins.head (builtins.split "-" system);
in

runCommand "rosenpass-${version}.rpm" { } ''
  mkdir -p rpmbuild/SPECS

  cat << EOF > rpmbuild/SPECS/rosenpass.spec
  Name:           rosenpass
  Release:        ${release}
  Version:        ${version}
  Summary:        Post-quantum-secure VPN key exchange
  License:        Apache-2.0

  %description
  Post-quantum-secure VPN tool Rosenpass
  Rosenpass is a post-quantum-secure VPN
  that uses WireGuard to transport the actual data.

  %files
  /usr/bin/rosenpass
  /usr/bin/rp
  /etc/systemd/system/rosenpass.target
  /etc/systemd/system/rosenpass@.service
  /etc/systemd/system/rp@.service
  /etc/rosenpass/example.toml
  EOF

  buildroot=rpmbuild/BUILDROOT/rosenpass-${version}-${release}.${arch}
  mkdir -p $buildroot/usr/bin
  install -m755 -t $buildroot/usr/bin ${rosenpass}/bin/*

  mkdir -p $buildroot/etc/rosenpass
  cp -r ${rosenpass}/lib/systemd $buildroot/etc/
  chmod -R 744 $buildroot/etc/systemd
  cp ${./example.toml} $buildroot/etc/rosenpass/example.toml

  export HOME=/build
  mkdir -p /build/tmp
  ls -R rpmbuild

  ${rpm}/bin/rpmbuild \
    -bb \
    --dbpath=$HOME \
    --define "_tmppath /build/tmp" \
    rpmbuild/SPECS/rosenpass.spec

  cp rpmbuild/RPMS/${arch}/rosenpass*.rpm $out
''
