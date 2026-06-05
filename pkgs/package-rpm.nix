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



  %install
  rm -rfv %{buildroot}

  mkdir -v -p %{buildroot}%{_bindir}
  install -v -m755 -t %{buildroot}%{_bindir} ${rosenpass}/bin/*

  mkdir -v -p %{buildroot}%{_sysconfdir}
  cp -v -r ${rosenpass}/lib/systemd %{buildroot}%{_sysconfdir}/

  find %{buildroot}%{_sysconfdir}/systemd -type d -exec chmod 755 {} +
  find %{buildroot}%{_sysconfdir}/systemd -type f -exec chmod 644 {} +

  install -v -Dm644 ${./example.toml} %{buildroot}%{_sysconfdir}/rosenpass/example.toml


  %files
  %{_bindir}/rosenpass
  %{_bindir}/rp
  %{_sysconfdir}/systemd/system/rosenpass.target
  %{_sysconfdir}/systemd/system/rosenpass@.service
  %{_sysconfdir}/systemd/system/rp@.service
  %config(noreplace) %{_sysconfdir}/rosenpass/example.toml
  EOF



  export HOME=/build
  mkdir -p /build/tmp
  ls -R rpmbuild

  # rpmbuild requires these defines, because Nix would otherwise overwrite them, especially %{_bindir}
  ${rpm}/bin/rpmbuild \
    -bb \
    --dbpath=$HOME \
    --define "_tmppath /build/tmp" \
    --define "_prefix /usr" \
    --define "_exec_prefix %{_prefix}" \
    --define "_bindir %{_exec_prefix}/bin" \
    --define "_sysconfdir /etc" \
    rpmbuild/SPECS/rosenpass.spec

  cp rpmbuild/RPMS/${arch}/rosenpass*.rpm $out
''
