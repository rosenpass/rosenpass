{
  lib,
  stdenvNoCC,
  runCommandNoCC,
  pkgsStatic,
  rosenpass,
  rosenpass-oci-image,
  rp,
}@args:

let
  version = rosenpass.version;

  # select static packages on Linux, default packages otherwise
  package = if stdenvNoCC.hostPlatform.isLinux then pkgsStatic.rosenpass else args.rosenpass;
  rp = if stdenvNoCC.hostPlatform.isLinux then pkgsStatic.rp else args.rp;
  oci-image =
    if stdenvNoCC.hostPlatform.isLinux then
      pkgsStatic.rosenpass-oci-image
    else
      args.rosenpass-oci-image;
in
runCommandNoCC "lace-result" { } ''
  mkdir {bin,$out}
  tar -cvf $out/rosenpass-${stdenvNoCC.hostPlatform.system}-${version}.tar \
    -C ${package} bin/rosenpass lib/systemd \
    -C ${rp} bin/rp
  cp ${oci-image} \
    $out/rosenpass-oci-image-${stdenvNoCC.hostPlatform.system}-${version}.tar.gz
''
