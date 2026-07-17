{
  stdenvNoCC,
  runCommand,
  pkgsStatic,
  rosenpass,
  rosenpass-oci-image,
  rp,
}:

let
  version = rosenpass.version;

  # select static packages on Linux, default packages otherwise
  rosenpass' = if stdenvNoCC.hostPlatform.isLinux then pkgsStatic.rosenpass else rosenpass;
  rp' = if stdenvNoCC.hostPlatform.isLinux then pkgsStatic.rp else rp;
  rosenpass-oci-image' =
    if stdenvNoCC.hostPlatform.isLinux then pkgsStatic.rosenpass-oci-image else rosenpass-oci-image;
in
runCommand "lace-result" { } ''
  mkdir {bin,$out}
  tar -cvf $out/rosenpass-${stdenvNoCC.hostPlatform.system}-${version}.tar \
    -C ${rosenpass'} bin/rosenpass lib/systemd \
    -C ${rp'} bin/rp
  cp ${rosenpass-oci-image'} \
    $out/rosenpass-oci-image-${stdenvNoCC.hostPlatform.system}-${version}.tar.gz
''
