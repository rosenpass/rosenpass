{
  dockerTools,
  buildEnv,
  fetchurl,
  rosenpass,
  rsync,
}:

let
  # rsync 3.5.0's partial-protected-regular-retry-linux test is broken on
  # i686-linux because its LD_PRELOAD hook does not interpose the large-file
  # libc symbols used by rsync. 3.5.1 contains the upstream fix.
  #
  # IDN support was added in 3.5.1 and defaults to enabled. The Nixpkgs
  # derivation being overridden is for 3.5.0 and consequently does not provide
  # libidn2, so keep the feature set equivalent to the original derivation.
  rsyncForDocker = rsync.overrideAttrs (old: rec {
    version = "3.5.1";
    src = fetchurl {
      url = "mirror://samba/rsync/src/rsync-${version}.tar.gz";
      hash = "sha256-xV+cncEPuL7Dl7OZoP3e1TzJotjjCJG7DWNyTSXDe+8=";
    };
    configureFlags = (old.configureFlags or [ ]) ++ [
      "--disable-idn"
    ];
  });

  dockerToolsForRosenpass = dockerTools.override {
    rsync = rsyncForDocker;
  };
in
dockerToolsForRosenpass.buildImage {
  name = rosenpass.name + "-oci";
  copyToRoot = buildEnv {
    name = "image-root";
    paths = [ rosenpass ];
    pathsToLink = [ "/bin" ];
  };
  config.Cmd = [ "/bin/rosenpass" ];
}
