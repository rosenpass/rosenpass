final: prev: {

  #
  ### Actual rosenpass software ###
  #
  rosenpass = final.callPackage ./pkgs/rosenpass.nix { };
  rosenpass-oci-image = final.callPackage ./pkgs/rosenpass-oci-image.nix { };
  rp = final.callPackage ./pkgs/rosenpass.nix { package = "rp"; };

  release-package = final.callPackage ./pkgs/release-package.nix { };

  #
  ### Appendix ###
  #
  proverif-patched = prev.proverif.overrideAttrs (old: {
    postInstall = ''
      install -D -t $out/lib cryptoverif.pvl
    '';
  });

  proof-proverif = final.stdenv.mkDerivation {
    name = "rosenpass-proverif-proof";
    version = "unstable";
    src = final.lib.sources.sourceByRegex ./. [
      "analyze.sh"
      "marzipan(/marzipan.awk)?"
      "analysis(/.*)?"
    ];
    nativeBuildInputs = [
      final.proverif
      final.graphviz
    ];
    CRYPTOVERIF_LIB = final.proverif-patched + "/lib/cryptoverif.pvl";
    installPhase = ''
      mkdir -p $out
      bash analyze.sh -color -html $out
    '';
  };

  whitepaper = final.callPackage ./pkgs/whitepaper.nix { };
}
