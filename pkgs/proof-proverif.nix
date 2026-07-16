{
  lib,
  stdenv,
  flakeRoot,
  graphviz,
  proverif,
  proverif-patched,
}:

stdenv.mkDerivation {
  name = "rosenpass-proverif-proof";
  version = "unstable";
  src = lib.sources.sourceByRegex flakeRoot [
    "analyze.sh"
    "marzipan(/marzipan.awk)?"
    "analysis(/.*)?"
  ];
  nativeBuildInputs = [
    proverif
    graphviz
  ];
  CRYPTOVERIF_LIB = proverif-patched + "/lib/cryptoverif.pvl";
  installPhase = ''
    mkdir -p $out
    bash analyze.sh -color -html $out
  '';
}
