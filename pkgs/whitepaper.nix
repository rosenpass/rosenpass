{
  stdenvNoCC,
  texlive,
  ncurses,
  python3Packages,
  which,
}:

let
  customTexLiveSetup = (
    texlive.combine {
      inherit (texlive)
        acmart
        amsfonts
        biber
        biblatex
        biblatex-software
        biblatex-trad
        ccicons
        csquotes
        csvsimple
        doclicense
        eso-pic
        fancyvrb
        fontspec
        gitinfo2
        gobble
        ifmtarg
        koma-script
        latexmk
        lm
        lualatex-math
        markdown
        mathtools
        minted
        noto
        nunito
        paralist
        pgf
        scheme-basic
        soul
        unicode-math
        upquote
        xifthen
        xkeyval
        xurl
        ;
    }
  );
in
stdenvNoCC.mkDerivation {
  name = "whitepaper";
  src = ../papers;
  nativeBuildInputs = [
    ncurses # tput
    python3Packages.pygments
    customTexLiveSetup # custom tex live scheme
    which
  ];
  buildPhase = ''
    export HOME=$(mktemp -d)
    latexmk -r tex/CI.rc
  '';
  installPhase = ''
    mkdir -p $out
    mv *.pdf readme.md $out/
  '';
}
