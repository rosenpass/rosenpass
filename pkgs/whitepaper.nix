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
        framed
        gitinfo2
        gobble
        ifmtarg
        koma-script
        latexmk
        lineno
        lm
        lualatex-math
        lua-ul
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
        xstring
        xurl
        dirtytalk
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
