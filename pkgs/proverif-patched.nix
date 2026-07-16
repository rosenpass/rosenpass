{ proverif }:

proverif.overrideAttrs (old: {
  postInstall = ''
    install -D -t $out/lib cryptoverif.pvl
  '';
})
