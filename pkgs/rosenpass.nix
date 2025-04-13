{
  lib,
  stdenv,
  rustPlatform,
  cmake,
  mandoc,
  removeReferencesTo,
  bash,
  package ? "rosenpass",
}:

let
  # whether we want to build a statically linked binary
  isStatic = stdenv.targetPlatform.isStatic;

  scoped = (scope: scope.result);

  # source files relevant for rust
  src = scoped rec {
    # File suffices to include
    extensions = [
      "lock"
      "rs"
      "service"
      "target"
      "toml"
    ];
    # Files to explicitly include
    files = [ "to/README.md" ];

    src = ../.;
    filter = (
      path: type:
      scoped rec {
        inherit (lib)
          any
          id
          removePrefix
          hasSuffix
          ;
        anyof = (any id);

        basename = baseNameOf (toString path);
        relative = removePrefix (toString src + "/") (toString path);

        result = anyof [
          (type == "directory")
          (any (ext: hasSuffix ".${ext}" basename) extensions)
          (any (file: file == relative) files)
        ];
      }
    );

    result = lib.sources.cleanSourceWith { inherit src filter; };
  };

  # parsed Cargo.toml
  cargoToml = builtins.fromTOML (builtins.readFile (src + "/rosenpass/Cargo.toml"));
in
rustPlatform.buildRustPackage {
  name = cargoToml.package.name;
  version = cargoToml.package.version;
  inherit src;

  cargoBuildOptions = [
    "--package"
    package
  ];
  cargoTestOptions = [
    "--package"
    package
  ];

  doCheck = true;

  cargoLock = {
    lockFile = src + "/Cargo.lock";
    outputHashes = {
      "memsec-0.6.3" = "sha256-4ri+IEqLd77cLcul3lZrmpDKj4cwuYJ8oPRAiQNGeLw=";
      "uds-0.4.2" = "sha256-qlxr/iJt2AV4WryePIvqm/8/MK/iqtzegztNliR93W8=";
      "libcrux-blake2-0.0.3-pre" = "sha256-0CLjuzwJqGooiODOHf5D8Hc8ClcG/XcGvVGyOVnLmJY=";
    };
  };

  nativeBuildInputs = [
    stdenv.cc
    cmake # for oqs build in the oqs-sys crate
    mandoc # for the built-in manual
    removeReferencesTo
    rustPlatform.bindgenHook # for C-bindings in the crypto libs
  ];
  buildInputs = [ bash ];

  hardeningDisable = lib.optional isStatic "fortify";

  postInstall = ''
    mkdir -p $out/lib/systemd/system
    install systemd/rosenpass@.service $out/lib/systemd/system
    install systemd/rp@.service $out/lib/systemd/system
    install systemd/rosenpass.target $out/lib/systemd/system
  '';

  meta = {
    inherit (cargoToml.package) description homepage;
    license = with lib.licenses; [
      mit
      asl20
    ];
    maintainers = [ lib.maintainers.wucke13 ];
    platforms = lib.platforms.all;
  };
}
