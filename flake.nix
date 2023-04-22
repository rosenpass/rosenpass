{
  inputs = {
    nixpkgs-unstable.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";

    # for quicker rust builds
    naersk.url = "github:nix-community/naersk";
    naersk.inputs.nixpkgs.follows = "nixpkgs";

    # for rust nightly with llvm-tools-preview
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, ... }@inputs:
    nixpkgs.lib.foldl (a: b: nixpkgs.lib.recursiveUpdate a b) { } [

      #
      ### Actual Rosenpass Package and Docker Container Images ###
      #
      (flake-utils.lib.eachSystem [
        "x86_64-linux"
        "i686-linux"
        "aarch64-linux"

        # unsuported best-effort
        "x86_64-darwin"
        "aarch64-darwin"
        # "x86_64-windows"
      ]
        (system:
          let
            lib = nixpkgs.lib;

            # normal nixpkgs
            pkgs = import nixpkgs {
              inherit system;

              # TODO remove overlay once a fix for
              # https://github.com/NixOS/nixpkgs/issues/216904 got merged
              overlays = [
                (
                  final: prev: {
                    iproute2 = prev.iproute2.overrideAttrs (old:
                      let
                        isStatic = prev.stdenv.hostPlatform.isStatic;
                      in
                      {
                        makeFlags = old.makeFlags ++ prev.lib.optional isStatic [
                          "TC_CONFIG_NO_XT=y"
                        ];
                      });
                  }
                )
              ];
            };

            # parsed Cargo.toml
            cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

            # source files relevant for rust
            src = pkgs.lib.sourceByRegex ./. [
              "Cargo\\.(toml|lock)"
              "(src|benches)(/.*\\.(rs|md))?"
              "rp"
            ];

            # builds a bin path for all dependencies for the `rp` shellscript
            rpBinPath = p: with p; lib.makeBinPath [
              coreutils
              findutils
              gawk
              wireguard-tools
            ];

            # a function to generate a nix derivation for rosenpass against any
            # given set of nixpkgs
            rpDerivation = p:
              let
                # whether we want to build a statically linked binary
                isStatic = p.targetPlatform.isStatic;

                # the rust target of `p`
                target = p.rust.toRustTargetSpec p.targetPlatform;

                # convert a string to shout case
                shout = string: builtins.replaceStrings [ "-" ] [ "_" ] (pkgs.lib.toUpper string);

                # suitable Rust toolchain
                toolchain = with inputs.fenix.packages.${system}; combine [
                  stable.cargo
                  stable.rustc
                  targets.${target}.stable.rust-std
                ];

                # naersk with a custom toolchain
                naersk = pkgs.callPackage inputs.naersk {
                  cargo = toolchain;
                  rustc = toolchain;
                };
              in
              naersk.buildPackage
                {
                  # metadata and source
                  name = cargoToml.package.name;
                  version = cargoToml.package.version;
                  inherit src;

                  doCheck = true;

                  nativeBuildInputs = with pkgs; [
                    p.stdenv.cc
                    cmake # for oqs build in the oqs-sys crate
                    makeWrapper # for the rp shellscript
                    pkg-config # let libsodium-sys-stable find libsodium
                    removeReferencesTo
                    rustPlatform.bindgenHook # for C-bindings in the crypto libs
                  ];
                  buildInputs = with p; [ bash libsodium ];

                  override = x: {
                    preBuild =
                      # nix defaults to building for aarch64 _without_ the armv8-a crypto
                      # extensions, but liboqs depens on these
                      (lib.optionalString (system == "aarch64-linux") ''
                        NIX_CFLAGS_COMPILE="$NIX_CFLAGS_COMPILE -march=armv8-a+crypto"
                      ''
                      );

                    # fortify is only compatible with dynamic linking
                    hardeningDisable = lib.optional isStatic "fortify";
                  };

                  overrideMain = x: {
                    # CMake detects that it was served a _foreign_ target dir, thus we have to
                    # convice it a little
                    # TODO this still re-builds liboqs in the second step, which is wasteful
                    preBuild = x.preBuild + ''
                      find -name CMakeCache.txt -exec sed s_/dummy-src/_/source/_g --in-place {} \;
                    '' + (lib.optionalString isStatic ''
                      NIX_CFLAGS_COMPILE="$NIX_CFLAGS_COMPILE -lc"
                    '')
                    ;

                    preInstall = ''
                      install -D ${./rp} $out/bin/rp
                      wrapProgram $out/bin/rp --prefix PATH : "${ rpBinPath p }"
                    '';
                  };

                  # liboqs requires quite a lot of stack memory, thus we adjust
                  # the default stack size picked for new threads (which is used
                  # by `cargo test`) to be _big enough_
                  RUST_MIN_STACK = 8 * 1024 * 1024; # 8 MiB

                  # We want to build for a specific target...
                  CARGO_BUILD_TARGET = target;

                  # ... which might require a non-default linker:
                  "CARGO_TARGET_${shout target}_LINKER" =
                    let
                      inherit (p.stdenv) cc;
                    in
                    "${cc}/bin/${cc.targetPrefix}cc";

                  meta = with pkgs.lib;
                    {
                      inherit (cargoToml.package) description homepage;
                      license = with licenses; [ mit asl20 ];
                      maintainers = [ maintainers.wucke13 ];
                      platforms = platforms.all;
                    };
                } // (lib.mkIf isStatic {
                # otherwise pkg-config tries to link non-existent dynamic libs
                # documented here: https://docs.rs/pkg-config/latest/pkg_config/
                PKG_CONFIG_ALL_STATIC = true;

                # tell rust to build everything statically linked
                CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
              });
            # a function to generate a docker image based of rosenpass
            rosenpassOCI = name: pkgs.dockerTools.buildImage rec {
              inherit name;
              copyToRoot = pkgs.buildEnv {
                name = "image-root";
                paths = [ self.packages.${system}.${name} ];
                pathsToLink = [ "/bin" ];
              };
              config.Cmd = [ "/bin/rosenpass" ];
            };
          in
          rec {
            packages = rec {
              default = rosenpass;
              rosenpass = rpDerivation pkgs;
              rosenpass-oci-image = rosenpassOCI "rosenpass";

              # derivation for the release
              release-package =
                let
                  version = cargoToml.package.version;
                  package =
                    if pkgs.hostPlatform.isLinux then
                      packages.rosenpass-static
                    else packages.rosenpass;
                  oci-image =
                    if pkgs.hostPlatform.isLinux then
                      packages.rosenpass-static-oci-image
                    else packages.rosenpass-oci-image;
                in
                pkgs.runCommandNoCC "lace-result" { }
                  ''
                    mkdir {bin,$out}
                    cp ${./.}/rp bin/
                    tar -cvf $out/rosenpass-${system}-${version}.tar bin/rp \
                      -C ${package} bin/rosenpass
                    cp ${oci-image} \
                      $out/rosenpass-oci-image-${system}-${version}.tar.gz
                  '';
            } // (if pkgs.stdenv.isLinux then rec {
              rosenpass-static = rpDerivation pkgs.pkgsStatic;
              rosenpass-static-oci-image = rosenpassOCI "rosenpass-static";
            } else { });
          }
        ))

      #
      ### Linux specifics ###
      #
      (flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
        let
          pkgs = import nixpkgs {
            inherit system;
          };
          packages = self.packages.${system};
        in
        {
          #
          ### Whitepaper ###
          #
          packages.whitepaper =
            let
              pkgs = import inputs.nixpkgs-unstable {
                inherit system;
              };
              tlsetup = (pkgs.texlive.combine {
                inherit (pkgs.texlive) scheme-basic acmart amsfonts ccicons
                  csquotes csvsimple doclicense fancyvrb fontspec gobble
                  koma-script ifmtarg latexmk lm markdown mathtools minted noto
                  nunito pgf soul soulutf8 unicode-math lualatex-math
                  gitinfo2 eso-pic biblatex biblatex-trad biblatex-software
                  xkeyval xurl xifthen biber;
              });
            in
            pkgs.stdenvNoCC.mkDerivation {
              name = "whitepaper";
              src = ./papers;
              nativeBuildInputs = with pkgs; [
                ncurses # tput
                python3Packages.pygments
                tlsetup # custom tex live scheme
                which
              ];
              buildPhase = ''
                export HOME=$(mktemp -d)
                export OSFONTDIR="$(kpsewhich --var-value TEXMF)/fonts/{opentype/public/nunito,truetype/google/noto}"
                latexmk -r tex/CI.rc
              '';
              installPhase = ''
                mkdir -p $out
                mv *.pdf readme.md $out/
              '';
            };


          #
          ### Proof and Proof Tools ###
          #
          packages.proverif-patched = pkgs.proverif.overrideAttrs (old: {
            postInstall = ''
              install -D -t $out/lib cryptoverif.pvl
            '';
          });
          packages.proof-proverif = pkgs.stdenv.mkDerivation {
            name = "rosenpass-proverif-proof";
            version = "unstable";
            src = pkgs.lib.sourceByRegex ./. [
              "analyze.sh"
              "marzipan(/marzipan.awk)?"
              "analysis(/.*)?"
            ];
            nativeBuildInputs = [ pkgs.proverif pkgs.graphviz ];
            CRYPTOVERIF_LIB = packages.proverif-patched + "/lib/cryptoverif.pvl";
            installPhase = ''
              mkdir -p $out
              bash analyze.sh -color -html $out
            '';
          };


          #
          ### Devshells ###
          #
          devShells.default = pkgs.mkShell {
            inherit (packages.proof-proverif) CRYPTOVERIF_LIB;
            inherit (packages.rosenpass) RUST_MIN_STACK;
            inputsFrom = [ packages.default ];
            nativeBuildInputs = with pkgs; [
              cargo-release
              clippy
              nodePackages.prettier
              rustfmt
              packages.proverif-patched
            ];
          };
          devShells.coverage = pkgs.mkShell {
            inputsFrom = [ packages.default ];
            inherit (packages.rosenpass) RUST_MIN_STACK;
            nativeBuildInputs = with pkgs; [ inputs.fenix.packages.${system}.complete.toolchain cargo-llvm-cov ];
          };


          checks = {
            cargo-fmt = pkgs.runCommand "check-cargo-fmt"
              { inherit (self.devShells.${system}.default) nativeBuildInputs buildInputs; } ''
              cargo fmt --manifest-path=${./.}/Cargo.toml --check > $out
            '';
            nixpkgs-fmt = pkgs.runCommand "check-nixpkgs-fmt"
              { nativeBuildInputs = [ pkgs.nixpkgs-fmt ]; } ''
              nixpkgs-fmt --check ${./.} && touch $out
            '';
            prettier-check = pkgs.runCommand "check-with-prettier"
              { nativeBuildInputs = [ pkgs.nodePackages.prettier ]; } ''
              cd ${./.} && prettier --check . && touch $out
            '';
          };

          formatter = pkgs.nixpkgs-fmt;
        }))
    ];
}
