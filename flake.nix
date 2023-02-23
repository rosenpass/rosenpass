{
  inputs = {
    nixpkgs-unstable.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";

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
        "aarch64-linux"

        # unsuported best-effort
        "x86_64-darwin"
        "aarch64-darwin"
        "x86_64-windows"
      ]
        (system:
          let
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
            rpDerivation = p: let
              isStatic = p.stdenv.hostPlatform.isStatic;
            in p.rustPlatform.buildRustPackage {
              # metadata and source
              pname = cargoToml.package.name;
              version = cargoToml.package.version;
              inherit src;
              cargoLock = {
                lockFile = src + "/Cargo.lock";
              };

              nativeBuildInputs = with pkgs; [
                cmake # for oqs build in the oqs-sys crate
                makeWrapper # for the rp shellscript
                pkg-config # let libsodium-sys-stable find libsodium
                removeReferencesTo
                rustPlatform.bindgenHook # for C-bindings in the crypto libs
              ];
              buildInputs = with p; [ bash libsodium ];

              # otherwise pkg-config tries to link non-existent dynamic libs
              PKG_CONFIG_ALL_STATIC = true;

              # nix defaults to building for aarch64 _without_ the armv8-a
              # crypto extensions, but liboqs depens on these
              preBuild =
                if system == "aarch64-linux" then ''
                  NIX_CFLAGS_COMPILE="$NIX_CFLAGS_COMPILE -march=armv8-a+crypto"
                '' else "";

              preInstall = ''
                install -D rp $out/bin/rp
                wrapProgram $out/bin/rp --prefix PATH : "${ rpBinPath p }"
              '';

              # nix progated the *.dev outputs of buildInputs for static
              # builds, but that is non-sense for an executables only package
              postFixup = if isStatic then ''
                remove-references-to -t ${p.bash.dev} -t ${p.libsodium.dev} \
                  $out/nix-support/propagated-build-inputs
              '' else "";

              meta = with pkgs.lib; {
                description = "Post-quantum crypto frontend for WireGuard";
                license = with licenses; [ mit asl20 ];
                maintainers = [ maintainers.wucke13 ];
                homepage = "https://rosenpass.eu/";
                platforms = platforms.all;
              };
            };
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
            inputsFrom = [ packages.default ];
            nativeBuildInputs = with pkgs; [
              cargo-release
              clippy
              rustfmt
              packages.proverif-patched
            ];
          };
          devShells.coverage = pkgs.mkShell {
            inputsFrom = [ packages.default ];
            nativeBuildInputs = with pkgs; [ inputs.fenix.packages.${system}.complete.toolchain cargo-llvm-cov ];
          };


          checks = {
            # Blocked by https://github.com/rust-lang/rustfmt/issues/4306
            # @dakoraa wants a coding style suitable for her accessible coding setup
            # cargo-fmt = pkgs.runCommand "check-cargo-fmt"
            #  { inherit (devShells.default) nativeBuildInputs buildInputs; } ''
            #  cargo fmt --manifest-path=${src}/Cargo.toml --check > $out
            # '';
            nixpkgs-fmt = pkgs.runCommand "check-nixpkgs-fmt"
              { nativeBuildInputs = [ pkgs.nixpkgs-fmt ]; } ''
              nixpkgs-fmt --check ${./.} > $out
            '';
          };
        }))
    ];
}
