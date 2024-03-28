{
  inputs = {
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
        "aarch64-linux"

        # unsuported best-effort
        "i686-linux"
        "x86_64-darwin"
        "aarch64-darwin"
        # "x86_64-windows"
      ]
        (system:
          let
            scoped = (scope: scope.result);
            lib = nixpkgs.lib;

            # normal nixpkgs
            pkgs = import nixpkgs {
              inherit system;
            };

            # parsed Cargo.toml
            cargoToml = builtins.fromTOML (builtins.readFile ./rosenpass/Cargo.toml);

            # source files relevant for rust
            src = scoped rec {
              # File suffices to include
              extensions = [
                "lock"
                "rs"
                "toml"
              ];
              # Files to explicitly include
              files = [
                "to/README.md"
              ];

              src = ./.;
              filter = (path: type: scoped rec {
                inherit (lib) any id removePrefix hasSuffix;
                anyof = (any id);

                basename = baseNameOf (toString path);
                relative = removePrefix (toString src + "/") (toString path);

                result = anyof [
                  (type == "directory")
                  (any (ext: hasSuffix ".${ext}" basename) extensions)
                  (any (file: file == relative) files)
                ];
              });

              result = pkgs.lib.sources.cleanSourceWith { inherit src filter; };
            };

            # a function to generate a nix derivation for rosenpass against any
            # given set of nixpkgs
            rosenpassDerivation = p:
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

                # used to trick the build.rs into believing that CMake was ran **again**
                fakecmake = pkgs.writeScriptBin "cmake" ''
                  #! ${pkgs.stdenv.shell} -e
                  true
                '';
              in
              naersk.buildPackage
                {
                  # metadata and source
                  name = cargoToml.package.name;
                  version = cargoToml.package.version;
                  inherit src;

                  cargoBuildOptions = x: x ++ [ "-p" "rosenpass" ];
                  cargoTestOptions = x: x ++ [ "-p" "rosenpass" ];

                  doCheck = true;

                  nativeBuildInputs = with pkgs; [
                    p.stdenv.cc
                    cmake # for oqs build in the oqs-sys crate
                    mandoc # for the built-in manual
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
                    # CMake detects that it was served a _foreign_ target dir, and CMake
                    # would be executed again upon the second build step of naersk.
                    # By adding our specially optimized CMake version, we reduce the cost
                    # of recompilation by 99 % while, while avoiding any CMake errors.
                    nativeBuildInputs = [ (lib.hiPrio fakecmake) ] ++ x.nativeBuildInputs;

                    # make sure that libc is linked, under musl this is not the case per
                    # default
                    preBuild = (lib.optionalString isStatic ''
                      NIX_CFLAGS_COMPILE="$NIX_CFLAGS_COMPILE -lc"
                    '');
                  };

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
            # a function to generate a nix derivation for the rp helper against any
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

                # used to trick the build.rs into believing that CMake was ran **again**
                fakecmake = pkgs.writeScriptBin "cmake" ''
                  #! ${pkgs.stdenv.shell} -e
                  true
                '';
              in
              naersk.buildPackage
                {
                  # metadata and source
                  name = cargoToml.package.name;
                  version = cargoToml.package.version;
                  inherit src;

                  cargoBuildOptions = x: x ++ [ "-p" "rp" ];
                  cargoTestOptions = x: x ++ [ "-p" "rp" ];

                  doCheck = true;

                  nativeBuildInputs = with pkgs; [
                    p.stdenv.cc
                    cmake # for oqs build in the oqs-sys crate
                    mandoc # for the built-in manual
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
                    # CMake detects that it was served a _foreign_ target dir, and CMake
                    # would be executed again upon the second build step of naersk.
                    # By adding our specially optimized CMake version, we reduce the cost
                    # of recompilation by 99 % while, while avoiding any CMake errors.
                    nativeBuildInputs = [ (lib.hiPrio fakecmake) ] ++ x.nativeBuildInputs;

                    # make sure that libc is linked, under musl this is not the case per
                    # default
                    preBuild = (lib.optionalString isStatic ''
                      NIX_CFLAGS_COMPILE="$NIX_CFLAGS_COMPILE -lc"
                    '');
                  };

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
              rosenpass = rosenpassDerivation pkgs;
              rp = rpDerivation pkgs;
              rosenpass-oci-image = rosenpassOCI "rosenpass";

              # derivation for the release
              release-package =
                let
                  version = cargoToml.package.version;
                  package =
                    if pkgs.hostPlatform.isLinux then
                      packages.rosenpass-static
                    else packages.rosenpass;
                  rp =
                    if pkgs.hostPlatform.isLinux then
                      packages.rp-static
                    else packages.rp;
                  oci-image =
                    if pkgs.hostPlatform.isLinux then
                      packages.rosenpass-static-oci-image
                    else packages.rosenpass-oci-image;
                in
                pkgs.runCommandNoCC "lace-result" { }
                  ''
                    mkdir {bin,$out}
                    tar -cvf $out/rosenpass-${system}-${version}.tar \
                      -C ${package} bin/rosenpass \
                      -C ${rp} bin/rp
                    cp ${oci-image} \
                      $out/rosenpass-oci-image-${system}-${version}.tar.gz
                  '';
            } // (if pkgs.stdenv.isLinux then rec {
              rosenpass-static = rosenpassDerivation pkgs.pkgsStatic;
              rp-static = rpDerivation pkgs.pkgsStatic;
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
              tlsetup = (pkgs.texlive.combine {
                inherit (pkgs.texlive) scheme-basic acmart amsfonts ccicons
                  csquotes csvsimple doclicense fancyvrb fontspec gobble
                  koma-script ifmtarg latexmk lm markdown mathtools minted noto
                  nunito pgf soul unicode-math lualatex-math paralist
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
            src = pkgs.lib.sources.sourceByRegex ./. [
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
              cmake # override the fakecmake from the main step above
              cargo-release
              clippy
              nodePackages.prettier
              rustfmt
              packages.proverif-patched
            ];
          };
          devShells.coverage = pkgs.mkShell {
            inputsFrom = [ packages.default ];
            nativeBuildInputs = with pkgs; [ inputs.fenix.packages.${system}.complete.toolchain cargo-llvm-cov ];
          };


          checks = {
            cargo-fmt = pkgs.runCommand "check-cargo-fmt"
              { inherit (self.devShells.${system}.default) nativeBuildInputs buildInputs; } ''
              cargo fmt --manifest-path=${./.}/Cargo.toml --check --all && touch $out
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
