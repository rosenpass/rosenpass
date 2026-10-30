{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";

    nix-vm-test.url = "github:numtide/nix-vm-test";
    nix-vm-test.inputs.nixpkgs.follows = "nixpkgs";
    nix-vm-test.inputs.flake-utils.follows = "flake-utils";

    # for rust nightly with llvm-tools-preview
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";

    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";

    # older version of rosenpass against which backwards-compatibility integration tests are run
    #
    # This input is usually overriden by the CI which executes the tests (see .github/workflows/integration.yml) but the default value is sensible, too.
    # 512fe426be9281366d92a910d391fe8ddd72bd10 is v0.2.3
    rosenpassOld.url = "github:rosenpass/rosenpass?rev=512fe426be9281366d92a910d391fe8ddd72bd10";
    rosenpassOld.inputs.nixpkgs.follows = "nixpkgs"; # TODO: why do we need this line?
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      nix-vm-test,
      rust-overlay,
      treefmt-nix,
      rosenpassOld,
      ...
    }@inputs:
    nixpkgs.lib.foldl (a: b: nixpkgs.lib.recursiveUpdate a b) { } [

      #
      ### Export the packages with the pinned project toolchain ###
      #
      {
        overlays.default = nixpkgs.lib.composeManyExtensions [
          rust-overlay.overlays.default
          (import ./overlay.nix)
          (
            final: prev:
            let
              rustPlatform = final.makeRustPlatform {
                cargo = final.buildPackages.rosenpass-rust-toolchain;
                rustc = final.buildPackages.rosenpass-rust-toolchain;
              };
            in
            {
              # rust-overlay enables Cargo's libsecret credential integration
              # by default on Linux. It pulls in libsecret, whose test suite is
              # flaky in the Nix build sandbox (e.g. on i686-linux), and this
              # project doesn't use Cargo credentials.
              rosenpass-rust-toolchain = (final.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
                enableLibsecret = false;
              };
              rosenpass = prev.rosenpass.override { inherit rustPlatform; };
              rp = prev.rp.override { inherit rustPlatform; };
            }
          )
        ];
      }

      #
      ### Actual Rosenpass Package and Docker Container Images ###
      #
      (flake-utils.lib.eachSystem
        [
          "x86_64-linux"
          "aarch64-linux"

          # unsuported best-effort
          "i686-linux"
          "x86_64-darwin"
          "aarch64-darwin"
          # "x86_64-windows"
        ]
        (
          system:
          let
            # normal nixpkgs
            pkgs = import nixpkgs {
              inherit system;

              # apply our own overlay, overriding/inserting our packages as defined in ./pkgs
              overlays = [ self.overlays.default ];
            };
          in
          {
            packages = {
              default = pkgs.rosenpass;
              rosenpass = pkgs.rosenpass;
              rosenpass-oci-image = pkgs.rosenpass-oci-image;
              rp = pkgs.rp;

              release-package = pkgs.release-package;

              # for good measure, we also offer to cross compile to Linux on Arm
              aarch64-linux-rosenpass-static = pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic.rosenpass;
              aarch64-linux-rp-static = pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic.rp;
            }
            //
              # We only offer static builds for linux, as this is not supported on OS X
              (nixpkgs.lib.attrsets.optionalAttrs pkgs.stdenv.isLinux {
                rosenpass-static = pkgs.pkgsStatic.rosenpass;
                rosenpass-static-oci-image = pkgs.pkgsStatic.rosenpass-oci-image;
                rp-static = pkgs.pkgsStatic.rp;
              });
          }
        )
      )

      #
      ### Linux specifics ###
      #
      (flake-utils.lib.eachSystem
        [
          "x86_64-linux"
          "aarch64-linux"
          "i686-linux"
        ]
        (
          system:
          let
            pkgs = import nixpkgs {
              inherit system;

              overlays = [
                # apply our own overlay, overriding/inserting our packages as defined in ./pkgs
                self.overlays.default

                nix-vm-test.overlays.default
              ];
            };

            fullEnv = pkgs.mkShell {
              inherit (pkgs.proof-proverif) CRYPTOVERIF_LIB;
              inputsFrom = [ pkgs.rosenpass ];
              nativeBuildInputs = with pkgs; [
                cargo-audit
                cargo-deny
                cargo-msrv
                cargo-nextest
                cargo-release
                cargo-vet
                prettier
                proverif-patched
                pkgs.cargo-llvm-cov
                pkgs.grcov
              ];
            };
            treefmtEval = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;
          in
          {
            packages.package-deb = pkgs.callPackage ./pkgs/package-deb.nix {
              rosenpass = pkgs.pkgsStatic.rosenpass;
            };
            packages.package-rpm = pkgs.callPackage ./pkgs/package-rpm.nix {
              rosenpass = pkgs.pkgsStatic.rosenpass;
            };

            #
            ### Reading materials ###
            #
            packages.whitepaper = pkgs.whitepaper;

            #
            ### Proof and Proof Tools ###
            #
            packages.proverif-patched = pkgs.proverif-patched;
            packages.proof-proverif = pkgs.proof-proverif;

            #
            ### Devshells ###
            #
            # TODO: Write this as a patched version of the default environment
            devShells = {
              inherit fullEnv;
              default = fullEnv; # appropriate for most development work
              coverage = pkgs.mkShell {
                inputsFrom = [ pkgs.rosenpass ];
                nativeBuildInputs = [
                  pkgs.cargo-llvm-cov
                  pkgs.grcov
                ];
                env = {
                  LLVM_COV = "${pkgs.rosenpass-rust-toolchain}/lib/rustlib/${pkgs.stdenv.buildPlatform.rust.rustcTarget}/bin/llvm-cov";
                  LLVM_PROFDATA = "${pkgs.rosenpass-rust-toolchain}/lib/rustlib/${pkgs.stdenv.buildPlatform.rust.rustcTarget}/bin/llvm-profdata";
                };
              };
              benchmarks = pkgs.mkShell {
                inputsFrom = [ pkgs.rosenpass ];
                nativeBuildInputs = with pkgs; [
                  cargo-release
                ];
              };
              # a devshell to hunt unsafe `unsafe` in the code
              miri = pkgs.mkShell {
                # inputsFrom = [ self.packages.${system}.rosenpass ];
                nativeBuildInputs = with pkgs; [
                  ((rust-bin.selectLatestNightlyWith (toolchain: toolchain.default)).override {
                    extensions = [
                      "rust-analysis"
                      "rust-src"
                      "miri-preview"
                    ];
                  })
                  pkgs.cmake
                  pkgs.rustPlatform.bindgenHook
                ];
                # Run this to find unsafe `unsafe`:
                # MIRIFLAGS="-Zmiri-disable-isolation" cargo miri test --no-fail-fast --lib --bins --tests
                #
                # - Some test failure is expected.
              };
            };

            checks =
              let
                integrationChecks = import ./tests/integration/integration-checks.nix {
                  inherit system;
                  pkgs = inputs.nixpkgs;
                  lib = nixpkgs.lib;
                  rosenpassNew = self.packages.${system}.rosenpass-static;
                  rosenpassOld = inputs.rosenpassOld.packages.${system}.rosenpass-static.overrideAttrs (old: {
                    doCheck = false; # no need to re-run the check for the old version
                  });
                };
              in
              integrationChecks
              // {
                # Aggregate target so the CI can run just the integration tests:
                # nix build .#checks.<system>.integration
                # docs: https://noogle.dev/f/pkgs/linkFarm/
                integration = pkgs.linkFarm "integration-checks" integrationChecks;
                systemd-rosenpass = pkgs.testers.runNixOSTest ./tests/systemd/rosenpass.nix;
                systemd-rp = pkgs.testers.runNixOSTest ./tests/systemd/rp.nix;
                formatting = treefmtEval.config.build.check self;
                # PLACEHOLDER: until stable Rust 1.100.0 is released
                # (expected 2026-11-12), the fallback below resolves to the
                # pinned beta toolchain, so this check builds the normal
                # beta package and provides no MSRV signal.
                rosenpass-msrv-check =
                  let
                    rosenpassCargoToml = pkgs.lib.trivial.importTOML ./rosenpass/Cargo.toml;

                    msrv = rosenpassCargoToml.package.rust-version;
                    # Use the matching beta until this MSRV is released on stable.
                    rustToolchain =
                      pkgs.rust-bin.stable.${msrv}.default
                        or (builtins.warn "rosenpass-msrv-check: no stable Rust ${msrv} exists yet; falling back to the pinned project toolchain (${pkgs.rosenpass-rust-toolchain.version}), so this check is a placeholder with no MSRV signal" pkgs.rosenpass-rust-toolchain);
                    rustPlatform = pkgs.makeRustPlatform {
                      cargo = rustToolchain;
                      rustc = rustToolchain;
                    };
                  in
                  pkgs.rosenpass.override { inherit rustPlatform; };
                # Test specific feature combinations: experiment_api
                rosenpass-feat-experiment-api = pkgs.rosenpass.overrideAttrs (old: {
                  name = "rosenpass-feat-experiment-api";
                  cargoBuildFeatures = [ "experiment_api" ];
                  cargoCheckFeatures = [ "experiment_api" ];
                });
                # Test specific feature combinations: expose_internal_modules
                rosenpass-feat-expose-internal-modules = pkgs.rosenpass.overrideAttrs (old: {
                  name = "rosenpass-feat-expose-internal-modules";
                  cargoBuildFeatures = [ "expose_internal_modules" ];
                  cargoCheckFeatures = [ "expose_internal_modules" ];
                });
              }
              // pkgs.lib.optionalAttrs (system == "x86_64-linux") (
                import ./tests/legacy-distro-packaging.nix {
                  inherit pkgs;
                  rosenpass-deb = self.packages.${system}.package-deb;
                  rosenpass-rpm = self.packages.${system}.package-rpm;
                }
              );

            # for `nix fmt`
            formatter = treefmtEval.config.build.wrapper;
          }
        )
      )
    ];
}
