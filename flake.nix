{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";

    # for rust nightly with llvm-tools-preview
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";

    nix-vm-test.url = "github:numtide/nix-vm-test";
    nix-vm-test.inputs.nixpkgs.follows = "nixpkgs";
    nix-vm-test.inputs.flake-utils.follows = "flake-utils";

    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, nix-vm-test, treefmt-nix, ... }@inputs:
    nixpkgs.lib.foldl (a: b: nixpkgs.lib.recursiveUpdate a b) { } [


      #
      ### Export the overlay.nix from this flake ###
      #
      {
        overlays.default = import ./overlay.nix;
      }


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
              aarch64-linux-rosenpass-static =
                pkgs.pkgsCross.aarch64-multiplatform.pkgsStatic.rosenpass;
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
        ))


      #
      ### Linux specifics ###
      #
      (flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
        let
          pkgs = import nixpkgs {
            inherit system;

            # apply our own overlay, overriding/inserting our packages as defined in ./pkgs
            overlays = [
              self.overlays.default
              nix-vm-test.overlays.default
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
          devShells.default = pkgs.mkShell {
            inherit (pkgs.proof-proverif) CRYPTOVERIF_LIB;
            inputsFrom = [ pkgs.rosenpass ];
            nativeBuildInputs = with pkgs; [
              cargo-release
              clippy
              rustfmt
              nodePackages.prettier
              nushell # for the .ci/gen-workflow-files.nu script
              proverif-patched
            ];
          };
          # TODO: Write this as a patched version of the default environment
          devShells.fullEnv = pkgs.mkShell {
            inherit (pkgs.proof-proverif) CRYPTOVERIF_LIB;
            inputsFrom = [ pkgs.rosenpass ];
            nativeBuildInputs = with pkgs; [
              cargo-audit
              cargo-release
              cargo-msrv
              rustfmt
              nodePackages.prettier
              nushell # for the .ci/gen-workflow-files.nu script
              proverif-patched
              inputs.fenix.packages.${system}.complete.toolchain
              pkgs.cargo-llvm-cov
              pkgs.grcov
            ];
          };
          devShells.coverage = pkgs.mkShell {
            inputsFrom = [ pkgs.rosenpass ];
            nativeBuildInputs = [
              inputs.fenix.packages.${system}.complete.toolchain
              pkgs.cargo-llvm-cov
              pkgs.grcov
            ];
          };


          checks = {
            systemd-rosenpass = pkgs.testers.runNixOSTest ./tests/systemd/rosenpass.nix;
            systemd-rp = pkgs.testers.runNixOSTest ./tests/systemd/rp.nix;
            formatting = treefmtEval.config.build.check self;
          } // pkgs.lib.optionalAttrs (system == "x86_64-linux") (import ./tests/legacy-distro-packaging.nix {
            inherit pkgs;
            rosenpass-deb = self.packages.${system}.package-deb;
            rosenpass-rpm = self.packages.${system}.package-rpm;
          });

          # for `nix fmt`
          formatter = treefmtEval.config.build.wrapper;
        }))
    ];
}
