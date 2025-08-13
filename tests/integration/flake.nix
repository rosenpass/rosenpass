{
  description = "Integration tests for rosenpass";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    # Override or change these inputs for testing new Integrations. They are overriden automatically when run in the CI
    rosenpass-old.url = "github:rosenpass/rosenpass/main";
    rosenpass-new.url = "github:rosenpass/rosenpass/main";
  };
  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "i686-linux"
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem =
        { system, lib, ... }:
        let
          # Since other parts of the CI are already doing the unit tests, we deactivate them here.
          rosenpassOld = inputs.rosenpass-old.packages.${system}.default.overrideAttrs (old: {
            doCheck = false;
          });
          rosenpassNew = inputs.rosenpass-new.packages.${system}.default.overrideAttrs (new: {
            doCheck = false;
          });
          defaultChecks = import ./integration-checks.nix {
            inherit
              system
              lib
              rosenpassNew
              rosenpassOld
              ;
            pkgs = inputs.nixpkgs;
          };
        in
        {
          checks = defaultChecks;
        };
    };
}
