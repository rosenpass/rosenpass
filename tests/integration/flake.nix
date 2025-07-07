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
          rosenpass-old = inputs.rosenpass-old.packages.${system}.default.overrideAttrs (old: {
            doCheck = false;
          });
          rosenpass-new = inputs.rosenpass-new.packages.${system}.default.overrideAttrs (old: {
            doCheck = false;
          });

          basicConnectivityOverlay = final: prev: {
            rosenpass-peer-a = rosenpass-new;
            rosenpass-peer-b = rosenpass-new;
          };

          backwardServerOverlay = final: prev: {
            rosenpass-peer-a = rosenpass-old;
            rosenpass-peer-b = rosenpass-new;
          };

          backwardClientOverlay = final: prev: {
            rosenpass-peer-a = rosenpass-new;
            rosenpass-peer-b = rosenpass-old;
          };

          multiPeerOverlay = final: prev: {
            rosenpass-peer-a = rosenpass-new;
            rosenpass-peer-b = rosenpass-new;
            rosenpass-peer-c = rosenpass-new;
          };

          # The current version of ipython fails to build on i686 linux.
          # We therefore pin an older version that works for the time beeing.
          ipythonOverlay = final: prev: {
            python313 = prev.python313.override {
              packageOverrides = python-final: python-prev: {
                ipython = python-prev.ipython.overridePythonAttrs (old: {
                  version = "8.37.0";
                  src = python-final.fetchPypi {
                    pname = "ipython";
                    version = "8.37.0";
                    hash = "sha256-yoFYQeGkGh5rc6CwjzA4r5siUlZNAfxAU1bTQDMBIhY=";
                  };
                });
              };
            };
          };

          pkgsBasicConnectivity = import inputs.nixpkgs {
            inherit system;
            overlays = [
              basicConnectivityOverlay
              ipythonOverlay
            ];
          };

          pkgsBackwardServer = import inputs.nixpkgs {
            inherit system;
            overlays = [
              backwardServerOverlay
              ipythonOverlay
            ];
          };

          pkgsBackwardClient = import inputs.nixpkgs {
            inherit system;
            overlays = [
              backwardClientOverlay
              ipythonOverlay
            ];
          };

          pkgsMultiPeer = import inputs.nixpkgs {
            inherit system;
            overlays = [
              multiPeerOverlay
              ipythonOverlay
            ];
          };

        in
        {
          checks.basicConnectivity = pkgsBasicConnectivity.testers.runNixOSTest (
            import ./rpsc-test.nix {
              pkgs = pkgsBasicConnectivity;
              inherit lib;
            }
          );

          checks.backwardServer = pkgsBackwardServer.testers.runNixOSTest (
            import ./rpsc-test.nix {
              pkgs = pkgsBackwardServer;
              inherit lib;
            }
          );

          checks.backwardClient = pkgsBackwardClient.testers.runNixOSTest (
            import ./rpsc-test.nix {
              pkgs = pkgsBackwardClient;
              inherit lib;
            }
          );

          checks.multiPeer = pkgsMultiPeer.testers.runNixOSTest (
            import ./rpsc-test.nix {
              pkgs = pkgsMultiPeer;
              inherit lib;
              multiPeer = true;
            }
          );
        };
    };
}
