{
  description = "Integration tests for rosenpass";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rosenpass-old.url = "github:rosenpass/rosenpass/main";
    rosenpass-new.url = "github:rosenpass/rosenpass/main";
  };

  outputs = inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "i686-linux" "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];

      perSystem = { system, lib, ... }: let

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

        pkgsBasicConnectivity = import inputs.nixpkgs {
          inherit system;
          overlays = [ basicConnectivityOverlay ];
        };

        pkgsBackwardServer = import inputs.nixpkgs {
          inherit system;
          overlays = [ backwardServerOverlay ];
        };

        pkgsBackwardClient = import inputs.nixpkgs {
          inherit system;
          overlays = [ backwardClientOverlay ];
        };

        pkgsMultiPeer = import inputs.nixpkgs {
          inherit system;
          overlays = [ multiPeerOverlay ];
        };

      in {
        checks.basicConnectivity = pkgsBasicConnectivity.testers.runNixOSTest (import ./rpsc-test.nix {
          pkgs = pkgsBasicConnectivity;
          inherit lib;
        });

        checks.backwardServer = pkgsBackwardServer.testers.runNixOSTest (import ./rpsc-test.nix {
          pkgs = pkgsBackwardServer;
          inherit lib;
        });

        checks.backwardClient = pkgsBackwardClient.testers.runNixOSTest (import ./rpsc-test.nix {
          pkgs = pkgsBackwardClient;
          inherit lib;
        });

        checks.multiPeer = pkgsMultiPeer.testers.runNixOSTest (import ./rpsc-test.nix {
          pkgs = pkgsMultiPeer;
          inherit lib;
          multiPeer = true;
        });
      };
    };
}


