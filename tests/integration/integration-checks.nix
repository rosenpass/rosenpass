{
  pkgs,
  lib,
  system,
  rosenpassOld,
  rosenpassNew,
  ...
}:
let
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

  basicConnectivityOverlay = final: prev: {
    rosenpass-peer-a = rosenpassNew;
    rosenpass-peer-b = rosenpassNew;
  };

  backwardServerOverlay = final: prev: {
    rosenpass-peer-a = rosenpassOld;
    rosenpass-peer-b = rosenpassNew;
  };

  backwardClientOverlay = final: prev: {
    rosenpass-peer-a = rosenpassNew;
    rosenpass-peer-b = rosenpassOld;
  };

  multiPeerOverlay = final: prev: {
    rosenpass-peer-a = rosenpassNew;
    rosenpass-peer-b = rosenpassNew;
    rosenpass-peer-c = rosenpassNew;
  };

  pkgsBasicConnectivity = import pkgs {
    inherit system;
    overlays = [
      basicConnectivityOverlay
      ipythonOverlay
    ];
  };

  pkgsBackwardServer = import pkgs {
    inherit system;
    overlays = [
      backwardServerOverlay
      ipythonOverlay
    ];
  };

  pkgsBackwardClient = import pkgs {
    inherit system;
    overlays = [
      backwardClientOverlay
      ipythonOverlay
    ];
  };

  pkgsMultiPeer = import pkgs {
    inherit system;
    overlays = [
      multiPeerOverlay
      ipythonOverlay
    ];
  };

  generatedChecks = {
    basicConnectivity = pkgsBasicConnectivity.testers.runNixOSTest (
      import ./rpsc-test.nix {
        pkgs = pkgsBasicConnectivity;
        inherit lib;
      }
    );

    backwardServer = pkgsBackwardServer.testers.runNixOSTest (
      import ./rpsc-test.nix {
        pkgs = pkgsBackwardServer;
        inherit lib;
      }
    );

    backwardClient = pkgsBackwardClient.testers.runNixOSTest (
      import ./rpsc-test.nix {
        pkgs = pkgsBackwardClient;
        inherit lib;
      }
    );

    multiPeer = pkgsMultiPeer.testers.runNixOSTest (
      import ./rpsc-test.nix {
        pkgs = pkgsMultiPeer;
        inherit lib;
        multiPeer = true;
      }
    );
  };
in
generatedChecks
