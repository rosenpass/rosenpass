{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  inputs.poetry2nix.url = "github:nix-community/poetry2nix";
  inputs.flake-utils.url = "github:numtide/flake-utils";

  outputs = (inputs:
    let scoped = (scope: scope.result);
    in scoped rec {
      inherit (builtins) removeAttrs;

      result = (import ./nix/init.nix) {
        scoped = scoped;
        flake.self = inputs.self;
        flake.inputs = removeAttrs inputs ["self"];
      };
    }
  );
}
