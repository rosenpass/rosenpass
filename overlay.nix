final: prev:

let
  inherit (prev) lib;

  # root dir of this flake
  flakeRoot = ./.;

  # all packages from the local tree
  rosenpassPackages = lib.filesystem.packagesFromDirectoryRecursive {
    # a special callPackage variant that contains our flakeRoot
    callPackage = lib.callPackageWith (final // { inherit flakeRoot; });

    # local tree of packages
    directory = ./pkgs;
  };
in
{
  inherit rosenpassPackages;
}
// rosenpassPackages
