{ pkgs, ... }:
{
  # Used to find the project root
  projectRootFile = "flake.nix";
  programs.nixfmt.enable = true;
  programs.prettier = {
    enable = true;
    includes = [
      "*.css"
      "*.html"
      "*.js"
      "*.json"
      "*.json5"
      "*.md"
      "*.mdx"
      "*.yaml"
      "*.yml"
    ];
    excludes = [ "supply-chain/*" ];
  };
  programs.taplo = {
    enable = true;
    includes = [
      "*.toml"
    ];
  };
  programs.rustfmt = {
    enable = true;
    # Use the rustfmt of the pinned project toolchain (rust-toolchain.toml,
    # exposed via the flake overlay) instead of the nixpkgs default, so
    # `nix fmt` and the `formatting` check agree with the project compiler.
    package = pkgs.rosenpass-rust-toolchain;
    includes = [
      "*.rs"
    ];
  };
}
