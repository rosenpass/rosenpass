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
    # TOML config files are written in TOML 1.1 but the formatter only supports TOML 1.0
    # https://github.com/tamasfe/taplo/issues/332
    excludes = [
      "rosenpass/src/config/tests/data/configs/full.toml"
      "rosenpass/src/config/tests/data/configs/full-raw.toml"
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
