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
      "*.toml"
      "*.yaml"
      "*.yml"
    ];
    excludes = [ "supply-chain/*" ];
    settings = {
      plugins = [
        "${pkgs.nodePackages.prettier-plugin-toml}/lib/node_modules/prettier-plugin-toml/lib/index.js"
      ];
    };
  };
  programs.rustfmt.enable = true;
}
