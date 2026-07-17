{ ... }:
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
    includes = [
      "*.rs"
    ];
  };
}
