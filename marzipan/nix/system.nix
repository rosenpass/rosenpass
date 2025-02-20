ctx: ctx.scoped rec {
  inherit (ctx.system) pkgs;
  inherit (ctx.flake.inputs) poetry2nix flake-utils;
  inherit (pkgs) mkShellNoCC writeShellApplication;
  inherit (flake-utils.lib) mkApp;

  poetryCtx = poetry2nix.lib.mkPoetry2Nix { inherit pkgs; };
  inherit (poetryCtx) mkPoetryEnv mkPoetryApplication;

  deps = [poetryEnv];
  dev-deps = [] 
    ++ deps
    ++ [poetryHyugaEnv]
    ++ (with pkgs; [poetry]);

  poetryCfg = ctx.config.poetry // { overrides = poetryOverrides; };
  poetryEnv = mkPoetryEnv poetryCfg;

  poetryHyugaCfg = poetryCfg // { projectDir = ./hyuga; };
  poetryHyugaEnv = mkPoetryEnv poetryHyugaCfg;

  poetryOverrides = poetryCtx.defaultPoetryOverrides.extend (final: prev: {
    hyuga = prev.hyuga.overridePythonAttrs (old: {
        buildInputs = []
          ++ (old.buildInputs or [ ])
          ++ [ final.poetry-core ];
        preferWheel = true;
      }
    );
  });

  result.packages.default = mkPoetryApplication poetryCfg;
  result.devShells.default = mkShellNoCC {
    packages = dev-deps;
  };

  result.apps.replPython = mkShellApp "python-repl" ''python'';
  result.apps.replHy = mkShellApp "hy-repl" ''hy'';

  mkShellApp = (name: script: mkApp {
    drv = writeShellApplication {
      inherit name;
      text = script;
      runtimeInputs = dev-deps;
    };
  });
}
