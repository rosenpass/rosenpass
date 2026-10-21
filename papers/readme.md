# Rosenpass papers:

This directory is containing publications by the Rosenpass project. You find this readme either within the source directory or the branch holding the built PDFs files.

## Download

You can download the whitepaper PDF directly from our website: <https://rosenpass.eu/docs/whitepaper/>

## Build

This whitepaper is built with [Nix](https://nixos.org/download/) (you might need to enable [Nix flakes](https://nixos.wiki/wiki/flakes) manually).

1. change directory to `papers` and run the `gitinfo2` script:

```sh
cd papers
./tex/gitinfo2.sh
git add gitHeadInfo.gin
```

2. switch back to the project root directory and build with Nix:

```sh
cd ..
nix build .#whitepaper
```

The resulting artifact is in `result/whitepaper.pdf`.

**Alternatively,** you can try using `cd papers && latexmk -r tex/CI.rc` (not an official way to build the whitepaper).

The version information in the PDF footer automatically includes a “draft”. This can be removed by tagging a release version using `\jobname-release`, e.h. `whitepaper-release` for the `whitepaper.md` file.

## Licensing of assets

The text files and graphics in this folder (i.e. whitepaper.md, the SVG, PDF, and PNG files in the graphics/ folder) are released under the CC BY-SA 4.0 license.
