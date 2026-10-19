# Rosenpass papers:

This directory is containing publications by the Rosenpass project. You find this readme either within the source directory or the branch holding the built PDFs files.

## Direct links to the PDF files

[Whitepaper](https://github.com/rosenpass/rosenpass/blob/papers-pdf/whitepaper.pdf)

## Local build instructions

Requirements: To build the PDF files from Markdown you have to use at least TeX Live 2021 and python-pygments for the syntax highlighting.

You can build the PDF files from Markdown using `latexmk`. Simply run

```
latexmk -r tex/CI.rc
```

inside `papers/`. The PDF files will be located directly in `papers/`.

## Add version info within the template-rosenpass files

The version info is using gitinfo2. To use the setup one has to run the `papers/tex/gitinfo2.sh` script. In local copies it's also possible to add this as a post-checkout or post-commit hook to keep it automatically up to date.

The version information in the footer automatically includes a “draft”. This can be removed by tagging a release version using `\jobname-release`, e.h. `whitepaper-release` for the `whitepaper.md` file.

## Licensing of assets

The text files and graphics in this folder (i.e. whitepaper.md, the SVG, PDF, and PNG files in the graphics/ folder) are released under the CC BY-SA 4.0 license.
