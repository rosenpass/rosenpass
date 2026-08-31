# Contributing to Rosenpass

## Tooling

When contributing to this project, you probably want to use this tooling:

1. [install Nix package manager](https://nixos.org/download/)
2. get all shell with all tooling prived by running `nix develop`

## Before opening PRs

Before opening PRs, please

1. format the code with `nix fmt`
2. format Rust code in MarkDown files with `./format_rust_code.sh --mode fix`
3. run tests with `RUST_MIN_STACK=8388608 cargo test --workspace --all-features`

When making a larger contribution, please run the code coverage tool. Keep in mind that many of Rosenpass' tests are doctests, so to get an accurate read on our code coverage, you have to include doctests which is done by running: `./coverage_report.sh`

If you are a first-time contributer, feel free to contact us before starting any work. Upfront coordination can be really useful for everyone involved.
