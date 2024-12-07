# Contributing to Rosenpass

## Common operations

### Apply code formatting

Format rust code:

```bash
cargo fmt
```

Format rust code in markdown files:

```bash
./format_rust_code.sh --mode fix
```

### Spawn a development environment with nix

```bash
nix develop .#fullEnv
```

You need to [install this nix package manager](https://wiki.archlinux.org/title/Nix) first.

### Run our test

Make sure to increase the stack size available; some of our cryptography operations require a lot of stack memory.

```bash
RUST_MIN_STACK=8388608 cargo test --workspace --all-features
```

### Generate coverage reports

Keep in mind that many of Rosenpass' tests are doctests, so to get an accurate read on our code coverage, you have to include doctests:

```bash
./coverage_report.sh
```
