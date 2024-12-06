# Contributing to Rosenpass

## Common operations

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
cargo llvm-cov --all-features --workspace --doctests --html --open
```
