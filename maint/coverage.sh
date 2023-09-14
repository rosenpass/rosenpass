#!/usr/bin/env bash
#
# In order use this, you need to have `grcov` in your path and `llvm-tools` in
# your Rust toolchain.
#
# ```sh
# cargo install grcov
# rustup component add llvm-tools
# ```

BASEDIR=$(git rev-parse --show-toplevel)
COVERAGE="$BASEDIR/coverage"
FORMAT="lcov"
OUTPUT="$BASEDIR/lcov.info"

export RUST_MIN_STACK=16000000 # 16MB
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="$COVERAGE/rosenpass-%p-%m.profraw"

echo "Removing data from previous runs ..."
rm -rf "$COVERAGE"
rm -rf "$OUTPUT"
mkdir "$COVERAGE"

cargo build --all-features
cargo test --all-features

echo "Generating report ..."
grcov "$COVERAGE" \
	-s "$BASEDIR/src" \
	--binary-path "$BASEDIR/target/debug" \
	-t "$FORMAT" \
	--branch \
	--ignore-not-existing \
	--excl-start "^(pub(\((crate|super)\))? )?mod test" \
	--excl-stop "^}" \
	-o "$OUTPUT"
