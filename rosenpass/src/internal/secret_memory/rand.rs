//! This module provides functionality for generating random numbers using the [rand] crate.

/// We use the [`ThreadRng`](rand::rngs::ThreadRng) for randomness in this module.
pub type Rng = rand::rngs::ThreadRng;

/// Get the default [Rng].
pub fn rng() -> Rng {
    rand::rng()
}
