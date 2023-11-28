// TODO remove this once std::cmp::max becomes const
pub const fn max_usize(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}
