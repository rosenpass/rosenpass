pub type Rng = rand::rngs::ThreadRng;

pub fn rng() -> Rng {
    rand::thread_rng()
}
