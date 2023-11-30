/// Try block basically…returns a result and allows the use of the question mark operator inside
#[macro_export]
#[macro_export]
macro_rules! attempt {
    ($block:expr) => {
        (|| -> Result<_, _> {
            $block.map_err(|err| {
                ::rosenpass_util::SodiumError::LibSodiumError(err)
            })
        })()
    };
}
