/// Try block basically…returns a result and allows the use of the question mark operator inside
#[macro_export]
macro_rules! attempt {
    ($block:expr) => {
        (|| -> Result<_, ::rosenpass_util::SodiumError> {
            $block.map_err(|err| {
                // Converted anyhow::Error to SodiumError
                ::rosenpass_util::SodiumError::LibSodiumError(err)
            })
        })()
    };
}
