use base64ct::{Base64, Decoder as B64Reader, Encoder as B64Writer};
use zeroize::Zeroize;

use std::fmt::Display;

pub struct B64DisplayHelper<'a, const F: usize>(&'a [u8]);

impl<const F: usize> Display for B64DisplayHelper<'_, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut bytes = [0u8; F];
        let string = b64_encode(&self.0, &mut bytes).map_err(|_| std::fmt::Error)?;
        let result = f.write_str(string);
        bytes.zeroize();
        result
    }
}

pub trait B64Display {
    fn fmt_b64<'o, const F: usize>(&'o self) -> B64DisplayHelper<'o, F>;
}

impl B64Display for [u8] {
    fn fmt_b64<'o, const F: usize>(&'o self) -> B64DisplayHelper<'o, F> {
        B64DisplayHelper(self)
    }
}

impl<T: AsRef<[u8]>> B64Display for T {
    fn fmt_b64<'o, const F: usize>(&'o self) -> B64DisplayHelper<'o, F> {
        B64DisplayHelper(self.as_ref())
    }
}

pub fn b64_decode(input: &[u8], output: &mut [u8]) -> anyhow::Result<()> {
    let mut reader = B64Reader::<Base64>::new(input).map_err(|e| anyhow::anyhow!(e))?;
    reader.decode(output).map_err(|e| anyhow::anyhow!(e))?;
    if reader.is_finished() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Input not decoded completely (buffer size too small?)"
        ))
    }
}

pub fn b64_encode<'o>(input: &[u8], output: &'o mut [u8]) -> anyhow::Result<&'o str> {
    let mut writer = B64Writer::<Base64>::new(output).map_err(|e| anyhow::anyhow!(e))?;
    writer.encode(input).map_err(|e| anyhow::anyhow!(e))?;
    writer.finish().map_err(|e| anyhow::anyhow!(e))
}
