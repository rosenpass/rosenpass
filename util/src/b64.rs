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
    match reader.decode(output) {
        Ok(_) => (),
        Err(base64ct::Error::InvalidLength) => (),
        Err(e) => {
            return Err(anyhow::anyhow!(e));
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b64_encode() {
        let input = b"Hello, World!";
        let mut output = [0u8; 20];
        let result = b64_encode(input, &mut output);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_b64_encode_small_buffer() {
        let input = b"Hello, World!";
        let mut output = [0u8; 10]; // Small output buffer
        let result = b64_encode(input, &mut output);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "invalid Base64 length");
    }

    #[test]
    fn test_b64_encode_empty_buffer() {
        let input = b"";
        let mut output = [0u8; 16];
        let result = b64_encode(input, &mut output);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_b64_decode() {
        let input = b"SGVsbG8sIFdvcmxkIQ==";
        let mut output = [0u8; 1000];
        b64_decode(input, &mut output).unwrap();
        assert_eq!(&output[..13], b"Hello, World!");
    }

    #[test]
    fn test_b64_decode_small_buffer() {
        let input = b"SGVsbG8sIFdvcmxkIQ==";
        let mut output = [0u8; 10]; // Small output buffer
        let result = b64_decode(input, &mut output);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Input not decoded completely (buffer size too small?)"
        );
    }

    #[test]
    fn test_b64_decode_empty_buffer() {
        let input = b"";
        let mut output = [0u8; 16];
        let result = b64_decode(input, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn test_fmt_b64() {
        let input = b"Hello, World!";
        let result = input.fmt_b64::<20>().to_string();
        assert_eq!(result, "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn test_fmt_b64_empty_input() {
        let input = b"";
        let result = input.fmt_b64::<16>().to_string();
        assert_eq!(result, "");
    }
}
