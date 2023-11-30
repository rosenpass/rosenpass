use std::fmt;

/// Writes the contents of an `&[u8]` as hexadecimal symbols to a [std::fmt::Formatter]
pub fn debug_crypto_array(v: &[u8], fmt: &mut fmt::Formatter) -> fmt::Result {
    fmt.write_str("[{}]=")?;
    if v.len() > 64 {
        for byte in &v[..32] {
            std::fmt::LowerHex::fmt(byte, fmt)?;
        }
        fmt.write_str("…")?;
        for byte in &v[v.len() - 32..] {
            std::fmt::LowerHex::fmt(byte, fmt)?;
        }
    } else {
        for byte in v {
            std::fmt::LowerHex::fmt(byte, fmt)?;
        }
    }
    Ok(())
}
