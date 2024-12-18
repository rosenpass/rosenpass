//! This module provides a helper for creating debug prints for byte slices.
//! See [debug_crypto_array] for more details.

use std::fmt;

/// Writes the contents of an `&[u8]` as hexadecimal symbols to a [std::fmt::Formatter].
/// # Example
///
/// ```rust
/// use std::fmt::{Debug, Formatter};
/// use rosenpass_secret_memory::debug::debug_crypto_array;
///
/// struct U8Wrapper {
///     pub u_eigt: Vec<u8>
/// }
/// impl Debug for U8Wrapper {fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
///  //         let dead_beef: [u8; 11] = [3, 3, 6, 5, 3, 3, 3, 7, 3, 5, 7];
///         debug_crypto_array(self.u_eigt.as_slice(), f)
///     }
/// }
/// // Short byte slices are printed completely.
/// let cafe = U8Wrapper {u_eigt: vec![1, 4, 5, 3, 7, 6]};
/// assert_eq!(format!("{:?}", cafe), "[{}]=145376");
/// // For longer byte slices, only the first 32 and last 32 bytes are printed.
/// let all_u8 = U8Wrapper {u_eigt: (0..256).map(|i| i as u8).collect()};
/// assert_eq!(format!("{:?}", all_u8), "[{}]=0123456789abcdef101112131415161718191a1b1c1d1e1f…e0e\
/// 1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
/// ```
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
