//! Additional helpers to [std::convert]: Traits for conversions between types.

/// Variant of [std::convert::Into] with an explicitly specified type.
///
/// This facilitates method chaining.
///
/// # Examples
///
/// We can create a nicer implementation of the following function using this extension trait
///
/// ```
/// use rosenpass_util::convert::IntoTypeExt;
///
/// fn encode_char_u32_be_1(c: char) -> [u8; 4] {
///     let i : u32 = c.into();
///     i.to_be_bytes()
/// }
///
/// fn encode_char_u32_be_2(c: char) -> [u8; 4] {
///     c.into_type::<u32>().to_be_bytes()
/// }
///
/// assert_eq!(encode_char_u32_be_1('X'), [0x00, 0x00, 0x00, 0x58]);
/// assert_eq!(encode_char_u32_be_1('X'), encode_char_u32_be_2('X'));
///
/// ```
pub trait IntoTypeExt {
    /// Variant of [std::convert::Into] with explicitly specified type.
    ///
    /// # Examples
    ///
    /// See [IntoType].
    fn into_type<T>(self) -> T
    where
        Self: Into<T>,
    {
        self.into()
    }
}

impl<T> IntoTypeExt for T {}

/// Variant of [std::convert::TryInto] with an explicitly specified type.
///
/// This facilitates method chaining.
///
/// # Examples
///
/// We can create a nicer implementation of the following function using this extension trait
///
/// ```
/// use rosenpass_util::convert::TryIntoTypeExt;
/// use rosenpass_util::result::OkExt;
///
/// fn encode_char_u16_be_1(c: char) -> Result<[u8; 2], <char as TryInto<u16>>::Error> {
///     let i : u16 = c.try_into()?;
///     Ok(i.to_be_bytes())
/// }
///
/// fn encode_char_u16_be_2(c: char) -> Result<[u8; 2], <char as TryInto<u16>>::Error> {
///     c.try_into_type::<u16>()?.to_be_bytes().ok()
/// }
///
/// assert_eq!(encode_char_u16_be_1('X'), Ok([0x00, 0x58]));
/// assert_eq!(encode_char_u16_be_1('X'), encode_char_u16_be_2('X'));
///
/// const HEART_CAT : char = '😻'; // 1F63B
/// assert!(encode_char_u16_be_1(HEART_CAT).is_err());
/// assert_eq!(encode_char_u16_be_1(HEART_CAT), encode_char_u16_be_2(HEART_CAT));
/// ```
pub trait TryIntoTypeExt {
    /// Variant of [std::convert::TryInto] with explicitly specified type.
    ///
    /// # Examples
    ///
    /// See [TryIntoType].
    fn try_into_type<T>(self) -> Result<T, <Self as TryInto<T>>::Error>
    where
        Self: TryInto<T>,
    {
        self.try_into()
    }
}

impl<T> TryIntoTypeExt for T {}
