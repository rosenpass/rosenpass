//! Data structures representing the messages going over the wire
//!
//! This module contains de-/serialization of the protocol's messages. Thats kind
//! of a lie, since no actual ser/de happens. Instead, the structures offer views
//! into mutable byte slices (`&mut [u8]`), allowing to modify the fields of an
//! always serialized instance of the data in question. This is closely related
//! to the concept of lenses in function programming; more on that here:
//! [https://sinusoid.es/misc/lager/lenses.pdf](https://sinusoid.es/misc/lager/lenses.pdf)
//!
//! # Example
//!
//! The following example uses the [`data_lense` macro](crate::data_lense) to create a lense that
//! might be useful when dealing with UDP headers.
//!
//! ```
//! use rosenpass::{data_lense, RosenpassError, msgs::LenseView};
//! # fn main() -> Result<(), RosenpassError> {
//!
//! data_lense! {UdpDatagramHeader :=
//!     source_port: 2,
//!     dest_port: 2,
//!     length: 2,
//!     checksum: 2
//! }
//!
//! let mut buf = [0u8; 8];
//!
//! // read-only lense, no check of size:
//! let lense = UdpDatagramHeader(&buf);
//! assert_eq!(lense.checksum(), &[0, 0]);
//!
//! // mutable lense, runtime check of size
//! let mut lense = buf.as_mut().udp_datagram_header()?;
//! lense.source_port_mut().copy_from_slice(&53u16.to_be_bytes()); // some DNS, anyone?
//!
//! // the original buffer is still available
//! assert_eq!(buf, [0, 53, 0, 0, 0, 0, 0, 0]);
//!
//! // read-only lense, runtime check of size
//! let lense = buf.as_ref().udp_datagram_header()?;
//! assert_eq!(lense.source_port(), &[0, 53]);
//! # Ok(())
//! # }
//! ```

use super::RosenpassError;
use crate::{pqkem::*, sodium};

// Macro magic ////////////////////////////////////////////////////////////////

/// A macro to create data lenses. Refer to the [`msgs` mod](crate::msgs) for
/// an example and further elaboration
// TODO implement TryFrom<[u8]> and From<[u8; Self::len()]>
#[macro_export]
macro_rules! data_lense(
    // prefix          @ offset       ; optional meta    ; field name   : field length, ...
    (token_muncher_ref @ $offset:expr ; $( $attr:meta )* ; $field:ident : $len:expr $(, $( $tail:tt )+ )?) =>  {
        ::paste::paste!{

        #[allow(rustdoc::broken_intra_doc_links)]
        $( #[ $attr ] )*
        ///
        #[doc = data_lense!(maybe_docstring_link $len)]
        /// bytes long
        pub fn $field(&self) -> &__ContainerType::Output {
            &self.0[$offset .. $offset + $len]
        }

        /// The bytes until the
        #[doc = data_lense!(maybe_docstring_link Self::$field)]
        /// field
        pub fn [< until_ $field >](&self) -> &__ContainerType::Output {
            &self.0[0 .. $offset]
        }

        // if the tail exits, consume it as well
        $(
        data_lense!{token_muncher_ref @ $offset + $len ; $( $tail )+ }
        )?
        }
    };

    // prefix          @ offset       ; optional meta    ; field name   : field length, ...
    (token_muncher_mut @ $offset:expr ; $( $attr:meta )* ; $field:ident : $len:expr $(, $( $tail:tt )+ )?) =>  {
        ::paste::paste!{

        #[allow(rustdoc::broken_intra_doc_links)]
        $( #[ $attr ] )*
        ///
        #[doc = data_lense!(maybe_docstring_link $len)]
        /// bytes long
        pub fn [< $field _mut >](&mut self) -> &mut __ContainerType::Output {
            &mut self.0[$offset .. $offset + $len]
        }

        // if the tail exits, consume it as well
        $(
        data_lense!{token_muncher_mut @ $offset + $len ; $( $tail )+ }
        )?
        }
    };

    // switch that yields literals unchanged, but creates docstring links to
    // constants
    // TODO the doc string link doesn't work if $x is taken from a generic,
    (maybe_docstring_link $x:literal) => (stringify!($x));
    (maybe_docstring_link $x:expr) => (stringify!([$x]));

    // struct name  < optional generics     >    := optional doc string      field name   : field length, ...
    ($type:ident $( < $( $generic:ident ),+ > )? := $( $( #[ $attr:meta ] )* $field:ident : $len:expr ),+) => (::paste::paste!{

        #[allow(rustdoc::broken_intra_doc_links)]
        /// A data lense to manipulate byte slices.
        ///
        //// # Fields
        ///
        $(
        /// - `
        #[doc = stringify!($field)]
        /// `:
        #[doc = data_lense!(maybe_docstring_link $len)]
        /// bytes
        )+
        pub struct $type<__ContainerType $(, $( $generic ),+ )? > (
            __ContainerType,
            // The phantom data is required, since all generics declared on a
            // type need to be used on the type.
            // https://doc.rust-lang.org/stable/error_codes/E0392.html
            $( $( ::core::marker::PhantomData<$generic> ),+ )?
        );

        impl<__ContainerType $(, $( $generic: LenseView ),+ )? > $type<__ContainerType $(, $( $generic ),+ )? >{
            $(
            /// Size in bytes of the field `
            #[doc = !($field)]
            /// `
            pub const fn [< $field _len >]() -> usize{
                $len
            }
            )+

            /// Verify that `len` is sufficiently long to hold [Self]
            pub fn check_size(len: usize) -> Result<(), RosenpassError>{
                let required_size = $( $len + )+ 0;
                let actual_size = len;
                if required_size != actual_size {
                    Err(RosenpassError::BufferSizeMismatch {
                        required_size,
                        actual_size,
                    })
                }else{
                    Ok(())
                }
            }
        }

        // read-only accessor functions
        impl<'a, __ContainerType $(, $( $generic: LenseView ),+ )?> $type<&'a __ContainerType $(, $( $generic ),+ )?>
        where
            __ContainerType: std::ops::Index<std::ops::Range<usize>> + ?Sized,
        {
            data_lense!{token_muncher_ref @ 0 ; $( $( $attr )* ; $field : $len ),+ }

            /// View into all bytes belonging to this Lense
            pub fn all_bytes(&self) -> &__ContainerType::Output {
                &self.0[0..Self::LEN]
            }
        }

        // mutable accessor functions
        impl<'a, __ContainerType $(, $( $generic: LenseView ),+ )?> $type<&'a mut __ContainerType $(, $( $generic ),+ )?>
        where
            __ContainerType: std::ops::IndexMut<std::ops::Range<usize>> + ?Sized,
        {
            data_lense!{token_muncher_ref @ 0 ; $( $( $attr )* ; $field : $len ),+ }
            data_lense!{token_muncher_mut @ 0 ; $( $( $attr )* ; $field : $len ),+ }

            /// View into all bytes belonging to this Lense
            pub fn all_bytes(&self) -> &__ContainerType::Output {
                &self.0[0..Self::LEN]
            }

            /// View into all bytes belonging to this Lense
            pub fn all_bytes_mut(&mut self) -> &mut __ContainerType::Output {
                &mut self.0[0..Self::LEN]
            }
        }

        // lense trait, allowing us to know the implementing lenses size
        impl<__ContainerType $(, $( $generic: LenseView ),+ )? > LenseView for $type<__ContainerType $(, $( $generic ),+ )? >{
            /// Number of bytes required to store this type in binary format
            const LEN: usize = $( $len + )+ 0;
        }

        /// Extension trait to allow checked creation of a lense over
        /// some byte slice that contains a
        #[doc = data_lense!(maybe_docstring_link $type)]
        pub trait [< $type Ext >] {
            type __ContainerType;

            /// Create a lense to the byte slice
            fn [< $type:snake >] $(< $($generic : LenseView),* >)? (self) -> Result< $type<Self::__ContainerType, $( $($generic),+ )? >, RosenpassError>;

            /// Create a lense to the byte slice, automatically truncating oversized buffers
            fn [< $type:snake _ truncating >] $(< $($generic : LenseView),* >)? (self) -> Result< $type<Self::__ContainerType, $( $($generic),+ )? >, RosenpassError>;
        }

        impl<'a> [< $type Ext >] for &'a [u8] {
            type __ContainerType = &'a [u8];

            fn [< $type:snake >] $(< $($generic : LenseView),* >)? (self) -> Result< $type<Self::__ContainerType, $( $($generic),+ )? >, RosenpassError> {
                $type::<Self::__ContainerType, $( $($generic),+ )? >::check_size(self.len())?;
                Ok($type ( self, $( $( ::core::marker::PhantomData::<$generic>  ),+ )? ))
            }

            fn [< $type:snake _ truncating >] $(< $($generic : LenseView),* >)? (self) -> Result< $type<Self::__ContainerType, $( $($generic),+ )? >, RosenpassError> {
                let required_size = $( $len + )+ 0;
                let actual_size = self.len();
                if actual_size < required_size {
                    return Err(RosenpassError::BufferSizeMismatch {
                        required_size,
                        actual_size,
                    });
                }

                [< $type Ext >]::[< $type:snake >](&self[..required_size])
            }
        }

        impl<'a> [< $type Ext >] for &'a mut [u8] {
            type __ContainerType = &'a mut [u8];
            fn [< $type:snake >] $(< $($generic : LenseView),* >)? (self) -> Result< $type<Self::__ContainerType, $( $($generic),+ )? >, RosenpassError> {
                $type::<Self::__ContainerType, $( $($generic),+ )? >::check_size(self.len())?;
                Ok($type ( self, $( $( ::core::marker::PhantomData::<$generic>  ),+ )? ))
            }

            fn [< $type:snake _ truncating >] $(< $($generic : LenseView),* >)? (self) -> Result< $type<Self::__ContainerType, $( $($generic),+ )? >, RosenpassError> {
                let required_size = $( $len + )+ 0;
                let actual_size = self.len();
                if actual_size < required_size {
                    return Err(RosenpassError::BufferSizeMismatch {
                        required_size,
                        actual_size,
                    });
                }

                [< $type Ext >]::[< $type:snake >](&mut self[..required_size])
            }
        }
    });
);

/// Common trait shared by all Lenses
pub trait LenseView {
    const LEN: usize;
}

data_lense! { Envelope<M> :=
    /// [MsgType] of this message
    msg_type: 1,
    /// Reserved for future use
    reserved: 3,
    /// The actual Paylod
    payload: M::LEN,
    /// Message Authentication Code (mac) over all bytes until (exclusive)
    /// `mac` itself
    mac: sodium::MAC_SIZE,
    /// Currently unused, TODO: do something with this
    cookie: sodium::MAC_SIZE
}

data_lense! { InitHello :=
    /// Randomly generated connection id
    sidi: 4,
    /// Kyber 512 Ephemeral Public Key
    epki: EphemeralKEM::PK_LEN,
    /// Classic McEliece Ciphertext
    sctr: StaticKEM::CT_LEN,
    /// Encryped: 16 byte hash of McEliece initiator static key
    pidic: sodium::AEAD_TAG_LEN + 32,
    /// Encrypted TAI64N Time Stamp (against replay attacks)
    auth: sodium::AEAD_TAG_LEN
}

data_lense! { RespHello :=
    /// Randomly generated connection id
    sidr: 4,
    /// Copied from InitHello
    sidi: 4,
    /// Kyber 512 Ephemeral Ciphertext
    ecti: EphemeralKEM::CT_LEN,
    /// Classic McEliece Ciphertext
    scti: StaticKEM::CT_LEN,
    /// Responders handshake state in encrypted form
    biscuit: BISCUIT_CT_LEN,
    /// Empty encrypted message (just an auth tag)
    auth: sodium::AEAD_TAG_LEN
}

data_lense! { InitConf :=
    /// Copied from InitHello
    sidi: 4,
    /// Copied from RespHello
    sidr: 4,
    /// Responders handshake state in encrypted form
    biscuit: BISCUIT_CT_LEN,
    /// Empty encrypted message (just an auth tag)
    auth: sodium::AEAD_TAG_LEN
}

data_lense! { EmptyData :=
    /// Copied from RespHello
    sid: 4,
    /// Nonce
    ctr: 8,
    /// Empty encrypted message (just an auth tag)
    auth: sodium::AEAD_TAG_LEN
}

data_lense! { Biscuit :=
    /// H(spki) – Ident ifies the initiator
    pidi: sodium::KEY_SIZE,
    /// The biscuit number (replay protection)
    biscuit_no: 12,
    /// Chaining key
    ck: sodium::KEY_SIZE
}

data_lense! { DataMsg :=
    dummy: 4
}

data_lense! { CookieReply :=
    dummy: 4
}

// Traits /////////////////////////////////////////////////////////////////////

pub trait WireMsg: std::fmt::Debug {
    const MSG_TYPE: MsgType;
    const MSG_TYPE_U8: u8 = Self::MSG_TYPE as u8;
    const BYTES: usize;
}

// Constants //////////////////////////////////////////////////////////////////

pub const SESSION_ID_LEN: usize = 4;
pub const BISCUIT_ID_LEN: usize = 12;

pub const WIRE_ENVELOPE_LEN: usize = 1 + 3 + 16 + 16; // TODO verify this

/// Size required to fit any message in binary form
pub const MAX_MESSAGE_LEN: usize = 2500; // TODO fix this

/// Recognized message types
#[repr(u8)]
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum MsgType {
    InitHello = 0x81,
    RespHello = 0x82,
    InitConf = 0x83,
    EmptyData = 0x84,
    DataMsg = 0x85,
    CookieReply = 0x86,
}

impl TryFrom<u8> for MsgType {
    type Error = RosenpassError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x81 => MsgType::InitHello,
            0x82 => MsgType::RespHello,
            0x83 => MsgType::InitConf,
            0x84 => MsgType::EmptyData,
            0x85 => MsgType::DataMsg,
            0x86 => MsgType::CookieReply,
            _ => return Err(RosenpassError::InvalidMessageType(value)),
        })
    }
}

/// length in bytes of an unencrypted Biscuit (plain text)
pub const BISCUIT_PT_LEN: usize = Biscuit::<()>::LEN;

/// Length in bytes of an encrypted Biscuit (cipher text)
pub const BISCUIT_CT_LEN: usize = BISCUIT_PT_LEN + sodium::XAEAD_NONCE_LEN + sodium::XAEAD_TAG_LEN;

#[cfg(test)]
mod test_constants {
    use crate::{
        msgs::{BISCUIT_CT_LEN, BISCUIT_PT_LEN},
        sodium,
    };

    #[test]
    fn sodium_keysize() {
        assert_eq!(sodium::KEY_SIZE, 32);
    }

    #[test]
    fn biscuit_pt_len() {
        assert_eq!(BISCUIT_PT_LEN, 2 * sodium::KEY_SIZE + 12);
    }

    #[test]
    fn biscuit_ct_len() {
        assert_eq!(
            BISCUIT_CT_LEN,
            BISCUIT_PT_LEN + sodium::XAEAD_NONCE_LEN + sodium::XAEAD_TAG_LEN
        );
    }
}
