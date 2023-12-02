use std::result::Result;

/// Common trait shared by all Lenses
pub trait LenseView {
    const LEN: usize;
}

/// Error during lense creation
#[derive(thiserror::Error, Debug, Eq, PartialEq, Clone)]
pub enum LenseError {
    #[error("buffer size mismatch")]
    BufferSizeMismatch,
}

pub type LenseResult<T> = Result<T, LenseError>;

impl LenseError {
    pub fn ensure_exact_buffer_size(len: usize, required: usize) -> LenseResult<()> {
        (len == required)
            .then_some(())
            .ok_or(LenseError::BufferSizeMismatch)
    }

    pub fn ensure_sufficient_buffer_size(len: usize, required: usize) -> LenseResult<()> {
        (len >= required)
            .then_some(())
            .ok_or(LenseError::BufferSizeMismatch)
    }
}

/// A macro to create data lenses.
#[macro_export]
macro_rules! lense(
    // prefix          @ offset       ; optional meta    ; field name   : field length, ...
    (token_muncher_ref @ $offset:expr ; $( $attr:meta )* ; $field:ident : $len:expr $(, $( $tail:tt )+ )?) =>  {
        ::paste::paste!{

        #[allow(rustdoc::broken_intra_doc_links)]
        $( #[ $attr ] )*
        ///
        #[doc = lense!(maybe_docstring_link $len)]
        /// bytes long
        pub fn $field(&self) -> &__ContainerType::Output {
            &self.0[$offset .. $offset + $len]
        }

        /// The bytes until the
        #[doc = lense!(maybe_docstring_link Self::$field)]
        /// field
        pub fn [< until_ $field >](&self) -> &__ContainerType::Output {
            &self.0[0 .. $offset]
        }

        // if the tail exits, consume it as well
        $(
        lense!{token_muncher_ref @ $offset + $len ; $( $tail )+ }
        )?
        }
    };

    // prefix          @ offset       ; optional meta    ; field name   : field length, ...
    (token_muncher_mut @ $offset:expr ; $( $attr:meta )* ; $field:ident : $len:expr $(, $( $tail:tt )+ )?) =>  {
        ::paste::paste!{

        #[allow(rustdoc::broken_intra_doc_links)]
        $( #[ $attr ] )*
        ///
        #[doc = lense!(maybe_docstring_link $len)]
        /// bytes long
        pub fn [< $field _mut >](&mut self) -> &mut __ContainerType::Output {
            &mut self.0[$offset .. $offset + $len]
        }

        // if the tail exits, consume it as well
        $(
        lense!{token_muncher_mut @ $offset + $len ; $( $tail )+ }
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
        #[doc = lense!(maybe_docstring_link $len)]
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

            /// Verify that `len` exactly holds [Self]
            pub fn check_size(len: usize) -> ::rosenpass_lenses::LenseResult<()> {
                ::rosenpass_lenses::LenseError::ensure_exact_buffer_size(len, $( $len + )+ 0)
            }
        }

        // read-only accessor functions
        impl<'a, __ContainerType $(, $( $generic: LenseView ),+ )?> $type<&'a __ContainerType $(, $( $generic ),+ )?>
        where
            __ContainerType: std::ops::Index<std::ops::Range<usize>> + ?Sized,
        {
            lense!{token_muncher_ref @ 0 ; $( $( $attr )* ; $field : $len ),+ }

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
            lense!{token_muncher_ref @ 0 ; $( $( $attr )* ; $field : $len ),+ }
            lense!{token_muncher_mut @ 0 ; $( $( $attr )* ; $field : $len ),+ }

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
        #[doc = lense!(maybe_docstring_link $type)]
        pub trait [< $type Ext >] {
            type __ContainerType;

            /// Create a lense to the byte slice
            fn [< $type:snake >] $(< $($generic : LenseView),* >)? (self) -> ::rosenpass_lenses::LenseResult< $type<Self::__ContainerType, $( $($generic),+ )? >>;

            /// Create a lense to the byte slice, automatically truncating oversized buffers
            fn [< $type:snake _ truncating >] $(< $($generic : LenseView),* >)? (self) -> ::rosenpass_lenses::LenseResult< $type<Self::__ContainerType, $( $($generic),+ )? >>;
        }

        impl<'a> [< $type Ext >] for &'a [u8] {
            type __ContainerType = &'a [u8];

            fn [< $type:snake >] $(< $($generic : LenseView),* >)? (self) -> ::rosenpass_lenses::LenseResult< $type<Self::__ContainerType, $( $($generic),+ )? >> {
                $type::<Self::__ContainerType, $( $($generic),+ )? >::check_size(self.len())?;
                Ok($type ( self, $( $( ::core::marker::PhantomData::<$generic>  ),+ )? ))
            }

            fn [< $type:snake _ truncating >] $(< $($generic : LenseView),* >)? (self) -> ::rosenpass_lenses::LenseResult< $type<Self::__ContainerType, $( $($generic),+ )? >> {
                let required_size = $( $len + )+ 0;
                ::rosenpass_lenses::LenseError::ensure_sufficient_buffer_size(self.len(), required_size)?;
                [< $type Ext >]::[< $type:snake >](&self[..required_size])
            }
        }

        impl<'a> [< $type Ext >] for &'a mut [u8] {
            type __ContainerType = &'a mut [u8];
            fn [< $type:snake >] $(< $($generic : LenseView),* >)? (self) -> ::rosenpass_lenses::LenseResult< $type<Self::__ContainerType, $( $($generic),+ )? >> {
                $type::<Self::__ContainerType, $( $($generic),+ )? >::check_size(self.len())?;
                Ok($type ( self, $( $( ::core::marker::PhantomData::<$generic>  ),+ )? ))
            }

            fn [< $type:snake _ truncating >] $(< $($generic : LenseView),* >)? (self) -> ::rosenpass_lenses::LenseResult< $type<Self::__ContainerType, $( $($generic),+ )? >> {
                let required_size = $( $len + )+ 0;
                ::rosenpass_lenses::LenseError::ensure_sufficient_buffer_size(self.len(), required_size)?;
                [< $type Ext >]::[< $type:snake >](&mut self[..required_size])
            }
        }
    });
);
