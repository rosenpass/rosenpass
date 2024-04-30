macro_rules! oqs_kem {
    ($name:ident) => { ::paste::paste!{
        mod [< $name:snake >] {
            use rosenpass_cipher_traits::Kem;
            use rosenpass_util::result::Guaranteed;

            pub enum [< $name:camel >]  {}

            /// # Panic & Safety
            ///
            /// This Trait impl calls unsafe [oqs_sys] functions, that write to byte
            /// slices only identified using raw pointers. It must be ensured that the raw
            /// pointers point into byte slices of sufficient length, to avoid UB through
            /// overwriting of arbitrary data. This is ensured through assertions in the
            /// implementation.
            ///
            /// __Note__: This requirement is stricter than necessary, it would suffice
            /// to only check that the buffers are big enough, allowing them to be even
            /// bigger. However, from a correctness point of view it does not make sense to
            /// allow bigger buffers.
            impl Kem for [< $name:camel >] {
                type Error = ::std::convert::Infallible;

                const SK_LEN: usize =  ::oqs_sys::kem::[<OQS_KEM _ $name:snake _ length_secret_key >] as usize;
                const PK_LEN: usize =  ::oqs_sys::kem::[<OQS_KEM _ $name:snake _ length_public_key >] as usize;
                const CT_LEN: usize =  ::oqs_sys::kem::[<OQS_KEM _ $name:snake _ length_ciphertext >] as usize;
                const SHK_LEN: usize =  ::oqs_sys::kem::[<OQS_KEM _ $name:snake _ length_shared_secret >] as usize;

                fn keygen(sk: &mut [u8], pk: &mut [u8]) -> Guaranteed<()> {
                    assert_eq!(sk.len(), Self::SK_LEN);
                    assert_eq!(pk.len(), Self::PK_LEN);
                    unsafe {
                        oqs_call!(
                            ::oqs_sys::kem::[< OQS_KEM _ $name:snake _ keypair >],
                            pk.as_mut_ptr(),
                            sk.as_mut_ptr()
                        );
                    }

                    Ok(())
                }

                fn encaps(shk: &mut [u8], ct: &mut [u8], pk: &[u8]) -> Guaranteed<()> {
                    assert_eq!(shk.len(), Self::SHK_LEN);
                    assert_eq!(ct.len(), Self::CT_LEN);
                    assert_eq!(pk.len(), Self::PK_LEN);
                    unsafe {
                        oqs_call!(
                            ::oqs_sys::kem::[< OQS_KEM _ $name:snake _ encaps >],
                            ct.as_mut_ptr(),
                            shk.as_mut_ptr(),
                            pk.as_ptr()
                        );
                    }

                    Ok(())
                }

                fn decaps(shk: &mut [u8], sk: &[u8], ct: &[u8]) -> Guaranteed<()> {
                    assert_eq!(shk.len(), Self::SHK_LEN);
                    assert_eq!(sk.len(), Self::SK_LEN);
                    assert_eq!(ct.len(), Self::CT_LEN);
                    unsafe {
                        oqs_call!(
                            ::oqs_sys::kem::[< OQS_KEM _ $name:snake _ decaps >],
                            shk.as_mut_ptr(),
                            ct.as_ptr(),
                            sk.as_ptr()
                        );
                    }

                    Ok(())
                }
            }

        }

        pub use [< $name:snake >] :: [< $name:camel >];
    }}
}
