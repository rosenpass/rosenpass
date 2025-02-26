//! Generic helpers for declaring bindings to liboqs kems

/// Generate bindings to a liboqs-provided KEM
macro_rules! oqs_kem {
    ($name:ident) => { ::paste::paste!{
        #[doc = "Bindings for ::oqs_sys::kem::" [<"OQS_KEM" _ $name:snake>] "_*"]
        mod [< $name:snake >] {
            use rosenpass_cipher_traits::kem;

            #[doc = "Bindings for ::oqs_sys::kem::" [<"OQS_KEM" _ $name:snake>] "_*"]
            #[doc = ""]
            #[doc = "# Examples"]
            #[doc = ""]
            #[doc = "```rust"]
            #[doc = "use std::borrow::{Borrow, BorrowMut};"]
            #[doc = "use rosenpass_cipher_traits::Kem;"]
            #[doc = "use rosenpass_oqs::" $name:camel " as MyKem;"]
            #[doc = "use rosenpass_secret_memory::{Secret, Public};"]
            #[doc = ""]
            #[doc = "rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();"]
            #[doc = ""]
            #[doc = "// Recipient generates secret key, transfers pk to sender"]
            #[doc = "let mut sk = Secret::<{ MyKem::SK_LEN }>::zero();"]
            #[doc = "let mut pk = Public::<{ MyKem::PK_LEN }>::zero();"]
            #[doc = "MyKem::keygen(sk.secret_mut(), pk.borrow_mut());"]
            #[doc = ""]
            #[doc = "// Sender generates ciphertext and local shared key, sends ciphertext to recipient"]
            #[doc = "let mut shk_enc = Secret::<{ MyKem::SHK_LEN }>::zero();"]
            #[doc = "let mut ct = Public::<{ MyKem::CT_LEN }>::zero();"]
            #[doc = "MyKem::encaps(shk_enc.secret_mut(), ct.borrow_mut(), pk.borrow());"]
            #[doc = ""]
            #[doc = "// Recipient decapsulates ciphertext"]
            #[doc = "let mut shk_dec = Secret::<{ MyKem::SHK_LEN }>::zero();"]
            #[doc = "MyKem::decaps(shk_dec.secret_mut(), sk.secret(), ct.borrow());"]
            #[doc = ""]
            #[doc = "// Both parties end up with the same shared key"]
            #[doc = "assert!(rosenpass_constant_time::compare(shk_enc.secret_mut(), shk_dec.secret_mut()) == 0);"]
            #[doc = "```"]
            pub struct [< $name:camel >];

            pub const SK_LEN: usize =  ::oqs_sys::kem::[<OQS_KEM _ $name:snake _ length_secret_key >] as usize;
            pub const PK_LEN: usize =  ::oqs_sys::kem::[<OQS_KEM _ $name:snake _ length_public_key >] as usize;
            pub const CT_LEN: usize =  ::oqs_sys::kem::[<OQS_KEM _ $name:snake _ length_ciphertext >] as usize;
            pub const SHK_LEN: usize =  ::oqs_sys::kem::[<OQS_KEM _ $name:snake _ length_shared_secret >] as usize;

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
            impl kem::Kem<SK_LEN, PK_LEN, CT_LEN, SHK_LEN> for [< $name:camel >] {
                fn keygen(&self, sk: &mut [u8; SK_LEN], pk: &mut [u8; PK_LEN]) -> Result<(), kem::Error> {
                    unsafe {
                        oqs_call!(
                            ::oqs_sys::kem::[< OQS_KEM _ $name:snake _ keypair >],
                            pk.as_mut_ptr(),
                            sk.as_mut_ptr()
                        );
                    }

                    Ok(())
                }

                    fn encaps(&self, shk: &mut [u8; SHK_LEN], ct: &mut [u8; CT_LEN], pk: &[u8; PK_LEN]) -> Result<(), kem::Error> {
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

                fn decaps(&self, shk: &mut [u8; SHK_LEN], sk: &[u8; SK_LEN], ct: &[u8; CT_LEN]) -> Result<(), kem::Error> {
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

        impl Default for [< $name:camel >] {
            fn default() -> Self {
                Self
            }
        }

        pub use [< $name:snake >] :: [< $name:camel >];
    }}
}
