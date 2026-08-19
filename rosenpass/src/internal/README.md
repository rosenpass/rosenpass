# Internal Rosenpass Modules

This module contains various modules which used to have their own crates. These modules implement a lot of functionality which is used internally with Rosenpass.

- [`crate::internal::cipher_traits`]
- [`crate::internal::ciphers`]
- [`crate::internal::constant_time`]
- [`crate::internal::oqs`]
- [`crate::internal::secret_memory`]
- [`crate::internal::util`]
- [`crate::internal::wireguard_broker`]

They are all `pub(crate)` by default because their interfaces may change between non-breaking releases of `rosenpass`. If you want to use these modules when using `rosenpass` as a library:

- use the `expose_internal_modules` feature (makes these modules `pub` instead of `pub(crate)`)
- be aware that their interfaces may get breaking changes from time to time without a major version number increase of the `rosenpass` crate
