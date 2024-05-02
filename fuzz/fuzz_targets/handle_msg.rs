#![no_main]
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass::protocol::CryptoServer;
use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::kem::StaticKem;
use rosenpass_secret_memory::Secret;

fuzz_target!(|rx_buf: &[u8]| {
    let sk = Secret::from_slice(&[0; StaticKem::SK_LEN]);
    let pk = Secret::from_slice(&[0; StaticKem::PK_LEN]);

    let mut cs = CryptoServer::new(sk, pk);
    let mut tx_buf = [0; 10240];

    // We expect errors while fuzzing therefore we do not check the result.
    let _ = cs.handle_msg(rx_buf, &mut tx_buf);
});
