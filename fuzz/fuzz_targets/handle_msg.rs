#![no_main]
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass::sodium::sodium_init;
use rosenpass::protocol::CryptoServer;
use rosenpass::coloring::Secret;

fuzz_target!(|rx_buf: &[u8]| {
    sodium_init().unwrap();

    let sk = Secret::from_slice(&[0;13568]);
    let pk = Secret::from_slice(&[0;524160]);

    let mut cs = CryptoServer::new(sk,pk);
    let mut tx_buf = [0;10240];
    cs.handle_msg(rx_buf, &mut tx_buf).unwrap();

});


