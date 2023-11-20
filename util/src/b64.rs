use base64::{
    display::Base64Display as B64Display, read::DecoderReader as B64Reader,
    write::EncoderWriter as B64Writer,
};
use std::io::{Read, Write};

use base64::engine::general_purpose::GeneralPurpose as Base64Engine;
const B64ENGINE: Base64Engine = base64::engine::general_purpose::STANDARD;

pub fn fmt_b64<'a>(payload: &'a [u8]) -> B64Display<'a, 'static, Base64Engine> {
    B64Display::<'a, 'static>::new(payload, &B64ENGINE)
}

pub fn b64_writer<W: Write>(w: W) -> B64Writer<'static, Base64Engine, W> {
    B64Writer::new(w, &B64ENGINE)
}

pub fn b64_reader<R: Read>(r: R) -> B64Reader<'static, Base64Engine, R> {
    B64Reader::new(r, &B64ENGINE)
}
