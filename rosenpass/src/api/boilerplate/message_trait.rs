use zerocopy::{ByteSliceMut, Ref};

use rosenpass_util::zerocopy::RefMaker;

use super::RawMsgType;

pub trait Message {
    type Payload;
    type MessageClass: Into<RawMsgType>;
    const MESSAGE_TYPE: Self::MessageClass;

    fn from_payload(payload: Self::Payload) -> Self;
    fn init(&mut self);
    fn setup<B: ByteSliceMut>(buf: B) -> anyhow::Result<Ref<B, Self>>;
}

pub trait ZerocopyResponseMakerSetupMessageExt<B, T> {
    fn setup_msg(self) -> anyhow::Result<Ref<B, T>>;
}

impl<B, T> ZerocopyResponseMakerSetupMessageExt<B, T> for RefMaker<B, T>
where
    B: ByteSliceMut,
    T: Message,
{
    fn setup_msg(self) -> anyhow::Result<Ref<B, T>> {
        T::setup(self.into_buf())
    }
}
