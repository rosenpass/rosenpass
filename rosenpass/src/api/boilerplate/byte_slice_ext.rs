use zerocopy::{ByteSlice, Ref};

use rosenpass_util::zerocopy::{RefMaker, ZerocopySliceExt};

use super::{
    PingRequest, PingResponse, RawMsgType, RefMakerRawMsgTypeExt, RequestMsgType, RequestRef,
    ResponseMsgType, ResponseRef,
};

pub trait ByteSliceRefExt: ByteSlice {
    fn msg_type_maker(self) -> RefMaker<Self, RawMsgType> {
        self.zk_ref_maker()
    }

    fn msg_type(self) -> anyhow::Result<Ref<Self, PingRequest>> {
        self.zk_parse()
    }

    fn msg_type_from_prefix(self) -> anyhow::Result<Ref<Self, PingRequest>> {
        self.zk_parse_prefix()
    }

    fn msg_type_from_suffix(self) -> anyhow::Result<Ref<Self, PingRequest>> {
        self.zk_parse_suffix()
    }

    fn request_msg_type(self) -> anyhow::Result<RequestMsgType> {
        self.msg_type_maker().parse_request_msg_type()
    }

    fn request_msg_type_from_prefix(self) -> anyhow::Result<RequestMsgType> {
        self.msg_type_maker()
            .from_prefix()?
            .parse_request_msg_type()
    }

    fn request_msg_type_from_suffix(self) -> anyhow::Result<RequestMsgType> {
        self.msg_type_maker()
            .from_suffix()?
            .parse_request_msg_type()
    }

    fn response_msg_type(self) -> anyhow::Result<ResponseMsgType> {
        self.msg_type_maker().parse_response_msg_type()
    }

    fn response_msg_type_from_prefix(self) -> anyhow::Result<ResponseMsgType> {
        self.msg_type_maker()
            .from_prefix()?
            .parse_response_msg_type()
    }

    fn response_msg_type_from_suffix(self) -> anyhow::Result<ResponseMsgType> {
        self.msg_type_maker()
            .from_suffix()?
            .parse_response_msg_type()
    }

    fn parse_request(self) -> anyhow::Result<RequestRef<Self>> {
        RequestRef::parse(self)
    }

    fn parse_request_from_prefix(self) -> anyhow::Result<RequestRef<Self>> {
        RequestRef::parse_from_prefix(self)
    }

    fn parse_request_from_suffix(self) -> anyhow::Result<RequestRef<Self>> {
        RequestRef::parse_from_suffix(self)
    }

    fn parse_response(self) -> anyhow::Result<ResponseRef<Self>> {
        ResponseRef::parse(self)
    }

    fn parse_response_from_prefix(self) -> anyhow::Result<ResponseRef<Self>> {
        ResponseRef::parse_from_prefix(self)
    }

    fn parse_response_from_suffix(self) -> anyhow::Result<ResponseRef<Self>> {
        ResponseRef::parse_from_suffix(self)
    }

    fn ping_request_maker(self) -> RefMaker<Self, PingRequest> {
        self.zk_ref_maker()
    }

    fn ping_request(self) -> anyhow::Result<Ref<Self, PingRequest>> {
        self.zk_parse()
    }

    fn ping_request_from_prefix(self) -> anyhow::Result<Ref<Self, PingRequest>> {
        self.zk_parse_prefix()
    }

    fn ping_request_from_suffix(self) -> anyhow::Result<Ref<Self, PingRequest>> {
        self.zk_parse_suffix()
    }

    fn ping_response_maker(self) -> RefMaker<Self, PingResponse> {
        self.zk_ref_maker()
    }

    fn ping_response(self) -> anyhow::Result<Ref<Self, PingResponse>> {
        self.zk_parse()
    }

    fn ping_response_from_prefix(self) -> anyhow::Result<Ref<Self, PingResponse>> {
        self.zk_parse_prefix()
    }

    fn ping_response_from_suffix(self) -> anyhow::Result<Ref<Self, PingResponse>> {
        self.zk_parse_suffix()
    }
}

impl<B: ByteSlice> ByteSliceRefExt for B {}
