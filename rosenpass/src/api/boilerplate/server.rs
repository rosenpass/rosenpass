use super::{ByteSliceRefExt, Message, PingRequest, PingResponse, RequestRef, RequestResponsePair};
use std::{collections::VecDeque, os::fd::OwnedFd};
use zerocopy::{ByteSlice, ByteSliceMut};

pub trait Server {
    fn ping(
        &mut self,
        req: &PingRequest,
        req_fds: &mut VecDeque<OwnedFd>,
        res: &mut PingResponse,
    ) -> anyhow::Result<()>;

    fn supply_keypair(
        &mut self,
        req: &super::SupplyKeypairRequest,
        req_fds: &mut VecDeque<OwnedFd>,
        res: &mut super::SupplyKeypairResponse,
    ) -> anyhow::Result<()>;

    fn dispatch<ReqBuf, ResBuf>(
        &mut self,
        p: &mut RequestResponsePair<ReqBuf, ResBuf>,
        req_fds: &mut VecDeque<OwnedFd>,
    ) -> anyhow::Result<()>
    where
        ReqBuf: ByteSlice,
        ResBuf: ByteSliceMut,
    {
        match p {
            RequestResponsePair::Ping((req, res)) => self.ping(req, req_fds, res),
            RequestResponsePair::SupplyKeypair((req, res)) => {
                self.supply_keypair(req, req_fds, res)
            }
        }
    }

    fn handle_message<ReqBuf, ResBuf>(
        &mut self,
        req: ReqBuf,
        req_fds: &mut VecDeque<OwnedFd>,
        res: ResBuf,
    ) -> anyhow::Result<usize>
    where
        ReqBuf: ByteSlice,
        ResBuf: ByteSliceMut,
    {
        let req = req.parse_request_from_prefix()?;
        // TODO: This is not pretty; This match should be moved into RequestRef
        let mut pair = match req {
            RequestRef::Ping(req) => {
                let mut res = res.ping_response_from_prefix()?;
                res.init();
                RequestResponsePair::Ping((req, res))
            }
            RequestRef::SupplyKeypair(req) => {
                let mut res = res.supply_keypair_response_from_prefix()?;
                res.init();
                RequestResponsePair::SupplyKeypair((req, res))
            }
        };
        self.dispatch(&mut pair, req_fds)?;

        let res_len = pair.response().bytes().len();
        Ok(res_len)
    }
}
