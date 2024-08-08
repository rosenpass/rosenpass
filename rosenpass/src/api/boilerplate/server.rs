use zerocopy::{ByteSlice, ByteSliceMut};

use super::{ByteSliceRefExt, Message, PingRequest, PingResponse, RequestRef, RequestResponsePair};

pub trait Server {
    fn ping(&mut self, req: &PingRequest, res: &mut PingResponse) -> anyhow::Result<()>;

    fn dispatch<ReqBuf, ResBuf>(
        &mut self,
        p: &mut RequestResponsePair<ReqBuf, ResBuf>,
    ) -> anyhow::Result<()>
    where
        ReqBuf: ByteSlice,
        ResBuf: ByteSliceMut,
    {
        match p {
            RequestResponsePair::Ping((req, res)) => self.ping(req, res),
        }
    }

    fn handle_message<ReqBuf, ResBuf>(&mut self, req: ReqBuf, res: ResBuf) -> anyhow::Result<usize>
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
        };
        self.dispatch(&mut pair)?;

        let res_len = pair.request().bytes().len();
        Ok(res_len)
    }
}
