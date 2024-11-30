use super::{ByteSliceRefExt, Message, PingRequest, PingResponse, RequestRef, RequestResponsePair};
use std::{collections::VecDeque, os::fd::OwnedFd};
use zerocopy::{ByteSlice, ByteSliceMut};

pub trait Server {
    /// This implements the handler for the [crate::api::RequestMsgType::Ping] API message
    ///
    /// It merely takes a buffer and returns that same buffer.
    fn ping(
        &mut self,
        req: &PingRequest,
        req_fds: &mut VecDeque<OwnedFd>,
        res: &mut PingResponse,
    ) -> anyhow::Result<()>;

    /// Supply the cryptographic server keypair through file descriptor passing in the API
    ///
    /// This implements the handler for the [crate::api::RequestMsgType::SupplyKeypair] API message.
    ///
    /// # File descriptors
    ///
    /// 1. The secret key (size must match exactly); the file descriptor must be backed by either
    ///    of
    ///     - file-system file
    ///     - [memfd](https://man.archlinux.org/man/memfd.2.en)
    ///     - [memfd_secret](https://man.archlinux.org/man/memfd.2.en)
    /// 2. The public key (size must match exactly); the file descriptor must be backed by either
    ///    of
    ///     - file-system file
    ///     - [memfd](https://man.archlinux.org/man/memfd.2.en)
    ///     - [memfd_secret](https://man.archlinux.org/man/memfd.2.en)
    ///
    /// # API Return Status
    ///
    /// 1. [crate::api::supply_keypair_response_status::OK] - Indicates success
    /// 2. [crate::api::supply_keypair_response_status::KEYPAIR_ALREADY_SUPPLIED] – The endpoint was used but
    ///    the server already has server keys
    /// 3. [crate::api::supply_keypair_response_status::INVALID_REQUEST]  – Malformed request; could be:
    ///     - Missing file descriptors for public key
    ///     - File descriptors contain data of invalid length
    ///     - Invalid file descriptor type
    ///
    /// # Description
    ///
    /// At startup, if no server keys are specified in the rosenpass configuration, and if the API
    /// is enabled, the Rosenpass process waits for server keys to be supplied to the API. Before
    /// then, any messages for the rosenpass cryptographic protocol are ignored and dropped – all
    /// cryptographic operations require access to the server keys.
    ///
    /// Both private and public keys are specified through file descriptors and both are read from
    /// their respective file descriptors into process memory. A file descriptor based transport is
    /// used because of the excessive size of Classic McEliece public keys (100kb and up).
    ///
    /// The file descriptors for the keys need not be backed by a file on disk. You can supply a
    /// [memfd](https://man.archlinux.org/man/memfd.2.en) or [memfd_secret](https://man.archlinux.org/man/memfd_secret.2.en)
    /// backed file descriptor if the server keys are not backed by a file system file.
    fn supply_keypair(
        &mut self,
        req: &super::SupplyKeypairRequest,
        req_fds: &mut VecDeque<OwnedFd>,
        res: &mut super::SupplyKeypairResponse,
    ) -> anyhow::Result<()>;

    /// Supply a new UDP listen socket through file descriptor passing via the API
    ///
    /// This implements the handler for the [crate::api::RequestMsgType::AddListenSocket] API message.
    ///
    /// # File descriptors
    ///
    /// 1. The listen socket; must be backed by a UDP network listen socket
    ///
    /// # API Return Status
    ///
    /// 1. [crate::api::add_listen_socket_response_status::OK] - Indicates success
    /// 2. [add_listen_socket_response_status::INVALID_REQUEST] – Malformed request; could be:
    ///     - Missing file descriptors for public key
    ///     - Invalid file descriptor type
    /// 3. [crate::api::add_listen_socket_response_status::INTERNAL_ERROR] – Some other, non-fatal error
    ///    occured. Check the logs on log
    ///
    /// # Description
    ///
    /// This endpoint allows you to supply a UDP listen socket; it will be used to perform
    /// cryptographic key exchanges via the Rosenpass protocol.
    fn add_listen_socket(
        &mut self,
        req: &super::AddListenSocketRequest,
        req_fds: &mut VecDeque<OwnedFd>,
        res: &mut super::AddListenSocketResponse,
    ) -> anyhow::Result<()>;

    fn add_psk_broker(
        &mut self,
        req: &super::AddPskBrokerRequest,
        req_fds: &mut VecDeque<OwnedFd>,
        res: &mut super::AddPskBrokerResponse,
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
            RequestResponsePair::AddListenSocket((req, res)) => {
                self.add_listen_socket(req, req_fds, res)
            }
            RequestResponsePair::AddPskBroker((req, res)) => self.add_psk_broker(req, req_fds, res),
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
            RequestRef::AddListenSocket(req) => {
                let mut res = res.add_listen_socket_response_from_prefix()?;
                res.init();
                RequestResponsePair::AddListenSocket((req, res))
            }
            RequestRef::AddPskBroker(req) => {
                let mut res = res.add_psk_broker_response_from_prefix()?;
                res.init();
                RequestResponsePair::AddPskBroker((req, res))
            }
        };
        self.dispatch(&mut pair, req_fds)?;

        let res_len = pair.response().bytes().len();
        Ok(res_len)
    }
}
