use std::{borrow::BorrowMut, collections::VecDeque, os::fd::OwnedFd};

use anyhow::Context;
use rosenpass_to::{ops::copy_slice, To};
use rosenpass_util::{fd::FdIo, functional::run, io::ReadExt, mem::DiscardResultExt};

use crate::{app_server::AppServer, protocol::BuildCryptoServer};

use super::{supply_keypair_response_status, Server as ApiServer};

#[derive(Debug)]
pub struct ApiHandler {
    _dummy: (),
}

impl ApiHandler {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self { _dummy: () }
    }
}

pub trait ApiHandlerContext {
    fn api_handler(&self) -> &ApiHandler;
    fn app_server(&self) -> &AppServer;
    fn api_handler_mut(&mut self) -> &mut ApiHandler;
    fn app_server_mut(&mut self) -> &mut AppServer;
}

#[derive(thiserror::Error, Debug)]
#[error("Error in SupplyKeypair")]
struct SupplyKeypairError {
    status: u128,
    #[source]
    cause: anyhow::Error,
}

trait SupplyKeypairErrorExt<T> {
    fn e_custom(self, status: u128) -> Result<T, SupplyKeypairError>;
    fn einternal(self) -> Result<T, SupplyKeypairError>;
    fn ealready_supplied(self) -> Result<T, SupplyKeypairError>;
    fn einvalid_req(self) -> Result<T, SupplyKeypairError>;
}

impl<T, E: Into<anyhow::Error>> SupplyKeypairErrorExt<T> for Result<T, E> {
    fn e_custom(self, status: u128) -> Result<T, SupplyKeypairError> {
        self.map_err(|e| SupplyKeypairError {
            status,
            cause: e.into(),
        })
    }

    fn einternal(self) -> Result<T, SupplyKeypairError> {
        self.e_custom(supply_keypair_response_status::INTERNAL_ERROR)
    }

    fn ealready_supplied(self) -> Result<T, SupplyKeypairError> {
        self.e_custom(supply_keypair_response_status::KEYPAIR_ALREADY_SUPPLIED)
    }

    fn einvalid_req(self) -> Result<T, SupplyKeypairError> {
        self.e_custom(supply_keypair_response_status::INVALID_REQUEST)
    }
}

impl<T> ApiServer for T
where
    T: ?Sized + ApiHandlerContext,
{
    fn ping(
        &mut self,
        req: &super::PingRequest,
        _req_fds: &mut VecDeque<OwnedFd>,
        res: &mut super::PingResponse,
    ) -> anyhow::Result<()> {
        let (req, res) = (&req.payload, &mut res.payload);
        copy_slice(&req.echo).to(&mut res.echo);
        Ok(())
    }

    fn supply_keypair(
        &mut self,
        req: &super::SupplyKeypairRequest,
        req_fds: &mut VecDeque<OwnedFd>,
        res: &mut super::SupplyKeypairResponse,
    ) -> anyhow::Result<()> {
        let outcome: Result<(), SupplyKeypairError> = run(|| {
            // Acquire the file descriptors
            let mut sk_io = FdIo(
                req_fds
                    .front()
                    .context("First file descriptor, secret key, missing.")
                    .einvalid_req()?,
            );
            let mut pk_io = FdIo(
                req_fds
                    .get(1)
                    .context("Second file descriptor, public key, missing.")
                    .einvalid_req()?,
            );

            // Actually read the secrets
            let mut sk = crate::protocol::SSk::zero();
            sk_io.read_exact_til_end(sk.secret_mut()).einvalid_req()?;

            let mut pk = crate::protocol::SPk::zero();
            pk_io.read_exact_til_end(pk.borrow_mut()).einvalid_req()?;

            // Retrieve the construction site
            let construction_site = self.app_server_mut().crypto_site.borrow_mut();

            // Retrieve the builder
            use rosenpass_util::build::ConstructionSite as C;
            let maybe_builder = match construction_site {
                C::Builder(builder) => Some(builder),
                C::Product(_) => None,
                C::Void => {
                    return Err(anyhow::Error::msg("CryptoServer construction side is void"))
                        .einternal();
                }
            };

            // Retrieve a reference to the keypair
            let Some(BuildCryptoServer {
                ref mut keypair, ..
            }) = maybe_builder
            else {
                return Err(anyhow::Error::msg("CryptoServer already built")).ealready_supplied();
            };

            // Supply the keypair to the CryptoServer
            keypair
                .insert(crate::protocol::Keypair { sk, pk })
                .discard_result();

            // Actually construct the CryptoServer
            construction_site
                .erect()
                .map_err(|e| anyhow::Error::msg(format!("Error erecting the CryptoServer {e:?}")))
                .einternal()?;

            Ok(())
        });

        // Handle errors
        use supply_keypair_response_status as status;
        let status = match outcome {
            Ok(()) => status::OK,
            Err(e) => {
                let lvl = match e.status {
                    status::INTERNAL_ERROR => log::Level::Warn,
                    _ => log::Level::Debug,
                };

                log::log!(
                    lvl,
                    "Error while processing API Request.\n    Request: {:?}\n    Error: {:?}",
                    req,
                    e.cause
                );

                if e.status == status::INTERNAL_ERROR {
                    return Err(e.cause);
                }

                e.status
            }
        };

        res.payload.status = status;

        Ok(())
    }
}
