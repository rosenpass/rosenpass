//! Client implementation for the WireGuard broker protocol.
//!
//! This module provides a client implementation that communicates with a WireGuard broker server
//! using a binary protocol. The client handles serialization and deserialization of messages,
//! error handling, and the core interaction flow.
//!
//! # Examples
//!
//! ```
//! use rosenpass_wireguard_broker::api::client::{BrokerClient, BrokerClientIo};
//! #[derive(Debug)]
//! struct MyIo;
//!
//! impl BrokerClientIo for MyIo {
//!     type SendError = std::io::Error;
//!     type RecvError = std::io::Error;
//!
//!     fn send_msg(&mut self, buf: &[u8]) -> Result<(), Self::SendError> {
//!         // Implement sending logic
//!         Ok(())
//!     }
//!
//!     fn recv_msg(&mut self) -> Result<Option<&[u8]>, Self::RecvError> {
//!         // Implement receiving logic
//!         Ok(None)
//!     }
//! }
//!
//! // Create client with custom IO implementation
//! let mut client = BrokerClient::new(MyIo);
//! assert!(client.poll_response().unwrap().is_none());
//! ```
//!
//! # Protocol
//!
//! The client implements a simple request-response protocol for setting WireGuard pre-shared keys.
//! Messages are serialized using a binary format defined in the [`crate::api::msgs`] module.

use std::{borrow::BorrowMut, fmt::Debug};

use crate::{
    api::{
        config::NetworkBrokerConfig,
        msgs::{self, REQUEST_MSG_BUFFER_SIZE},
    },
    SerializedBrokerConfig, WireGuardBroker,
};

use super::{
    config::NetworkBrokerConfigErr,
    msgs::{Envelope, SetPskResponse},
};

/// Error type for polling responses from the broker server.
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum BrokerClientPollResponseError<RecvError> {
    /// An IO error occurred while receiving the response
    #[error(transparent)]
    IoError(RecvError),
    /// The received message was invalid or malformed
    #[error("Invalid message.")]
    InvalidMessage,
}

impl<RecvError> From<msgs::InvalidMessageTypeError> for BrokerClientPollResponseError<RecvError> {
    fn from(value: msgs::InvalidMessageTypeError) -> Self {
        let msgs::InvalidMessageTypeError = value; // Assert that this is a unit type
        BrokerClientPollResponseError::<RecvError>::InvalidMessage
    }
}

/// Helper function that wraps a receive error into a `BrokerClientPollResponseError::IoError`
fn io_poller<RecvError>(e: RecvError) -> BrokerClientPollResponseError<RecvError> {
    BrokerClientPollResponseError::<RecvError>::IoError(e)
}

/// Helper function that returns a `BrokerClientPollResponseError::InvalidMessage` error
fn invalid_msg_poller<RecvError>() -> BrokerClientPollResponseError<RecvError> {
    BrokerClientPollResponseError::<RecvError>::InvalidMessage
}

/// Error type for setting pre-shared keys through the broker client.
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum BrokerClientSetPskError<SendError> {
    /// Error encoding or decoding the message
    #[error("Error with encoding/decoding message")]
    MsgError,
    /// Error in the broker configuration
    #[error("Network Broker Config error: {0}")]
    BrokerError(NetworkBrokerConfigErr),
    /// IO error while sending the request
    #[error(transparent)]
    IoError(SendError),
    /// Interface name exceeds maximum length
    #[error("Interface name out of bounds")]
    IfaceOutOfBounds,
}

/// Trait defining the IO operations required by the broker client.
///
/// Implementors must provide methods for sending and receiving binary messages.
pub trait BrokerClientIo {
    /// Error type returned by send operations
    type SendError;
    /// Error type returned by receive operations
    type RecvError;

    /// Send a binary message
    fn send_msg(&mut self, buf: &[u8]) -> Result<(), Self::SendError>;
    /// Receive a binary message, returning None if no message is available
    fn recv_msg(&mut self) -> Result<Option<&[u8]>, Self::RecvError>;
}

/// Client for interacting with a WireGuard broker server.
///
/// The client handles the protocol-level communication with the server,
/// including message serialization and response handling.
#[derive(Debug)]
pub struct BrokerClient<Io>
where
    Io: BrokerClientIo + Debug,
{
    io: Io,
}

impl<Io> BrokerClient<Io>
where
    Io: BrokerClientIo + Debug,
{
    /// Creates a new `BrokerClient` with the given IO implementation.
    pub fn new(io: Io) -> Self {
        Self { io }
    }

    /// Returns a reference to the underlying IO implementation.
    pub fn io(&self) -> &Io {
        &self.io
    }

    /// Returns a mutable reference to the underlying IO implementation.
    pub fn io_mut(&mut self) -> &mut Io {
        &mut self.io
    }

    /// Polls for a response from the broker server.
    ///
    /// This method attempts to receive and parse a SetPsk response message from the server.
    /// If no message is available, returns `Ok(None)`. If a message is received, it is
    /// parsed and validated before being returned as `Ok(Some(result))`.
    ///
    /// # Returns
    /// - `Ok(Some(result))` if a valid response was received
    /// - `Ok(None)` if no message was available
    /// - `Err(BrokerClientPollResponseError)` if an error occurred during receiving or parsing
    ///
    /// # Errors
    /// Returns an error if:
    /// - An IO error occurs while receiving the message
    /// - The received message is invalid or malformed
    /// - The message type is incorrect
    pub fn poll_response(
        &mut self,
    ) -> Result<Option<msgs::SetPskResult>, BrokerClientPollResponseError<Io::RecvError>> {
        let res: &[u8] = match self.io.borrow_mut().recv_msg().map_err(io_poller)? {
            Some(r) => r,
            None => return Ok(None),
        };

        let typ = res.first().ok_or(invalid_msg_poller())?;
        let typ = msgs::MsgType::try_from(*typ)?;
        let msgs::MsgType::SetPsk = typ; // Assert type

        let res = zerocopy::Ref::<&[u8], Envelope<SetPskResponse>>::new(res)
            .ok_or(invalid_msg_poller())?;
        let res: &msgs::SetPskResponse = &res.payload;
        let res: msgs::SetPskResponseReturnCode = res
            .return_code
            .try_into()
            .map_err(|_| invalid_msg_poller())?;
        let res: msgs::SetPskResult = res.into();

        Ok(Some(res))
    }
}

impl<Io> WireGuardBroker for BrokerClient<Io>
where
    Io: BrokerClientIo + Debug,
{
    type Error = BrokerClientSetPskError<Io::SendError>;

    fn set_psk(&mut self, config: SerializedBrokerConfig) -> Result<(), Self::Error> {
        let config: Result<NetworkBrokerConfig, NetworkBrokerConfigErr> = config.try_into();
        let config = config.map_err(BrokerClientSetPskError::BrokerError)?;

        use BrokerClientSetPskError::*;
        const BUF_SIZE: usize = REQUEST_MSG_BUFFER_SIZE;

        // Allocate message
        let mut req = [0u8; BUF_SIZE];

        // Construct message view
        let mut req = zerocopy::Ref::<&mut [u8], Envelope<msgs::SetPskRequest>>::new(&mut req)
            .ok_or(MsgError)?;

        // Populate envelope
        req.msg_type = msgs::MsgType::SetPsk as u8;
        {
            // Derived payload
            let req = &mut req.payload;

            // Populate payload
            req.peer_id.copy_from_slice(&config.peer_id.value);
            req.psk.copy_from_slice(config.psk.secret());
            req.set_iface(config.iface.as_ref())
                .ok_or(IfaceOutOfBounds)?;
        }

        // Send message
        self.io
            .borrow_mut()
            .send_msg(req.bytes())
            .map_err(IoError)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use msgs::{MsgType, SetPskError, SetPskResponseReturnCode};

    // Mock IO implementation for testing
    #[derive(Debug)]
    struct MockIo {
        recv_data: Vec<u8>,
    }

    impl MockIo {
        fn new() -> Self {
            Self {
                recv_data: Vec::new(),
            }
        }

        fn set_recv_data(&mut self, data: Option<Vec<u8>>) {
            self.recv_data = data.unwrap_or_default();
        }
    }

    impl BrokerClientIo for MockIo {
        type SendError = std::io::Error;
        type RecvError = std::io::Error;

        fn send_msg(&mut self, _buf: &[u8]) -> Result<(), Self::SendError> {
            Ok(())
        }

        fn recv_msg(&mut self) -> Result<Option<&[u8]>, Self::RecvError> {
            if self.recv_data.is_empty() {
                Ok(None)
            } else {
                Ok(Some(&self.recv_data))
            }
        }
    }

    fn create_response_msg(return_code: u8) -> Vec<u8> {
        let mut msg = vec![
            MsgType::SetPsk as u8, // msg_type
            0,
            0,
            0, // reserved bytes
        ];
        msg.push(return_code); // return_code
        msg
    }

    #[test]
    fn test_poll_response_no_message() {
        let io = MockIo::new();
        let mut client = BrokerClient::new(io);

        assert_eq!(client.poll_response().unwrap(), None);
    }

    #[test]
    fn test_poll_response_success() {
        let mut io = MockIo::new();
        io.set_recv_data(Some(create_response_msg(
            SetPskResponseReturnCode::Success as u8,
        )));
        let mut client = BrokerClient::new(io);

        assert_eq!(client.poll_response().unwrap(), Some(Ok(())));
    }

    #[test]
    fn test_poll_response_no_such_peer() {
        let mut io = MockIo::new();
        io.set_recv_data(Some(create_response_msg(
            SetPskResponseReturnCode::NoSuchPeer as u8,
        )));
        let mut client = BrokerClient::new(io);

        assert_eq!(
            client.poll_response().unwrap(),
            Some(Err(SetPskError::NoSuchPeer))
        );
    }

    #[test]
    fn test_poll_response_invalid_message_type() {
        let mut io = MockIo::new();
        io.set_recv_data(Some(vec![0xFF, 0, 0, 0, 0])); // Invalid message type
        let mut client = BrokerClient::new(io);

        assert!(matches!(
            client.poll_response(),
            Err(BrokerClientPollResponseError::InvalidMessage)
        ));
    }

    #[test]
    fn test_poll_response_invalid_return_code() {
        let mut io = MockIo::new();
        io.set_recv_data(Some(create_response_msg(0xFF))); // Invalid return code
        let mut client = BrokerClient::new(io);

        assert!(matches!(
            client.poll_response(),
            Err(BrokerClientPollResponseError::InvalidMessage)
        ));
    }
}
