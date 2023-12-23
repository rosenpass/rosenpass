#![allow(unused_macros)]
/// Whenever a log event occurs, the cause of the event must be decided on. This cause will then
/// be used to decide, if an actual log event is to be cause. The goal is to prevent especially
/// external, unautherized entities from causing excessive loggin, which otherwise might open the
/// door to MITM attacks
pub enum Cause {
    /// An unauthorized entitiy triggered this event via Network
    ///
    /// Example: a InitHello message in the rosenpass protocol
    UnauthorizedNetwork,

    /// An authorized entitity triggered this event via Network
    ///
    /// Example: a handshake was succesful (which asserts the peer is authorized)
    AuthorizedNetwork,

    /// A local entity like rosenpassctl triggered this event
    ///
    /// Example: the broker adds a new peer
    LocalNetwork,

    /// The user caused this event
    ///
    /// Examples:
    /// - The process was started
    /// - Ctrl+C was used to send sig SIGINT
    User,

    /// The developer wanted this in the log!
    Developer,
}

// Rational: All events are to be displayed if trace level debugging is configured
macro_rules! trace {
    ($cause:expr, $($tail:tt)* ) => {{
        use crate::Cause::*;
        match $cause {
            UnauthorizedNetwork | AuthorizedNetwork | LocalNetwork | User | Developer => {
                ::log::trace!($($tail)*);
            }
        }
    }}
}

// Rational: All events are to be displayed if debug level debugging is configured
macro_rules! debug {
    ($cause:expr, $($tail:tt)* ) => {{
        use crate::Cause::*;
        match $cause {
            UnauthorizedNetwork | AuthorizedNetwork | LocalNetwork | User | Developer => {
                ::log::debug!($($tail)*);
            }
        }
    }}
}

// Rational: Only authorized causes shall be able to emit info messages
macro_rules! info {
    ($cause:expr, $($tail:tt)* ) => {{
        use crate::Cause::*;
        match $cause {
            UnauthorizedNetwork => {},
             AuthorizedNetwork | LocalNetwork | User | Developer => {
                ::log::info!($($tail)*);
            }
        }
    }}
}

// Rational: Only authorized causes shall be able to emit info messages
macro_rules! warn {
    ($cause:expr, $($tail:tt)* ) => {{
        use crate::Cause::*;
        match $cause {
            UnauthorizedNetwork => {},
            AuthorizedNetwork | LocalNetwork | User | Developer =>{
                ::log::warn!($($tail)*);
            }
        }
    }}
}

// Rational: Only local sources shall be able to cause errors to be displayed
macro_rules! error {
    ($cause:expr, $($tail:tt)* ) => {{
        use crate::Cause::*;
        match $cause {
            UnauthorizedNetwork | AuthorizedNetwork => {},
            LocalNetwork | User | Developer => {
                ::log::error!($($tail)*);
            }
        }
    }}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_all_macros() {
        use Cause::*;

        trace!(UnauthorizedNetwork, "beep");
        debug!(UnauthorizedNetwork, "boop");
        info!(LocalNetwork, "tock");
        warn!(LocalNetwork, "möp");
        error!(User, "knirsch");
    }
}
