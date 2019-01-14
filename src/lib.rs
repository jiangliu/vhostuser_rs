// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/// The protocol for vhost-user is based on the existing implementation of
/// vhost for the Linux Kernel. The protocol defines two sides of the
/// communication, master and slave. Master is the application that shares
/// its virtqueues. Slave is the consumer of the virtqueues.
///
/// The communication channel between the master and the slave includes two
/// sub channels. One is used to send requests from the master to the slave
/// and optional replies from the slave to the master. This sub channel is
/// created on master startup by connecting to the slave service endpoint.
/// The other is used to send requests from the slave to the master and
/// optional replies from the master to the slave. This sub channel is
/// created by the master issuing a VHOST_USER_SET_SLAVE_REQ_FD request to
/// the slave with an auxiliary file descriptor.
///
/// Unix domain socket is used as the underline communication channel because
/// the master needs to send file descriptors to the slave.
///
/// Most messages that can be sent via the Unix domain socket implementing
/// vhost-user have an equivalent ioctl to the kernel implementation.
extern crate libc;
extern crate nix;
#[macro_use]
extern crate bitflags;

mod connection;
pub use connection::{Endpoint, Listener};

mod master;
pub use master::{Master, UserMemoryContext, VhostUserMaster};

mod slave;
pub use slave::{Slave, VhostUserSlave};

pub mod message;

#[derive(Debug)]
pub enum Error {
    /// Failure in socket read/write operations
    SocketError(std::io::Error),
    /// Failure when connecting to the slave
    ConnectFail(std::io::Error),
    /// Error conditions from the nix library
    NixError(nix::Error),
    /// Fd array in question is too big or too small
    FdArrayCapacity,
    /// Message is too large
    OversizedMsg,
    /// Only part of a message have been sent or received successfully
    PartialMessage,
    /// Invalid message format or flags
    InvalidMessage,
    /// Invalid value in message fields
    InvalidContent,
    /// Underline socket has been closed due to errors
    AlreadyClosed,
    /// Some parameters is invalid
    InvalidParam,
    /// Invalid operation because protocol feature is disabled
    InvalidOperation,
    /// Operation failed on slave side
    OperationFailedInSlave,
}

impl std::convert::From<nix::Error> for Error {
    fn from(err: nix::Error) -> Self {
        Error::NixError(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {}
