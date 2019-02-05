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
/// Unix domain socket is used as the underlying communication channel because
/// the master needs to send file descriptors to the slave.
///
/// Most messages that can be sent via the Unix domain socket implementing
/// vhost-user have an equivalent ioctl to the kernel implementation.
extern crate libc;
extern crate nix;
#[macro_use]
extern crate bitflags;

mod connection;
#[cfg(test)]
mod dummy_slave;
mod master;
pub mod message;
mod slave;

pub use connection::{Endpoint, Listener};
pub use master::{Master, UserMemoryContext, VhostUserMaster};
pub use slave::{Slave, VhostUserSlave};

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
    /// Underlying socket has been closed due to errors
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
mod tests {
    use super::dummy_slave::{DummySlave, VIRTIO_FEATURES};
    use super::message::*;
    use super::*;
    use std::fs;
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    fn remove_temp_file(path: &str) {
        let _ = fs::remove_file(path);
    }

    fn create_slave<S: VhostUserSlave>(path: &str, backend: Arc<Mutex<S>>) -> (Master, Slave<S>) {
        remove_temp_file(path);
        let listener = Listener::new(path).unwrap();
        let master = Master::new(path).unwrap();
        let slave_fd = listener.accept().unwrap().unwrap();
        (master, Slave::new(slave_fd, backend))
    }

    #[test]
    fn create_dummy_slave() {
        let mut slave = DummySlave::new();

        slave.set_owner().unwrap();
        assert!(slave.set_owner().is_err());
    }

    #[test]
    fn test_set_owner() {
        let slave_be = Arc::new(Mutex::new(DummySlave::new()));
        let (mut master, mut slave) =
            create_slave("/tmp/vhost_user_lib_unit_test_owner", slave_be.clone());

        assert_eq!(slave_be.lock().unwrap().owned, false);
        master.set_owner().unwrap();
        slave.handle_request().unwrap();
        assert_eq!(slave_be.lock().unwrap().owned, true);
        master.set_owner().unwrap();
        assert!(slave.handle_request().is_err());
        assert_eq!(slave_be.lock().unwrap().owned, true);
    }

    #[test]
    fn test_set_features() {
        let mbar = Arc::new(Barrier::new(2));
        let sbar = mbar.clone();
        let slave_be = Arc::new(Mutex::new(DummySlave::new()));
        let (mut master, mut slave) =
            create_slave("/tmp/vhost_user_lib_unit_test_feature", slave_be.clone());

        thread::spawn(move || {
            slave.handle_request().unwrap();
            assert_eq!(slave_be.lock().unwrap().owned, true);

            slave.handle_request().unwrap();
            slave.handle_request().unwrap();
            assert_eq!(
                slave_be.lock().unwrap().acked_features,
                VIRTIO_FEATURES & !0x1
            );

            slave.handle_request().unwrap();
            slave.handle_request().unwrap();
            assert_eq!(
                slave_be.lock().unwrap().acked_protocol_features,
                VhostUserProtocolFeatures::all().bits()
            );

            sbar.wait();
        });

        master.set_owner().unwrap();

        // set virtio features
        let features = master.get_features().unwrap();
        assert_eq!(features, VIRTIO_FEATURES);
        master.set_features(VIRTIO_FEATURES & !0x1).unwrap();

        // set vhost protocol features
        let features = master.get_protocol_features().unwrap();
        assert_eq!(features, VhostUserProtocolFeatures::all().bits());
        master.set_protocol_features(features).unwrap();

        mbar.wait();
    }
}
