// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use super::connection::Endpoint;
use super::message::*;
use super::{Error, HandlerResult, Result};

pub trait VhostUserSlaveReqHandler {
    // fn handle_iotlb_msg(&mut self, iotlb: VhostUserIotlb);
    // fn handle_vring_host_notifier(&mut self, area: VhostUserVringArea, fd: RawFd);

    fn handle_config_change(&mut self) -> HandlerResult<()>;

    fn fs_slave_map(&mut self, fs: &VhostUserFSSlaveMsg, fd: RawFd) -> HandlerResult<()>;
    fn fs_slave_unmap(&mut self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<()>;
    fn fs_slave_sync(&mut self, fs: &VhostUserFSSlaveMsg) -> HandlerResult<()>;
}

/// A vhost-user slave request endpoint which relays all received requests from
/// slave to the provided  hander backend object.
pub struct SlaveReqHandler<S: VhostUserSlaveReqHandler> {
    // underlying Unix domain socket for communication
    fd: Endpoint<SlaveReq>,
    // the VirtIO backend device object
    backend: Arc<Mutex<S>>,
    // whether the endpoint has encountered any failure
    failed: bool,
}

impl<S: VhostUserSlaveReqHandler> SlaveReqHandler<S> {
    /// Create a vhost-user slave request handler. This opens a pair of connected
    /// anonymous sockets.
    /// Returns Self and the socket that must be sent to the slave via
    /// SET_SLAVE_REQ_FD.
    pub fn new(backend: Arc<Mutex<S>>) -> Result<(Self, UnixStream)> {
        let (tx, rx) = UnixStream::pair().map_err(Error::SocketError)?;

        Ok((
            SlaveReqHandler {
                fd: Endpoint::new_slave(rx),
                backend,
                failed: false,
            },
            tx,
        ))
    }

    /// Mark endpoint as failed or normal state.
    pub fn set_failed(&mut self, failed: bool) {
        self.failed = failed;
    }

    /// Receive and handle one incoming request message from the slave.
    /// The caller needs to:
    /// . serialize calls to this function
    /// . decide what to do when errer happens
    /// . optional recover from failure
    pub fn handle_request(&mut self) -> Result<()> {
        // Return error if the endpoint is already in failed state.
        self.check_state()?;

        // The underlying communication channel is a Unix domain socket in
        // stream mode, and recvmsg() is a little tricky here. To successfully
        // receive attached file descriptors, we need to receive messages and
        // corresponding attached file descriptors in this way:
        // . recv messsage header and optional attached file
        // . validate message header
        // . recv optional message body and payload according size field in
        //   message header
        // . validate message body and optional payload
        let (hdr, rfds) = self.fd.recv_header()?;
        let rfds = self.check_attached_rfds(&hdr, rfds)?;
        let mut size = 0;
        let buf = match hdr.get_size() {
            0 => vec![0u8; 0],
            len => {
                let (size2, rbuf, _) = self.fd.recv_into_buf::<[RawFd; 0]>(len as usize)?;
                if size2 != len as usize {
                    return Err(Error::InvalidMessage);
                }
                size = size2;
                rbuf
            }
        };

        match hdr.get_code() {
            SlaveReq::CONFIG_CHANGE_MSG => {
                self.check_msg_size(&hdr, size, 0)?;
                self.backend
                    .lock()
                    .unwrap()
                    .handle_config_change()
                    .map_err(Error::SlaveReqHandlerError)?;
            }
            SlaveReq::FS_MAP => {
                let msg = self.extract_msg_body::<VhostUserFSSlaveMsg>(&hdr, size, &buf)?;
                self.backend
                    .lock()
                    .unwrap()
                    .fs_slave_map(msg, rfds.unwrap()[0])
                    .map_err(Error::SlaveReqHandlerError)?;
            }
            SlaveReq::FS_UNMAP => {
                let msg = self.extract_msg_body::<VhostUserFSSlaveMsg>(&hdr, size, &buf)?;
                self.backend
                    .lock()
                    .unwrap()
                    .fs_slave_unmap(msg)
                    .map_err(Error::SlaveReqHandlerError)?;
            }
            SlaveReq::FS_SYNC => {
                let msg = self.extract_msg_body::<VhostUserFSSlaveMsg>(&hdr, size, &buf)?;
                self.backend
                    .lock()
                    .unwrap()
                    .fs_slave_sync(msg)
                    .map_err(Error::SlaveReqHandlerError)?;
            }
            _ => {
                return Err(Error::InvalidMessage);
            }
        }

        Ok(())
    }

    fn check_state(&self) -> Result<()> {
        if self.failed {
            return Err(Error::AlreadyClosed);
        }
        Ok(())
    }

    fn check_msg_size(
        &self,
        hdr: &VhostUserMsgHeader<SlaveReq>,
        size: usize,
        expected: usize,
    ) -> Result<()> {
        if hdr.get_size() as usize != expected
            || hdr.is_reply()
            || hdr.get_version() != 0x1
            || size != expected
        {
            return Err(Error::InvalidMessage);
        }
        Ok(())
    }

    fn check_attached_rfds(
        &self,
        hdr: &VhostUserMsgHeader<SlaveReq>,
        rfds: Option<Vec<RawFd>>,
    ) -> Result<Option<Vec<RawFd>>> {
        match hdr.get_code() {
            SlaveReq::FS_MAP => Ok(rfds),
            SlaveReq::FS_UNMAP => Ok(rfds),
            SlaveReq::FS_SYNC => Ok(rfds),
            _ => {
                if rfds.is_some() {
                    Endpoint::<SlaveReq>::close_rfds(rfds);
                    return Err(Error::InvalidMessage);
                } else {
                    Ok(rfds)
                }
            }
        }
    }

    fn extract_msg_body<'a, T: Sized + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<SlaveReq>,
        size: usize,
        buf: &'a Vec<u8>,
    ) -> Result<&'a T> {
        self.check_msg_size(hdr, size, mem::size_of::<T>())?;
        let msg = unsafe { &*(buf.as_ptr() as *const T) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        Ok(msg)
    }
}

impl<S: VhostUserSlaveReqHandler> AsRawFd for SlaveReqHandler<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
