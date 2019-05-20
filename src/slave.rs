// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::slice;
use std::sync::{Arc, Mutex};

use super::connection::{Endpoint, Listener};
use super::message::*;
use super::{Error, Result};

pub trait VhostUserSlave {
    fn set_owner(&mut self) -> Result<()>;
    fn reset_owner(&mut self) -> Result<()>;
    fn get_features(&mut self) -> Result<u64>;
    fn set_features(&mut self, features: u64) -> Result<()>;
    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures>;
    fn set_protocol_features(&mut self, features: u64) -> Result<()>;

    fn set_mem_table(&mut self, ctx: &[VhostUserMemoryRegion], fds: &[RawFd]) -> Result<()>;

    fn get_queue_num(&mut self) -> Result<u64>;

    fn set_vring_num(&mut self, index: u32, num: u32) -> Result<()>;
    fn set_vring_addr(
        &mut self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()>;
    fn set_vring_base(&mut self, index: u32, base: u32) -> Result<()>;
    fn get_vring_base(&mut self, index: u32) -> Result<VhostUserVringState>;
    fn set_vring_kick(&mut self, index: u8, fd: Option<RawFd>) -> Result<()>;
    fn set_vring_call(&mut self, index: u8, fd: Option<RawFd>) -> Result<()>;
    fn set_vring_err(&mut self, index: u8, fd: Option<RawFd>) -> Result<()>;
    fn set_vring_enable(&mut self, index: u32, enable: bool) -> Result<()>;

    fn get_config(&mut self, buf: &[u8], flags: VhostUserConfigFlags) -> Result<Vec<u8>>;
    fn set_config(&mut self, buf: &[u8], offset: u32, flags: VhostUserConfigFlags) -> Result<()>;
}

pub struct SlaveListener<S: VhostUserSlave> {
    listener: Listener,
    backend: Option<Arc<Mutex<S>>>,
}

/// Sets up a listener for incoming master connections, and handles construction
/// of a Slave on success.
impl<S: VhostUserSlave> SlaveListener<S> {
    /// Create a unix domain socket for incoming master connections.
    pub fn new(path: &str, backend: Arc<Mutex<S>>) -> Result<Self> {
        Ok(SlaveListener {
            listener: Listener::new(path)?,
            backend: Some(backend),
        })
    }

    /// Accept an incoming connection from the master, returning Some(Slave) on
    /// success, or None if the socket is nonblocking and no incoming connection
    /// was detected
    pub fn accept(&mut self) -> Result<Option<Slave<S>>> {
        if let Some(fd) = self.listener.accept()? {
            return Ok(Some(Slave::new(fd, self.backend.take().unwrap())));
        }
        Ok(None)
    }

    /// Change blocking status on the listener.
    pub fn set_nonblocking(&self, block: bool) -> Result<()> {
        self.listener.set_nonblocking(block)
    }
}

/// A vhost-user slave endpoint which relays all received requests from the
/// master to the virtio backend device object.
pub struct Slave<S: VhostUserSlave> {
    // underlying Unix domain socket for communication
    fd: Endpoint<MasterReq>,
    // the VirtIO backend device object
    backend: Arc<Mutex<S>>,

    virtio_features: u64,
    acked_virtio_features: u64,
    protocol_features: VhostUserProtocolFeatures,
    acked_protocol_features: u64,

    // sending ack for messages without payload
    reply_ack_enabled: bool,
    // whether the endpoint has encountered any failure
    failed: bool,
}

impl<S: VhostUserSlave> Slave<S> {
    /// Create a vhost-user slave endpoint.
    fn new(fd: Endpoint<MasterReq>, backend: Arc<Mutex<S>>) -> Self {
        Slave {
            fd,
            backend,
            virtio_features: 0,
            acked_virtio_features: 0,
            protocol_features: VhostUserProtocolFeatures::empty(),
            acked_protocol_features: 0,
            reply_ack_enabled: false,
            failed: false,
        }
    }

    /// Mark endpoint as failed or normal state.
    pub fn set_failed(&mut self, failed: bool) {
        self.failed = failed;
    }

    /// Receive and handle one incoming request message from the master.
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
            MasterReq::SET_OWNER => {
                self.check_msg_size(&hdr, size, 0)?;
                self.backend.lock().unwrap().set_owner()?;
            }
            MasterReq::RESET_OWNER => {
                self.check_msg_size(&hdr, size, 0)?;
                self.backend.lock().unwrap().reset_owner()?;
            }
            MasterReq::GET_FEATURES => {
                self.check_msg_size(&hdr, size, 0)?;
                let features = self.backend.lock().unwrap().get_features()?;
                let msg = VhostUserU64::new(features);
                self.send_reply_message(&hdr, &msg)?;
                self.virtio_features = features;
                self.update_reply_ack_flag();
            }
            MasterReq::SET_FEATURES => {
                let msg = self.extract_msg_body::<VhostUserU64>(&hdr, size, &buf)?;
                self.backend.lock().unwrap().set_features(msg.value)?;
                self.acked_virtio_features = msg.value;
                self.update_reply_ack_flag();
            }
            MasterReq::GET_PROTOCOL_FEATURES => {
                self.check_msg_size(&hdr, size, 0)?;
                let features = self.backend.lock().unwrap().get_protocol_features()?;
                let msg = VhostUserU64::new(features.bits());
                self.send_reply_message(&hdr, &msg)?;
                self.protocol_features = features;
                self.update_reply_ack_flag();
            }
            MasterReq::SET_PROTOCOL_FEATURES => {
                let msg = self.extract_msg_body::<VhostUserU64>(&hdr, size, &buf)?;
                self.backend
                    .lock()
                    .unwrap()
                    .set_protocol_features(msg.value)?;
                self.acked_protocol_features = msg.value;
                self.update_reply_ack_flag();
            }
            MasterReq::SET_MEM_TABLE => {
                let res = self.set_mem_table(&hdr, size, &buf, rfds);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::GET_QUEUE_NUM => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_msg_size(&hdr, size, 0)?;
                let num = self.backend.lock().unwrap().get_queue_num()?;
                let msg = VhostUserU64::new(num);
                self.send_reply_message(&hdr, &msg)?;
            }
            MasterReq::SET_VRING_NUM => {
                let msg = self.extract_msg_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let res = self
                    .backend
                    .lock()
                    .unwrap()
                    .set_vring_num(msg.index, msg.num);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::SET_VRING_ADDR => {
                let msg = self.extract_msg_body::<VhostUserVringAddr>(&hdr, size, &buf)?;
                let flags = match VhostUserVringAddrFlags::from_bits(msg.flags) {
                    Some(val) => val,
                    None => return Err(Error::InvalidMessage),
                };
                let res = self.backend.lock().unwrap().set_vring_addr(
                    msg.index,
                    flags,
                    msg.descriptor,
                    msg.used,
                    msg.available,
                    msg.log,
                );
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::SET_VRING_BASE => {
                let msg = self.extract_msg_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let res = self
                    .backend
                    .lock()
                    .unwrap()
                    .set_vring_base(msg.index, msg.num);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::GET_VRING_BASE => {
                let msg = self.extract_msg_body::<VhostUserVringState>(&hdr, size, &buf)?;
                let reply = self.backend.lock().unwrap().get_vring_base(msg.index)?;
                self.send_reply_message(&hdr, &reply)?;
            }
            MasterReq::SET_VRING_CALL => {
                self.check_msg_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, rfds) = self.handle_vring_fd_request(&buf, rfds)?;
                let res = self.backend.lock().unwrap().set_vring_call(index, rfds);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::SET_VRING_KICK => {
                self.check_msg_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, rfds) = self.handle_vring_fd_request(&buf, rfds)?;
                let res = self.backend.lock().unwrap().set_vring_kick(index, rfds);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::SET_VRING_ERR => {
                self.check_msg_size(&hdr, size, mem::size_of::<VhostUserU64>())?;
                let (index, rfds) = self.handle_vring_fd_request(&buf, rfds)?;
                let res = self.backend.lock().unwrap().set_vring_err(index, rfds);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::SET_VRING_ENABLE => {
                let msg = self.extract_msg_body::<VhostUserVringState>(&hdr, size, &buf)?;
                if self.acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() == 0
                    && msg.index > 0
                {
                    return Err(Error::InvalidOperation);
                }
                let enable = match msg.num {
                    1 => true,
                    0 => false,
                    _ => return Err(Error::InvalidParam),
                };

                let res = self
                    .backend
                    .lock()
                    .unwrap()
                    .set_vring_enable(msg.index, enable);
                self.send_ack_message(&hdr, res)?;
            }
            MasterReq::GET_CONFIG => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.get_config(&hdr, &buf, size)?;
            }
            MasterReq::SET_CONFIG => {
                if self.acked_protocol_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
                    return Err(Error::InvalidOperation);
                }
                self.check_msg_size(&hdr, size, hdr.get_size() as usize)?;
                self.set_config(&hdr, size, &buf)?;
            }
            _ => {
                return Err(Error::InvalidMessage);
            }
        }
        Ok(())
    }

    fn set_mem_table(
        &mut self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        size: usize,
        buf: &Vec<u8>,
        rfds: Option<Vec<RawFd>>,
    ) -> Result<()> {
        self.check_msg_size(&hdr, size, hdr.get_size() as usize)?;

        // check message size is consistent
        let hdrsize = mem::size_of::<VhostUserMemory>();
        if size < hdrsize {
            Endpoint::<MasterReq>::close_rfds(rfds);
            return Err(Error::InvalidMessage);
        }
        let msg = unsafe { &*(buf.as_ptr() as *const VhostUserMemory) };
        if !msg.is_valid() {
            Endpoint::<MasterReq>::close_rfds(rfds);
            return Err(Error::InvalidMessage);
        }
        if size != hdrsize + msg.num_regions as usize * mem::size_of::<VhostUserMemoryRegion>() {
            Endpoint::<MasterReq>::close_rfds(rfds);
            return Err(Error::InvalidMessage);
        }

        // validate number of fds matching number of memory regions
        let fds = match rfds {
            None => return Err(Error::InvalidMessage),
            Some(fds) => {
                if fds.len() != msg.num_regions as usize {
                    Endpoint::<MasterReq>::close_rfds(Some(fds));
                    return Err(Error::InvalidMessage);
                }
                fds
            }
        };

        // Validate memory regions
        let regions = unsafe {
            slice::from_raw_parts(
                buf.as_ptr().add(hdrsize) as *const VhostUserMemoryRegion,
                msg.num_regions as usize,
            )
        };
        for region in regions.iter() {
            if !region.is_valid() {
                Endpoint::<MasterReq>::close_rfds(Some(fds));
                return Err(Error::InvalidMessage);
            }
        }

        self.backend.lock().unwrap().set_mem_table(&regions, &fds)
    }

    fn get_config(
        &mut self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        buf: &[u8],
        size: usize,
    ) -> Result<()> {
        if size < mem::size_of::<VhostUserConfig>() {
            return Err(Error::InvalidMessage);
        }
        let msg = unsafe { &*(buf.as_ptr() as *const VhostUserConfig) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        let payload_offset = mem::size_of::<VhostUserConfig>();
        if size - payload_offset != msg.size as usize || msg.offset > msg.size {
            return Err(Error::InvalidMessage);
        }
        let flags = match VhostUserConfigFlags::from_bits(msg.flags) {
            Some(val) => val,
            None => return Err(Error::InvalidMessage),
        };

        let res = self
            .backend
            .lock()
            .unwrap()
            .get_config(&buf[payload_offset..], flags);

        // vhost-user slave's payload size MUST match master's request
        // on success, uses zero length of payload to indicate an error
        // to vhost-user master.
        match res {
            Ok(ref buf) if buf.len() == msg.size as usize => {
                let reply = VhostUserConfig::new(msg.offset, buf.len() as u32, flags);
                self.send_reply_with_payload(&hdr, &reply, buf.as_slice())?;
            }
            Ok(_) => {
                let reply = VhostUserConfig::new(msg.offset, 0, flags);
                self.send_reply_message(&hdr, &reply)?;
            }
            Err(_) => {
                let reply = VhostUserConfig::new(msg.offset, 0, flags);
                self.send_reply_message(&hdr, &reply)?;
            }
        }
        Ok(())
    }

    fn set_config(
        &mut self,
        hdr: &VhostUserMsgHeader<MasterReq>,
        size: usize,
        buf: &[u8],
    ) -> Result<()> {
        if size < mem::size_of::<VhostUserConfig>() {
            return Err(Error::InvalidMessage);
        }
        let msg = unsafe { &*(buf.as_ptr() as *const VhostUserConfig) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }
        let payload_offset = mem::size_of::<VhostUserConfig>();
        if size - payload_offset != msg.size as usize || msg.offset > msg.size {
            return Err(Error::InvalidMessage);
        }
        let flags: VhostUserConfigFlags;
        match VhostUserConfigFlags::from_bits(msg.flags) {
            Some(val) => flags = val,
            None => return Err(Error::InvalidMessage),
        }

        let res =
            self.backend
                .lock()
                .unwrap()
                .set_config(&buf[payload_offset..], msg.offset, flags);
        self.send_ack_message(&hdr, res)?;
        Ok(())
    }

    fn handle_vring_fd_request(
        &mut self,
        buf: &[u8],
        rfds: Option<Vec<RawFd>>,
    ) -> Result<(u8, Option<RawFd>)> {
        let msg = unsafe { &*(buf.as_ptr() as *const VhostUserU64) };
        if !msg.is_valid() {
            return Err(Error::InvalidMessage);
        }

        // Bits (0-7) of the payload contain the vring index. Bit 8 is the
        // invalid FD flag. This flag is set when there is no file descriptor
        // in the ancillary data. This signals that polling will be used
        // instead of waiting for the call.
        let nofd = match msg.value & 0x100u64 {
            0x100u64 => true,
            _ => false,
        };

        let mut rfd = None;
        match rfds {
            Some(fds) => {
                if !nofd && fds.len() == 1 {
                    rfd = Some(fds[0]);
                } else if (nofd && fds.len() > 0) || (!nofd && fds.len() != 1) {
                    Endpoint::<MasterReq>::close_rfds(Some(fds));
                    return Err(Error::InvalidMessage);
                }
            }
            None => {
                if !nofd {
                    return Err(Error::InvalidMessage);
                }
            }
        }
        Ok((msg.value as u8, rfd))
    }

    fn check_state(&self) -> Result<()> {
        if self.failed {
            return Err(Error::AlreadyClosed);
        }
        Ok(())
    }

    fn check_msg_size(
        &self,
        hdr: &VhostUserMsgHeader<MasterReq>,
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
        hdr: &VhostUserMsgHeader<MasterReq>,
        rfds: Option<Vec<RawFd>>,
    ) -> Result<Option<Vec<RawFd>>> {
        match hdr.get_code() {
            MasterReq::SET_MEM_TABLE => Ok(rfds),
            MasterReq::SET_VRING_CALL => Ok(rfds),
            MasterReq::SET_VRING_KICK => Ok(rfds),
            MasterReq::SET_VRING_ERR => Ok(rfds),
            _ => {
                if rfds.is_some() {
                    Endpoint::<MasterReq>::close_rfds(rfds);
                    return Err(Error::InvalidMessage);
                } else {
                    Ok(rfds)
                }
            }
        }
    }

    fn extract_msg_body<'a, T: Sized + VhostUserMsgValidator>(
        &self,
        hdr: &VhostUserMsgHeader<MasterReq>,
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

    fn update_reply_ack_flag(&mut self) {
        let vflag = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let pflag = VhostUserProtocolFeatures::REPLY_ACK;
        if (self.virtio_features & vflag) != 0
            && (self.acked_virtio_features & vflag) != 0
            && self.protocol_features.contains(pflag)
            && (self.acked_protocol_features & pflag.bits()) != 0
        {
            self.reply_ack_enabled = true;
        } else {
            self.reply_ack_enabled = false;
        }
    }

    fn new_reply_header<T: Sized>(
        &self,
        req: &VhostUserMsgHeader<MasterReq>,
        payload_size: usize,
    ) -> Result<VhostUserMsgHeader<MasterReq>> {
        if self.failed {
            return Err(Error::AlreadyClosed);
        } else if mem::size_of::<T>() > MAX_MSG_SIZE {
            return Err(Error::InvalidParam);
        }
        Ok(VhostUserMsgHeader::new(
            req.get_code(),
            VhostUserHeaderFlag::REPLY.bits(),
            (mem::size_of::<T>() + payload_size) as u32,
        ))
    }

    fn send_ack_message(
        &mut self,
        req: &VhostUserMsgHeader<MasterReq>,
        res: Result<()>,
    ) -> Result<()> {
        if self.reply_ack_enabled {
            let hdr = self.new_reply_header::<VhostUserU64>(req, 0)?;
            let val = match res {
                Ok(_) => 0,
                Err(_) => 1,
            };
            let msg = VhostUserU64::new(val);
            self.fd.send_message(&hdr, &msg, None)?;
        }
        Ok(())
    }

    fn send_reply_message<T>(
        &mut self,
        req: &VhostUserMsgHeader<MasterReq>,
        msg: &T,
    ) -> Result<()> {
        let hdr = self.new_reply_header::<T>(req, 0)?;
        self.fd.send_message(&hdr, msg, None)?;
        Ok(())
    }

    fn send_reply_with_payload<T, P>(
        &mut self,
        req: &VhostUserMsgHeader<MasterReq>,
        msg: &T,
        payload: &[P],
    ) -> Result<()>
    where
        T: Sized,
        P: Sized,
    {
        let hdr = self.new_reply_header::<T>(req, payload.len())?;
        self.fd
            .send_message_with_payload(&hdr, msg, payload, None)?;
        Ok(())
    }
}

impl<S: VhostUserSlave> AsRawFd for Slave<S> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}
