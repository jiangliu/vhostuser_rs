// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::message::*;
use super::{Endpoint, Error, Result};
use std::mem;
use std::os::unix::io::RawFd;
use std::slice;
use std::sync::Mutex;

// Suggested initialization flow on master side:
//     set_owner()
//     get_features() -> set_features()
//     get_protocol_features() -> set_protocol_features()
//     set_mem_table()
//     get_queue_num()
//     for each vring
//         set_vring_num()
//         set_vring_addr()
//         set_vring_base()
//         set_vring_call()
//         set_vring_kick()
//         set_vring_err()
//     for each vring
//         set_vring_start()
pub trait VhostUserMaster {
    /// Set the current Master as an owner of the session.
    fn set_owner(&mut self) -> Result<()>;

    /// This is no longer used.
    fn reset_owner(&mut self) -> Result<()>;

    /// Get from the underlying vhost implementation the features bitmask.
    fn get_features(&mut self) -> Result<u64>;

    /// Enable features in the underlying vhost implementation using a bitmask.
    fn set_features(&mut self, features: u64) -> Result<()>;

    /// Get the protocol feature bitmask from the underlying vhost implementation.
    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures>;

    /// Enable protocol features in the underlying vhost implementation.
    fn set_protocol_features(&mut self, features: VhostUserProtocolFeatures) -> Result<()>;

    /// Set the memory map regions on the slave so it can translate the vring
    /// addresses. In the ancillary data there is an array of file descriptors
    fn set_mem_table(&mut self, ctx: &UserMemoryContext) -> Result<()>;

    /// Query how many queues the backend supports.
    fn get_queue_num(&mut self) -> Result<u64>;

    /// Set the size of the queue.
    fn set_vring_num(&mut self, index: u32, num: u32) -> Result<()>;

    /// Sets the addresses of the different aspects of the vring.
    fn set_vring_addr(
        &mut self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()>;

    /// Sets the base offset in the available vring.
    fn set_vring_base(&mut self, index: u32, base: u32) -> Result<()>;

    /// Get the available vring base offset.
    fn get_vring_base(&mut self, index: u32) -> Result<VhostUserVringState>;

    /// Set the event file descriptor for adding buffers to the vring.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid
    /// FD flag. This flag is set when there is no file descriptor in the
    /// ancillary data. This signals that polling should be used instead of
    /// waiting for a kick.
    fn set_vring_kick(&mut self, index: u8, fd: Option<RawFd>) -> Result<()>;

    /// Set the event file descriptor to signal when buffers are used.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid
    /// FD flag. This flag is set when there is no file descriptor in the
    /// ancillary data. This signals that polling will be used instead of
    /// waiting for the call.
    fn set_vring_call(&mut self, index: u8, fd: Option<RawFd>) -> Result<()>;

    /// Set the event file descriptor to signal when error occurs.
    /// Bits (0-7) of the payload contain the vring index. Bit 8 is the invalid
    /// FD flag. This flag is set when there is no file descriptor in the
    /// ancillary data.
    fn set_vring_err(&mut self, index: u8, fd: Option<RawFd>) -> Result<()>;

    /// Signal slave to enable or disable corresponding vring.
    /// Slave must not pass data to/from the backend until ring is enabled by
    /// VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has been
    /// disabled by VHOST_USER_SET_VRING_ENABLE with parameter 0.
    fn set_vring_enable(&mut self, index: u32, enable: bool) -> Result<()>;

    /// Fetch the contents of the virtio device configuration space.
    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
    ) -> Result<Vec<u8>>;

    /// Change the virtio device configuration space. It also can be used for
    /// live migration on the destination host to set readonly configuration
    /// space fields.
    fn set_config(&mut self, offset: u32, buf: &[u8], flags: VhostUserConfigFlags) -> Result<()>;
}

/// Vhost-user protocol master endpoint.
pub struct Master {
    //  Used to serialize calls to interface methods and accesses to internal
    //  master object.
    node: Mutex<MasterInternal>,
}

impl Master {
    /// Create a new vhost-user master endpoint.
    ///
    /// # Arguments
    /// * `path` - path of Unix domain socket listener to connect to
    pub fn new(path: &str) -> Result<Self> {
        let conn = Endpoint::new_master(path)?;
        Ok(Master {
            node: Mutex::new(MasterInternal {
                fd: conn,
                path: String::from(path),
                virtio_features: 0,
                acked_virtio_features: 0,
                protocol_features: 0,
                acked_protocol_features: 0,
                protocol_features_ready: false,
                max_queue_num: 1,
                failed: false,
            }),
        })
    }

    /// Get the path of Unix domain socket listener to connect to.
    pub fn get_path(&self) -> String {
        let node = self.node.lock().unwrap();
        node.path.clone()
    }
}

impl VhostUserMaster for Master {
    fn set_owner(&mut self) -> Result<()> {
        // We unwrap() the return value to assert that we are not expecting
        // threads to ever fail while holding the lock.
        let mut node = self.node.lock().unwrap();
        let _ = node.send_header(VhostUserRequestCode::SET_OWNER)?;
        // Don't wait for ACK here because the protocol feature negotiation
        // process hasn't been completed yet.
        Ok(())
    }

    fn reset_owner(&mut self) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        let _ = node.send_header(VhostUserRequestCode::RESET_OWNER)?;
        // Don't wait for ACK here because the protocol feature negotiation
        // process hasn't been completed yet.
        Ok(())
    }

    fn get_features(&mut self) -> Result<u64> {
        let mut node = self.node.lock().unwrap();
        let hdr = node.send_header(VhostUserRequestCode::GET_FEATURES)?;
        let val = node.recv_message::<VhostUserU64>(&hdr)?;
        node.virtio_features = val.value;
        Ok(node.virtio_features)
    }

    fn set_features(&mut self, features: u64) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        let val = VhostUserU64::new(features);
        let _ = node.send_message(VhostUserRequestCode::SET_FEATURES, &val)?;
        // Don't wait for ACK here because the protocol feature negotiation
        // process hasn't been completed yet.
        node.acked_virtio_features = features & node.virtio_features;
        Ok(())
    }

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures> {
        let mut node = self.node.lock().unwrap();
        let flag = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        if node.virtio_features & flag == 0 || node.acked_virtio_features & flag == 0 {
            return Err(Error::InvalidOperation);
        }
        let hdr = node.send_header(VhostUserRequestCode::GET_PROTOCOL_FEATURES)?;
        let val = node.recv_message::<VhostUserU64>(&hdr)?;
        node.protocol_features = val.value;
        // Should we support forward compability? If so just mask out
        // unrecognized flags instead of return errors.
        match VhostUserProtocolFeatures::from_bits(node.protocol_features) {
            Some(val) => Ok(val),
            None => Err(Error::InvalidContent),
        }
    }

    fn set_protocol_features(&mut self, features: VhostUserProtocolFeatures) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        let flag = VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        if node.virtio_features & flag == 0 || node.acked_virtio_features & flag == 0 {
            return Err(Error::InvalidOperation);
        }
        let val = VhostUserU64::new(features.bits());
        let _ = node.send_message(VhostUserRequestCode::SET_PROTOCOL_FEATURES, &val)?;
        // Don't wait for ACK here because the protocol feature negotiation
        // process hasn't been completed yet.
        node.acked_protocol_features = features.bits();
        node.protocol_features_ready = true;
        Ok(())
    }

    //<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    fn set_mem_table(&mut self, ctx: &UserMemoryContext) -> Result<()> {
        if ctx.regions.len() == 0
            || ctx.regions.len() > MAX_ATTECHED_FD_ENTRIES
            || ctx.regions.len() != ctx.fds.len()
        {
            return Err(Error::InvalidParam);
        }

        let mut node = self.node.lock().unwrap();
        let body = VhostUserMemory::new(ctx.regions.len() as u32);
        let hdr = node.send_message_with_payload(
            VhostUserRequestCode::SET_MEM_TABLE,
            &body,
            ctx.regions.as_slice(),
            Some(ctx.fds.as_slice()),
        )?;
        node.wait_for_ack(&hdr)
    }

    fn get_queue_num(&mut self) -> Result<u64> {
        let mut node = self.node.lock().unwrap();
        if !node.is_feature_mq_available() {
            return Err(Error::InvalidOperation);
        }

        let hdr = node.send_header(VhostUserRequestCode::GET_QUEUE_NUM)?;
        let val = node.recv_message::<VhostUserU64>(&hdr)?;
        node.max_queue_num = val.value;
        Ok(node.max_queue_num)
    }

    fn set_vring_num(&mut self, index: u32, num: u32) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if index as u64 >= node.max_queue_num {
            return Err(Error::InvalidParam);
        }

        let val = VhostUserVringState::new(index, num);
        let hdr = node.send_message(VhostUserRequestCode::SET_VRING_NUM, &val)?;
        node.wait_for_ack(&hdr)
    }

    fn set_vring_addr(
        &mut self,
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if index as u64 >= node.max_queue_num {
            return Err(Error::InvalidParam);
        } else if !(flags & !VhostUserVringAddrFlags::all()).is_empty() {
            return Err(Error::InvalidParam);
        }

        let val = VhostUserVringAddr::new(index, flags, descriptor, used, available, log);
        let hdr = node.send_message(VhostUserRequestCode::SET_VRING_ADDR, &val)?;
        node.wait_for_ack(&hdr)
    }

    fn set_vring_base(&mut self, index: u32, base: u32) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if index as u64 >= node.max_queue_num {
            return Err(Error::InvalidParam);
        }

        let val = VhostUserVringState::new(index, base);
        let hdr = node.send_message(VhostUserRequestCode::SET_VRING_BASE, &val)?;
        node.wait_for_ack(&hdr)
    }

    fn get_vring_base(&mut self, index: u32) -> Result<VhostUserVringState> {
        let mut node = self.node.lock().unwrap();
        if index as u64 >= node.max_queue_num {
            return Err(Error::InvalidParam);
        }

        let req = VhostUserVringState::new(index, 0);
        let hdr = node.send_message(VhostUserRequestCode::GET_VRING_BASE, &req)?;
        let reply = node.recv_message::<VhostUserVringState>(&hdr)?;
        Ok(reply)
    }

    fn set_vring_kick(&mut self, index: u8, fd: Option<RawFd>) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if index as u64 >= node.max_queue_num {
            return Err(Error::InvalidParam);
        }

        node.send_fd_with_info(VhostUserRequestCode::SET_VRING_KICK, index, fd)
    }

    fn set_vring_call(&mut self, index: u8, fd: Option<RawFd>) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if index as u64 >= node.max_queue_num {
            return Err(Error::InvalidParam);
        }

        node.send_fd_with_info(VhostUserRequestCode::SET_VRING_CALL, index, fd)
    }

    fn set_vring_err(&mut self, index: u8, fd: Option<RawFd>) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        if index as u64 >= node.max_queue_num {
            return Err(Error::InvalidParam);
        }

        node.send_fd_with_info(VhostUserRequestCode::SET_VRING_ERR, index, fd)
    }

    fn set_vring_enable(&mut self, index: u32, enable: bool) -> Result<()> {
        let mut node = self.node.lock().unwrap();
        // set_vring_enable() is supported only when PROTOCOL_FEATURES has been enabled.
        if node.acked_virtio_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0 {
            return Err(Error::InvalidOperation);
        } else if index as u64 >= node.max_queue_num {
            return Err(Error::InvalidParam);
        }

        let flag = match enable {
            true => 1,
            false => 0,
        };
        let val = VhostUserVringState::new(index, flag);
        let hdr = node.send_message(VhostUserRequestCode::SET_VRING_ENABLE, &val)?;
        node.wait_for_ack(&hdr)
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        flags: VhostUserConfigFlags,
    ) -> Result<Vec<u8>> {
        let body = VhostUserConfig::new(offset, size, flags);
        if !body.is_valid() {
            return Err(Error::InvalidParam);
        }

        let mut node = self.node.lock().unwrap();
        // depends on VhostUserProtocolFeatures::CONFIG
        if node.acked_virtio_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
            return Err(Error::InvalidOperation);
        }

        // TODO: vhost-user spec states that:
        // "Master payload: virtio device config space"
        // But what conent should the payload contains for a get_config()
        // request? So current implementation doesn't conform to the spec.
        let hdr = node.send_message(VhostUserRequestCode::GET_CONFIG, &body)?;
        let (reply, buf, rfds) = node.recv_reply_with_payload::<VhostUserConfig>(&hdr)?;
        if rfds.is_some() {
            Endpoint::close_rfds(rfds);
            return Err(Error::InvalidMessage);
        } else if reply.size == 0 {
            return Err(Error::OperationFailedInSlave);
        } else if reply.size != body.size || reply.size as usize != buf.len() {
            return Err(Error::InvalidMessage);
        }
        Ok(buf)
    }

    fn set_config(&mut self, offset: u32, buf: &[u8], flags: VhostUserConfigFlags) -> Result<()> {
        if buf.len() > MAX_MSG_SIZE {
            return Err(Error::InvalidParam);
        }
        let body = VhostUserConfig::new(offset, buf.len() as u32, flags);
        if !body.is_valid() {
            return Err(Error::InvalidParam);
        }

        let mut node = self.node.lock().unwrap();
        // depends on VhostUserProtocolFeatures::CONFIG
        if node.acked_virtio_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
            return Err(Error::InvalidOperation);
        }

        let hdr =
            node.send_message_with_payload(VhostUserRequestCode::GET_CONFIG, &body, buf, None)?;
        node.wait_for_ack(&hdr)
    }
    //=============================>
}

/// Context object to pass memory information to set_mem_table().
/// VhostUserMemoryRegion entries should be paired with corresponding RawFd.
pub struct UserMemoryContext {
    regions: VhostUserMemoryPayload,
    fds: Vec<RawFd>,
}

impl UserMemoryContext {
    /// Create a context object.
    pub fn new() -> Self {
        UserMemoryContext {
            regions: VhostUserMemoryPayload::new(),
            fds: Vec::new(),
        }
    }

    /// Append a user memory region and corresponding RawFd into the context object.
    pub fn append(&mut self, region: &VhostUserMemoryRegion, fd: RawFd) {
        self.regions.push(*region);
        self.fds.push(fd);
    }
}

struct MasterInternal {
    // Underline Unix domain socket for communication
    fd: Endpoint,
    // Path of Unix domain socket listener to connect to
    path: String,
    virtio_features: u64,
    acked_virtio_features: u64,
    protocol_features: u64,
    acked_protocol_features: u64,
    protocol_features_ready: bool,
    max_queue_num: u64,
    // the endpoint is in failure mode
    failed: bool,
}

impl MasterInternal {
    fn send_header(&mut self, code: VhostUserRequestCode) -> Result<VhostUserMsgHeader> {
        if self.failed {
            return Err(Error::AlreadyClosed);
        }

        let hdr = Self::new_request_header(code, 0);
        self.fd.send_header(&hdr, None)?;
        Ok(hdr)
    }

    fn send_message<T: Sized>(
        &mut self,
        code: VhostUserRequestCode,
        msg: &T,
    ) -> Result<VhostUserMsgHeader> {
        if self.failed {
            return Err(Error::AlreadyClosed);
        } else if mem::size_of::<T>() > MAX_MSG_SIZE {
            return Err(Error::InvalidParam);
        }

        let hdr = Self::new_request_header(code, mem::size_of::<T>() as u32);
        self.fd.send_message(&hdr, msg, None)?;
        Ok(hdr)
    }

    fn send_message_with_payload<T: Sized, P: Sized>(
        &mut self,
        code: VhostUserRequestCode,
        msg: &T,
        payload: &[P],
        fds: Option<&[RawFd]>,
    ) -> Result<VhostUserMsgHeader> {
        let len = mem::size_of::<T>() + payload.len() * mem::size_of::<P>();
        if self.failed {
            return Err(Error::AlreadyClosed);
        } else if len > MAX_MSG_SIZE {
            return Err(Error::InvalidParam);
        }
        if let Some(ref fd_arr) = fds {
            if fd_arr.len() > MAX_ATTECHED_FD_ENTRIES {
                return Err(Error::InvalidParam);
            }
        }

        let hdr = Self::new_request_header(code, len as u32);
        self.fd.send_message_with_payload(&hdr, msg, payload, fds)?;
        Ok(hdr)
    }

    fn send_fd_with_info(
        &mut self,
        code: VhostUserRequestCode,
        index: u8,
        fd: Option<RawFd>,
    ) -> Result<()> {
        if self.failed {
            return Err(Error::AlreadyClosed);
        } else if index as u64 >= self.max_queue_num {
            return Err(Error::InvalidParam);
        }

        // Bits (0-7) of the payload contain the vring index. Bit 8 is the
        // invalid FD flag. This flag is set when there is no file descriptor
        // in the ancillary data. This signals that polling will be used
        // instead of waiting for the call.
        let mut msg = VhostUserU64::new((index as u64) | 0x100u64);

        let hdr = Self::new_request_header(code, mem::size_of::<VhostUserU64>() as u32);
        let mut fd_array = Vec::new();
        let mut fds = None;
        if let Some(rawfd) = fd {
            fd_array.push(rawfd);
            fds = Some(fd_array.as_slice());
            msg.value &= !0x100;
        }
        self.fd.send_message(&hdr, &msg, fds)?;
        Ok(())
    }

    fn recv_message<T: Sized + Default + VhostUserMsgValidator>(
        &mut self,
        hdr: &VhostUserMsgHeader,
    ) -> Result<T> {
        if mem::size_of::<T>() > MAX_MSG_SIZE {
            return Err(Error::InvalidParam);
        }

        let mut val: T = Default::default();
        let slice = unsafe {
            slice::from_raw_parts_mut((&mut val as *mut T) as *mut u8, mem::size_of::<T>())
        };
        let (hdr2, bytes, rfds) = self.fd.recv_message_into_buf(slice)?;
        if !hdr2.is_reply_for(&hdr)
            || bytes != mem::size_of::<T>()
            || rfds.is_some()
            || !val.is_valid()
        {
            Endpoint::close_rfds(rfds);
            return Err(Error::InvalidMessage);
        }
        Ok(val)
    }

    fn recv_reply_with_payload<T: Sized + Default + VhostUserMsgValidator>(
        &mut self,
        hdr: &VhostUserMsgHeader,
    ) -> Result<(T, Vec<u8>, Option<Vec<RawFd>>)> {
        if mem::size_of::<T>() > MAX_MSG_SIZE || hdr.is_reply() {
            return Err(Error::InvalidParam);
        }

        let mut buf = vec![0; MAX_MSG_SIZE - mem::size_of::<T>()];
        let (reply, body, bytes, rfds) = self.fd.recv_message_with_payload::<T>(&mut buf)?;
        if !reply.is_reply()
            || reply.get_code() != hdr.get_code()
            || reply.get_size() as usize != mem::size_of::<T>() + bytes
        {
            return Err(Error::InvalidMessage);
        } else if bytes > MAX_MSG_SIZE - mem::size_of::<T>() {
            return Err(Error::InvalidMessage);
        } else if bytes < buf.len() {
            // It's safe because have have checked the buffer size
            unsafe { buf.set_len(bytes) };
        }
        Ok((body, buf, rfds))
    }

    fn wait_for_ack(&mut self, hdr: &VhostUserMsgHeader) -> Result<()> {
        if self.acked_protocol_features & VhostUserProtocolFeatures::REPLY_ACK.bits() == 0 {
            return Ok(());
        } else if !hdr.is_need_reply() {
            return Ok(());
        }

        let mut val: VhostUserU64 = Default::default();
        let slice = unsafe {
            slice::from_raw_parts_mut(
                (&mut val as *mut VhostUserU64) as *mut u8,
                mem::size_of::<VhostUserU64>(),
            )
        };
        let (hdr2, bytes, rfds) = self.fd.recv_message_into_buf(slice)?;
        if !hdr2.is_reply_for(&hdr)
            || bytes != mem::size_of::<VhostUserU64>()
            || rfds.is_some()
            || !val.is_valid()
        {
            Endpoint::close_rfds(rfds);
            return Err(Error::InvalidMessage);
        }
        if val.value != 0 {
            return Err(Error::OperationFailedInSlave);
        }
        Ok(())
    }

    fn is_feature_mq_available(&mut self) -> bool {
        self.acked_protocol_features & VhostUserProtocolFeatures::MQ.bits() != 0
    }

    fn new_request_header(request: VhostUserRequestCode, size: u32) -> VhostUserMsgHeader {
        // TODO: handle NEED_REPLY flag
        VhostUserMsgHeader::new(request, 0, size)
    }
}

#[cfg(test)]
mod tests {
    use super::super::Listener;
    use super::*;
    use std::fs;

    const UNIX_SOCKET_MASTER: &'static str = "/tmp/vhost_user_test_rust_master";
    const UNIX_SOCKET_MASTER2: &'static str = "/tmp/vhost_user_test_rust_master2";
    const UNIX_SOCKET_MASTER3: &'static str = "/tmp/vhost_user_test_rust_master3";
    const UNIX_SOCKET_MASTER4: &'static str = "/tmp/vhost_user_test_rust_master4";

    fn remove_temp_file(path: &str) {
        let _ = fs::remove_file(path);
    }

    fn create_pair(path: &str) -> (Master, Endpoint) {
        remove_temp_file(path);
        let listener = Listener::new(path).unwrap();
        let master = Master::new(path).unwrap();
        let slave = listener.accept().unwrap().unwrap();
        (master, slave)
    }

    #[test]
    fn create_master() {
        remove_temp_file(UNIX_SOCKET_MASTER);
        let listener = Listener::new(UNIX_SOCKET_MASTER).unwrap();
        let mut master = Master::new(UNIX_SOCKET_MASTER).unwrap();
        let mut slave = listener.accept().unwrap().unwrap();

        // Send two messages continuously
        master.set_owner().unwrap();
        master.reset_owner().unwrap();

        let (hdr, rfds) = slave.recv_header().unwrap();
        assert_eq!(hdr.get_code(), VhostUserRequestCode::SET_OWNER);
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_none());

        let (hdr, rfds) = slave.recv_header().unwrap();
        assert_eq!(hdr.get_code(), VhostUserRequestCode::RESET_OWNER);
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_none());
    }

    #[test]
    fn test_create_failure() {
        remove_temp_file(UNIX_SOCKET_MASTER2);
        assert!(Master::new(UNIX_SOCKET_MASTER2).is_err());

        let listener = Listener::new(UNIX_SOCKET_MASTER2).unwrap();
        assert!(Listener::new(UNIX_SOCKET_MASTER2).is_err());

        let master = Master::new(UNIX_SOCKET_MASTER2).unwrap();
        let _slave = listener.accept().unwrap().unwrap();
        assert_eq!(UNIX_SOCKET_MASTER2, master.get_path());
    }

    #[test]
    fn test_features() {
        let (mut master, mut peer) = create_pair(UNIX_SOCKET_MASTER3);

        master.set_owner().unwrap();
        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code(), VhostUserRequestCode::SET_OWNER);
        assert_eq!(hdr.get_size(), 0);
        assert_eq!(hdr.get_version(), 0x1);
        assert!(rfds.is_none());

        let hdr = VhostUserMsgHeader::new(VhostUserRequestCode::GET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(0x15);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = master.get_features().unwrap();
        assert_eq!(features, 0x15u64);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_none());

        master.set_features(0x15).unwrap();
        let (_hdr, msg, rfds) = peer.recv_message::<VhostUserU64>().unwrap();
        assert!(rfds.is_none());
        let val = msg.value;
        assert_eq!(val, 0x15);

        let hdr = VhostUserMsgHeader::new(VhostUserRequestCode::GET_FEATURES, 0x4, 8);
        let msg = 0x15u32;
        peer.send_message(&hdr, &msg, None).unwrap();
        assert!(master.get_features().is_err());
    }

    #[test]
    fn test_protocol_features() {
        let (mut master, mut peer) = create_pair(UNIX_SOCKET_MASTER4);

        master.set_owner().unwrap();
        let (hdr, rfds) = peer.recv_header().unwrap();
        assert_eq!(hdr.get_code(), VhostUserRequestCode::SET_OWNER);
        assert!(rfds.is_none());

        assert!(master.get_protocol_features().is_err());
        assert!(master
            .set_protocol_features(VhostUserProtocolFeatures::all())
            .is_err());

        let vfeatures = 0x15 | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
        let hdr = VhostUserMsgHeader::new(VhostUserRequestCode::GET_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(vfeatures);
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = master.get_features().unwrap();
        assert_eq!(features, vfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_none());

        master.set_features(vfeatures).unwrap();
        let (_hdr, msg, rfds) = peer.recv_message::<VhostUserU64>().unwrap();
        assert!(rfds.is_none());
        let val = msg.value;
        assert_eq!(val, vfeatures);

        let pfeatures = VhostUserProtocolFeatures::all();
        let hdr = VhostUserMsgHeader::new(VhostUserRequestCode::GET_PROTOCOL_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(pfeatures.bits());
        peer.send_message(&hdr, &msg, None).unwrap();
        let features = master.get_protocol_features().unwrap();
        assert_eq!(features, pfeatures);
        let (_hdr, rfds) = peer.recv_header().unwrap();
        assert!(rfds.is_none());

        master.set_protocol_features(pfeatures).unwrap();
        let (_hdr, msg, rfds) = peer.recv_message::<VhostUserU64>().unwrap();
        assert!(rfds.is_none());
        let val = msg.value;
        assert_eq!(val, pfeatures.bits());

        let hdr = VhostUserMsgHeader::new(VhostUserRequestCode::SET_PROTOCOL_FEATURES, 0x4, 8);
        let msg = VhostUserU64::new(pfeatures.bits());
        peer.send_message(&hdr, &msg, None).unwrap();
        assert!(master.get_protocol_features().is_err());
    }

    #[test]
    fn test_set_mem_table() {
        // TODO
    }

    #[test]
    fn test_get_ring_num() {
        // TODO
    }

    #[test]
    fn test_set_vring_info() {
        // TODO
    }
}
