// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::fmt::Debug;
use std::marker::PhantomData;

/// The vhost-user specification uses a field of u32 to store message length.
/// On the other hand, preallocated buffers are needed to receive messages
/// from the Unix domain socket. To preallocating a 4GB buffer for vhost-user
/// messages is really just an overhead. Among all defined vhost-user messages,
/// only VhostUserConfig and VhostUserMemory has variable message size. For
/// VhostUserConfig, a maximum size of 4K is enough because the user
/// configuration space in virtio devices is (4K - 0x100) bytes at most.
/// For VhostUserMemory, 4K should be enough too because it can support
/// 255 memory regions at most.
pub const MAX_MSG_SIZE: usize = 0x1000;

/// The VhostUserMemory message has variable message size and variable number of
/// attached file descriptors. Each user memory entry in the message payload
/// occupies 32 bytes, so set maximum number of attached file descriptors based
/// on maximum message size.
//pub const MAX_ATTECHED_FD_ENTRIES: usize = (MAX_MSG_SIZE - 8) / 32;
// But rust only implements Default and AsMut traits for arrays with 0 - 32
// entries, so furthur reduce the maximum number...
pub const MAX_ATTECHED_FD_ENTRIES: usize = 32;

pub const VHOST_USER_CONFIG_OFFSET: u32 = 0x100;
pub const VHOST_USER_CONFIG_SIZE: u32 = 0x1000;

pub(crate) trait Req:
    Clone + Copy + Debug + PartialEq + Eq + PartialOrd + Ord + Into<u32>
{
    fn is_valid(&self) -> bool;
}

/// All request codes defined by the vhost-user protocol.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum MasterReq {
    NOOP = 0,
    GET_FEATURES = 1,
    SET_FEATURES = 2,
    SET_OWNER = 3,
    RESET_OWNER = 4,
    SET_MEM_TABLE = 5,
    SET_LOG_BASE = 6,
    SET_LOG_FD = 7,
    SET_VRING_NUM = 8,
    SET_VRING_ADDR = 9,
    SET_VRING_BASE = 10,
    GET_VRING_BASE = 11,
    SET_VRING_KICK = 12,
    SET_VRING_CALL = 13,
    SET_VRING_ERR = 14,
    GET_PROTOCOL_FEATURES = 15,
    SET_PROTOCOL_FEATURES = 16,
    GET_QUEUE_NUM = 17,
    SET_VRING_ENABLE = 18,
    SEND_RARP = 19,
    NET_SET_MTU = 20,
    SET_SLAVE_REQ_FD = 21,
    IOTLB_MSG = 22,
    SET_VRING_ENDIAN = 23,
    GET_CONFIG = 24,
    SET_CONFIG = 25,
    CREATE_CRYPTO_SESSION = 26,
    CLOSE_CRYPTO_SESSION = 27,
    POSTCOPY_ADVISE = 28,
    POSTCOPY_LISTEN = 29,
    POSTCOPY_END = 30,
    MAX_CMD = 31,
}

impl Into<u32> for MasterReq {
    fn into(self) -> u32 {
        self as u32
    }
}

impl Req for MasterReq {
    fn is_valid(&self) -> bool {
        (*self > MasterReq::NOOP) && (*self < MasterReq::MAX_CMD)
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SlaveReq {
    NONE = 0,
    IOTLB_MSG = 1,
    CONFIG_CHANGE_MSG = 2,
    VRING_HOST_NOTIFIER_MSG = 3,
    FS_MAP = 4,
    FS_UNMAP = 5,
    FS_SYNC = 6,
    MAX_CMD = 7,
}

impl Into<u32> for SlaveReq {
    fn into(self) -> u32 {
        self as u32
    }
}

impl Req for SlaveReq {
    fn is_valid(&self) -> bool {
        (*self > SlaveReq::NONE) && (*self < SlaveReq::MAX_CMD)
    }
}

/// Validate message format.
pub trait VhostUserMsgValidator {
    /// Validate message syntax only without validating message semantics such
    /// as protocol version number and dependency on feature flags etc.
    fn is_valid(&self) -> bool {
        true
    }
}

bitflags! {
    pub struct VhostUserHeaderFlag: u32 {
        // bits[0..2] is version number
        const REPLY = 0x4;
        const NEED_REPLY = 0x8;
        const ALL_FLAGS = 0xc;
        const RESERVED_BITS = !0xf;
    }
}

/// Common message header for vhost-user requests and replies.
#[allow(safe_packed_borrows)]
#[repr(packed)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct VhostUserMsgHeader<R: Req> {
    request: u32,
    flags: u32,
    size: u32,
    _r: PhantomData<R>,
}

impl<R: Req> VhostUserMsgHeader<R> {
    pub fn new(request: R, flags: u32, size: u32) -> Self {
        // Default to protocol version 1
        let fl = (flags & VhostUserHeaderFlag::ALL_FLAGS.bits()) | 0x1;
        VhostUserMsgHeader {
            request: request.into(),
            flags: fl,
            size,
            _r: PhantomData,
        }
    }

    pub fn get_code(&self) -> R {
        unsafe { std::mem::transmute_copy::<u32, R>(&self.request) }
    }

    pub fn set_code(&mut self, request: R) {
        self.request = request.into();
    }

    pub fn get_version(&self) -> u32 {
        self.flags & 0x3
    }

    pub fn set_version(&mut self, ver: u32) {
        self.flags &= !0x3;
        self.flags |= ver & 0x3;
    }

    pub fn is_reply(&self) -> bool {
        (self.flags & VhostUserHeaderFlag::REPLY.bits()) != 0
    }

    pub fn set_reply(&mut self, is_reply: bool) {
        if is_reply {
            self.flags |= VhostUserHeaderFlag::REPLY.bits();
        } else {
            self.flags &= !VhostUserHeaderFlag::REPLY.bits();
        }
    }

    pub fn is_need_reply(&self) -> bool {
        (self.flags & VhostUserHeaderFlag::NEED_REPLY.bits()) != 0
    }

    pub fn set_need_reply(&mut self, need_reply: bool) {
        if need_reply {
            self.flags |= VhostUserHeaderFlag::NEED_REPLY.bits();
        } else {
            self.flags &= !VhostUserHeaderFlag::NEED_REPLY.bits();
        }
    }

    pub fn get_size(&self) -> u32 {
        self.size
    }

    pub fn set_size(&mut self, size: u32) {
        self.size = size;
    }

    pub fn is_reply_for(&self, req: &VhostUserMsgHeader<R>) -> bool {
        self.is_reply() && !req.is_reply() && self.get_code() == req.get_code()
    }
}

impl<R: Req> Default for VhostUserMsgHeader<R> {
    fn default() -> Self {
        VhostUserMsgHeader {
            request: 0,
            flags: 0x1,
            size: 0,
            _r: PhantomData,
        }
    }
}

impl<T: Req> VhostUserMsgValidator for VhostUserMsgHeader<T> {
    fn is_valid(&self) -> bool {
        if !self.get_code().is_valid() {
            return false;
        } else if self.size as usize > MAX_MSG_SIZE {
            return false;
        } else if self.get_version() != 0x1 {
            return false;
        } else if (self.flags & VhostUserHeaderFlag::RESERVED_BITS.bits()) != 0 {
            return false;
        }
        true
    }
}

/// Transport specific flags in VirtIO feature set defined by vhost-user.
bitflags! {
    pub struct VhostUserVirtioFeatures: u64 {
        /// Whether protocol feature bits are available.
        const PROTOCOL_FEATURES = 0x40000000;
    }
}

/// Vhost-user protocol feature flags.
bitflags! {
    pub struct VhostUserProtocolFeatures: u64 {
        const MQ = 0x00000001;
        const LOG_SHMFD = 0x00000002;
        const RARP = 0x00000004;
        const REPLY_ACK = 0x00000008;
        const MTU = 0x00000010;
        const SLAVE_REQ = 0x00000020;
        const CROSS_ENDIAN = 0x00000040;
        const CRYPTO_SESSION = 0x00000080;
        const PAGEFAULT = 0x00000100;
        const CONFIG = 0x00000200;
        const SLAVE_SEND_FD = 0x00000400;
        const HOST_NOTIFIER = 0x00000800;
    }
}

#[repr(packed)]
#[derive(Default)]
pub struct VhostUserU64 {
    pub value: u64,
}

impl VhostUserU64 {
    pub fn new(value: u64) -> Self {
        VhostUserU64 { value }
    }
}

impl VhostUserMsgValidator for VhostUserU64 {}

#[repr(packed)]
#[derive(Default)]
pub struct VhostUserMemory {
    pub num_regions: u32,
    pub padding1: u32,
}

impl VhostUserMemory {
    pub fn new(cnt: u32) -> Self {
        VhostUserMemory {
            num_regions: cnt,
            padding1: 0,
        }
    }
}

impl VhostUserMsgValidator for VhostUserMemory {
    fn is_valid(&self) -> bool {
        if self.padding1 != 0 {
            return false;
        } else if self.num_regions == 0 || self.num_regions > MAX_ATTECHED_FD_ENTRIES as u32 {
            return false;
        }
        true
    }
}

#[repr(packed)]
#[derive(Default, Clone, Copy)]
pub struct VhostUserMemoryRegion {
    pub guest_phys_addr: u64,
    pub memory_size: u64,
    pub userspace_addr: u64,
    pub mmap_offset: u64,
}

impl VhostUserMemoryRegion {
    pub fn new(
        guest_phys_addr: u64,
        memory_size: u64,
        userspace_addr: u64,
        mmap_offset: u64,
    ) -> Self {
        VhostUserMemoryRegion {
            guest_phys_addr,
            memory_size,
            userspace_addr,
            mmap_offset,
        }
    }
}

impl VhostUserMsgValidator for VhostUserMemoryRegion {
    fn is_valid(&self) -> bool {
        if self.memory_size == 0
            || self.guest_phys_addr.checked_add(self.memory_size).is_none()
            || self.userspace_addr.checked_add(self.memory_size).is_none()
            || self.mmap_offset.checked_add(self.memory_size).is_none()
        {
            return false;
        }
        true
    }
}

pub type VhostUserMemoryPayload = Vec<VhostUserMemoryRegion>;

#[repr(packed)]
#[derive(Default)]
pub struct VhostUserVringState {
    pub index: u32,
    pub num: u32,
}

impl VhostUserVringState {
    pub fn new(index: u32, num: u32) -> Self {
        VhostUserVringState { index, num }
    }
}

impl VhostUserMsgValidator for VhostUserVringState {}

bitflags! {
    pub struct VhostUserVringAddrFlags: u32 {
        const VHOST_VRING_F_LOG = 0x1;
    }
}

#[repr(packed)]
#[derive(Default)]
pub struct VhostUserVringAddr {
    pub index: u32,
    pub flags: u32,
    pub descriptor: u64,
    pub used: u64,
    pub available: u64,
    pub log: u64,
}

impl VhostUserVringAddr {
    pub fn new(
        index: u32,
        flags: VhostUserVringAddrFlags,
        descriptor: u64,
        used: u64,
        available: u64,
        log: u64,
    ) -> Self {
        VhostUserVringAddr {
            index,
            flags: flags.bits(),
            descriptor,
            used,
            available,
            log,
        }
    }
}

impl VhostUserMsgValidator for VhostUserVringAddr {
    fn is_valid(&self) -> bool {
        if (self.flags & !VhostUserVringAddrFlags::all().bits()) != 0 {
            return false;
        } else if self.descriptor & 0xf != 0 {
            return false;
        } else if self.available & 0x1 != 0 {
            return false;
        } else if self.used & 0x3 != 0 {
            return false;
        }
        true
    }
}

bitflags! {
    pub struct VhostUserConfigFlags: u32 {
        const EMPTY = 0x0;
        const WRITABLE = 0x1;
        const LIVE_MIGRATION = 0x2;
    }
}

pub const VHOST_USER_MAX_CONFIG_SIZE: usize = 256;

#[repr(packed)]
#[derive(Default)]
pub struct VhostUserConfig {
    pub offset: u32,
    pub size: u32,
    pub flags: u32,
}

impl VhostUserConfig {
    pub fn new(offset: u32, size: u32, flags: VhostUserConfigFlags) -> Self {
        VhostUserConfig {
            offset,
            size,
            flags: flags.bits(),
        }
    }
}

impl VhostUserMsgValidator for VhostUserConfig {
    fn is_valid(&self) -> bool {
        if (self.flags & !VhostUserConfigFlags::all().bits()) != 0 {
            return false;
        } else if self.size > VHOST_USER_MAX_CONFIG_SIZE as u32 {
            return false;
        }
        true
    }
}

pub type VhostUserConfigPayload = Vec<u8>;

/*
 * TODO: support dirty log, live migration and IOTLB operations.
#[repr(packed)]
pub struct VhostUserVringArea {
    pub index: u32,
    pub flags: u32,
    pub size: u64,
    pub offset: u64,
}

#[repr(packed)]
pub struct VhostUserLog {
    pub size: u64,
    pub offset: u64,
}

#[repr(packed)]
pub struct VhostUserIotlb {
    pub iova: u64,
    pub size: u64,
    pub user_addr: u64,
    pub permission: u8,
    pub optype: u8,
}
*/

bitflags! {
    #[derive(Default)]
    pub struct VhostUserFSSlaveMsgFlags: u64 {
        const EMPTY = 0x0;
        const MAP_R = 0x1;
        const MAP_W = 0x2;
    }
}

const VHOST_USER_FS_SLAVE_ENTRIES: usize = 8;

#[repr(packed)]
#[derive(Default)]
pub struct VhostUserFSSlaveMsg {
    pub fd_offset: [u64; VHOST_USER_FS_SLAVE_ENTRIES],
    pub cache_offset: [u64; VHOST_USER_FS_SLAVE_ENTRIES],
    pub len: [u64; VHOST_USER_FS_SLAVE_ENTRIES],
    pub flags: [VhostUserFSSlaveMsgFlags; VHOST_USER_FS_SLAVE_ENTRIES],
}

impl VhostUserMsgValidator for VhostUserFSSlaveMsg {
    fn is_valid(&self) -> bool {
        for i in 0..VHOST_USER_FS_SLAVE_ENTRIES {
            if ({ self.flags[i] }.bits() & !VhostUserFSSlaveMsgFlags::all().bits()) != 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn check_request_code() {
        let code = MasterReq::NOOP;
        assert!(!code.is_valid());
        let code = MasterReq::MAX_CMD;
        assert!(!code.is_valid());
        let code = MasterReq::GET_FEATURES;
        assert!(code.is_valid());
    }

    #[test]
    fn msg_header_ops() {
        let mut hdr = VhostUserMsgHeader::new(MasterReq::GET_FEATURES, 0, 0x100);
        assert_eq!(hdr.get_code(), MasterReq::GET_FEATURES);
        hdr.set_code(MasterReq::SET_FEATURES);
        assert_eq!(hdr.get_code(), MasterReq::SET_FEATURES);

        assert_eq!(hdr.get_version(), 0x1);

        assert_eq!(hdr.is_reply(), false);
        hdr.set_reply(true);
        assert_eq!(hdr.is_reply(), true);
        hdr.set_reply(false);

        assert_eq!(hdr.is_need_reply(), false);
        hdr.set_need_reply(true);
        assert_eq!(hdr.is_need_reply(), true);
        hdr.set_need_reply(false);

        assert_eq!(hdr.get_size(), 0x100);
        hdr.set_size(0x200);
        assert_eq!(hdr.get_size(), 0x200);

        assert_eq!(hdr.is_need_reply(), false);
        assert_eq!(hdr.is_reply(), false);
        assert_eq!(hdr.get_version(), 0x1);

        // Check message length
        assert!(hdr.is_valid());
        hdr.set_size(0x2000);
        assert!(!hdr.is_valid());
        hdr.set_size(0x100);
        assert_eq!(hdr.get_size(), 0x100);
        assert!(hdr.is_valid());
        hdr.set_size((MAX_MSG_SIZE - mem::size_of::<VhostUserMsgHeader<MasterReq>>()) as u32);
        assert!(hdr.is_valid());
        hdr.set_size(0x0);
        assert!(hdr.is_valid());

        // Check version
        hdr.set_version(0x0);
        assert!(!hdr.is_valid());
        hdr.set_version(0x2);
        assert!(!hdr.is_valid());
        hdr.set_version(0x1);
        assert!(hdr.is_valid());
    }

    #[test]
    fn check_user_memory() {
        let mut msg = VhostUserMemory::new(1);
        assert!(msg.is_valid());
        msg.num_regions = MAX_ATTECHED_FD_ENTRIES as u32;
        assert!(msg.is_valid());

        msg.num_regions += 1;
        assert!(!msg.is_valid());
        msg.num_regions = 0xFFFFFFFF;
        assert!(!msg.is_valid());
        msg.num_regions = MAX_ATTECHED_FD_ENTRIES as u32;
        msg.padding1 = 1;
        assert!(!msg.is_valid());
    }

    #[test]
    fn check_user_memory_region() {
        let mut msg = VhostUserMemoryRegion {
            guest_phys_addr: 0,
            memory_size: 0x1000,
            userspace_addr: 0,
            mmap_offset: 0,
        };
        assert!(msg.is_valid());
        msg.guest_phys_addr = 0xFFFFFFFFFFFFEFFF;
        assert!(msg.is_valid());
        msg.guest_phys_addr = 0xFFFFFFFFFFFFF000;
        assert!(!msg.is_valid());
        msg.guest_phys_addr = 0xFFFFFFFFFFFF0000;
        msg.memory_size = 0;
        assert!(!msg.is_valid());
    }

    #[test]
    fn check_user_vring_addr() {
        let mut msg =
            VhostUserVringAddr::new(0, VhostUserVringAddrFlags::all(), 0x0, 0x0, 0x0, 0x0);
        assert!(msg.is_valid());

        msg.descriptor = 1;
        assert!(!msg.is_valid());
        msg.descriptor = 0;

        msg.available = 1;
        assert!(!msg.is_valid());
        msg.available = 0;

        msg.used = 1;
        assert!(!msg.is_valid());
        msg.used = 0;

        msg.flags |= 0x80000000;
        assert!(!msg.is_valid());
        msg.flags &= !0x80000000;
    }

    #[test]
    fn check_user_config_msg() {
        let mut msg = VhostUserConfig::new(
            VHOST_USER_CONFIG_OFFSET,
            VHOST_USER_CONFIG_SIZE - VHOST_USER_CONFIG_OFFSET,
            VhostUserConfigFlags::EMPTY,
        );

        assert!(msg.is_valid());
        msg.size = 0;
        assert!(!msg.is_valid());
        msg.size = 1;
        assert!(msg.is_valid());
        msg.offset = 0;
        assert!(!msg.is_valid());
        msg.offset = VHOST_USER_CONFIG_SIZE;
        assert!(!msg.is_valid());
        msg.offset = VHOST_USER_CONFIG_SIZE - 1;
        assert!(msg.is_valid());
        msg.size = 2;
        assert!(!msg.is_valid());
        msg.size = 1;
        msg.flags |= VhostUserConfigFlags::WRITABLE.bits();
        assert!(msg.is_valid());
        msg.flags |= 0x4;
        assert!(!msg.is_valid());
    }
}
