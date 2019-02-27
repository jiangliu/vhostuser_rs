// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::message::*;
use super::*;
use std::os::unix::io::RawFd;

pub const MAX_VRING_NUM: usize = 2;
pub const VIRTIO_FEATURES: u64 = 0x40000003;

#[derive(Default)]
pub struct DummySlave {
    pub owned: bool,
    pub features_acked: bool,
    pub acked_features: u64,
    pub acked_protocol_features: u64,
    pub vring_num: usize,
    pub call_fd: [Option<RawFd>; MAX_VRING_NUM],
    pub kick_fd: [Option<RawFd>; MAX_VRING_NUM],
    pub err_fd: [Option<RawFd>; MAX_VRING_NUM],
    pub vring_started: [bool; MAX_VRING_NUM],
    pub vring_enabled: [bool; MAX_VRING_NUM],
}

impl DummySlave {
    pub fn new() -> Self {
        DummySlave {
            vring_num: 1,
            ..Default::default()
        }
    }
}

impl VhostUserSlave for DummySlave {
    fn set_owner(&mut self) -> Result<()> {
        if self.owned {
            return Err(Error::InvalidOperation);
        }
        self.owned = true;
        Ok(())
    }

    fn reset_owner(&mut self) -> Result<()> {
        self.owned = false;
        self.features_acked = false;
        self.acked_features = 0;
        self.acked_protocol_features = 0;
        Ok(())
    }

    fn get_features(&mut self) -> Result<u64> {
        Ok(VIRTIO_FEATURES)
    }

    fn set_features(&mut self, features: u64) -> Result<()> {
        if !self.owned {
            return Err(Error::InvalidOperation);
        } else if self.features_acked {
            return Err(Error::InvalidOperation);
        } else if (features & !VIRTIO_FEATURES) != 0 {
            return Err(Error::InvalidParam);
        }

        self.acked_features = features;
        self.features_acked = true;

        // If VHOST_USER_F_PROTOCOL_FEATURES has not been negotiated,
        // the ring is initialized in an enabled state.
        // If VHOST_USER_F_PROTOCOL_FEATURES has been negotiated,
        // the ring is initialized in a disabled state. Client must not
        // pass data to/from the backend until ring is enabled by
        // VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has
        // been disabled by VHOST_USER_SET_VRING_ENABLE with parameter 0.
        let vring_enabled =
            self.acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0;
        for enabled in &mut self.vring_enabled {
            *enabled = vring_enabled;
        }

        Ok(())
    }

    fn get_protocol_features(&mut self) -> Result<VhostUserProtocolFeatures> {
        Ok(VhostUserProtocolFeatures::all())
    }

    fn set_protocol_features(&mut self, features: u64) -> Result<()> {
        // Note: slave that reported VHOST_USER_F_PROTOCOL_FEATURES must
        // support this message even before VHOST_USER_SET_FEATURES was
        // called.
        // What happens if the master calls set_features() with
        // VHOST_USER_F_PROTOCOL_FEATURES cleared after calling this
        // interface?
        self.acked_protocol_features = features;
        Ok(())
    }

    fn set_mem_table(&mut self, _ctx: &[VhostUserMemoryRegion], _fds: &[RawFd]) -> Result<()> {
        // TODO
        Ok(())
    }

    fn get_queue_num(&mut self) -> Result<u64> {
        Ok(MAX_VRING_NUM as u64)
    }

    fn set_vring_num(&mut self, _index: u32, _num: u32) -> Result<()> {
        // TODO
        Ok(())
    }

    fn set_vring_addr(
        &mut self,
        _index: u32,
        _flags: VhostUserVringAddrFlags,
        _descriptor: u64,
        _used: u64,
        _available: u64,
        _log: u64,
    ) -> Result<()> {
        // TODO
        Ok(())
    }

    fn set_vring_base(&mut self, _index: u32, _base: u32) -> Result<()> {
        // TODO
        Ok(())
    }

    fn get_vring_base(&mut self, index: u32) -> Result<VhostUserVringState> {
        Ok(VhostUserVringState::new(index, 0))
    }

    fn set_vring_kick(&mut self, index: u8, fd: Option<RawFd>) -> Result<()> {
        if index as usize >= MAX_VRING_NUM || index as usize > self.vring_num {
            return Err(Error::InvalidParam);
        }
        if self.kick_fd[index as usize].is_some() {
            // Close file descriptor set by previous operations.
            let _ = nix::unistd::close(self.kick_fd[index as usize].unwrap());
        }
        self.kick_fd[index as usize] = fd;

        // Quotation from vhost-user spec:
        // Client must start ring upon receiving a kick (that is, detecting
        // that file descriptor is readable) on the descriptor specified by
        // VHOST_USER_SET_VRING_KICK, and stop ring upon receiving
        // VHOST_USER_GET_VRING_BASE.
        //
        // So we should add fd to event monitor(select, poll, epoll) here.
        self.vring_started[index as usize] = true;
        Ok(())
    }

    fn set_vring_call(&mut self, index: u8, fd: Option<RawFd>) -> Result<()> {
        if index as usize >= MAX_VRING_NUM || index as usize > self.vring_num {
            return Err(Error::InvalidParam);
        }
        if self.call_fd[index as usize].is_some() {
            // Close file descriptor set by previous operations.
            let _ = nix::unistd::close(self.call_fd[index as usize].unwrap());
        }
        self.call_fd[index as usize] = fd;
        Ok(())
    }

    fn set_vring_err(&mut self, index: u8, fd: Option<RawFd>) -> Result<()> {
        if index as usize >= MAX_VRING_NUM || index as usize > self.vring_num {
            return Err(Error::InvalidParam);
        }
        if self.err_fd[index as usize].is_some() {
            // Close file descriptor set by previous operations.
            let _ = nix::unistd::close(self.err_fd[index as usize].unwrap());
        }
        self.err_fd[index as usize] = fd;
        Ok(())
    }

    /*
            Client must start ring upon receiving a kick (that is, detecting that file
    descriptor is readable) on the descriptor specified by
    VHOST_USER_SET_VRING_KICK, and stop ring upon receiving
    VHOST_USER_GET_VRING_BASE.

            */

    fn set_vring_enable(&mut self, index: u32, enable: bool) -> Result<()> {
        // This request should be handled only when VHOST_USER_F_PROTOCOL_FEATURES
        // has been negotiated.
        if self.acked_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() == 0 {
            return Err(Error::InvalidOperation);
        } else if index as usize >= MAX_VRING_NUM || index as usize > self.vring_num {
            return Err(Error::InvalidParam);
        }

        // Slave must not pass data to/from the backend until ring is
        // enabled by VHOST_USER_SET_VRING_ENABLE with parameter 1,
        // or after it has been disabled by VHOST_USER_SET_VRING_ENABLE
        // with parameter 0.
        self.vring_enabled[index as usize] = enable;
        Ok(())
    }

    fn get_config(
        &mut self,
        offset: u32,
        size: u32,
        _flags: VhostUserConfigFlags,
    ) -> Result<Vec<u8>> {
        if self.acked_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
            return Err(Error::InvalidOperation);
        } else if offset < VHOST_USER_CONFIG_OFFSET
            || offset >= VHOST_USER_CONFIG_SIZE
            || size > VHOST_USER_CONFIG_SIZE - VHOST_USER_CONFIG_OFFSET
            || size + offset > VHOST_USER_CONFIG_SIZE
        {
            return Err(Error::InvalidParam);
        }
        Ok(vec![0xa5; size as usize])
    }

    fn set_config(&mut self, offset: u32, buf: &[u8], _flags: VhostUserConfigFlags) -> Result<()> {
        let size = buf.len() as u32;
        if self.acked_features & VhostUserProtocolFeatures::CONFIG.bits() == 0 {
            return Err(Error::InvalidOperation);
        } else if offset < VHOST_USER_CONFIG_OFFSET
            || offset >= VHOST_USER_CONFIG_SIZE
            || size > VHOST_USER_CONFIG_SIZE - VHOST_USER_CONFIG_OFFSET
            || size + offset > VHOST_USER_CONFIG_SIZE
        {
            return Err(Error::InvalidParam);
        }
        Ok(())
    }
}
