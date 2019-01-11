// Copyright (C) 2019 Alibaba Cloud Computing. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use nix::sys::socket::{recvmsg, sendmsg, CmsgSpace, ControlMessage, MsgFlags};
use nix::sys::uio::IoVec;
use std::io::ErrorKind;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};

use super::{Error, Result};

/// Unix domain socket listener for vhost-user slaves.
pub struct Listener {
    fd: UnixListener,
}

impl Listener {
    /// Create a unix domain socket listener.
    pub fn new(path: &str) -> Result<Self> {
        let fd = UnixListener::bind(path).map_err(|e| Error::SocketError(e))?;
        fd.set_nonblocking(true)
            .map_err(|e| Error::SocketError(e))?;
        Ok(Listener { fd })
    }

    /// Accept an incoming connection from the master.
    pub fn accept(&self) -> Result<Option<Endpoint>> {
        match self.fd.accept() {
            Ok((socket, _addr)) => Ok(Some(Endpoint::new_slave(socket))),
            Err(e) => {
                // No incoming connection available.
                if e.kind() == ErrorKind::WouldBlock {
                    return Ok(None);
                } else {
                    Err(Error::SocketError(e))
                }
            }
        }
    }
}

impl AsRawFd for Listener {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Unix domain socket endpoint for vhostuser connection.
pub struct Endpoint {
    fd: UnixStream,
    master: bool,
}

impl Endpoint {
    /// Create a master endpoint for a vhost-user connection.
    pub fn new_master(path: &str) -> Result<Self> {
        let fd = UnixStream::connect(path).map_err(|e| Error::ConnectFail(e))?;
        Ok(Endpoint { fd, master: true })
    }

    /// Create a slave endpoint for a vhost-user connection.
    pub fn new_slave(fd: UnixStream) -> Self {
        Endpoint { fd, master: false }
    }

    /// Check whether the endpoint is in master mode.
    pub fn is_master(&self) -> bool {
        self.master
    }

    /// Sends bytes from scatter-gather vectors over the socket with optional
    /// attached file descriptors.
    pub fn send_iovec(&mut self, iov: &[IoVec<&[u8]>], fds: Option<&[RawFd]>) -> Result<usize> {
        if let Some(rfds) = fds {
            sendmsg(
                self.as_raw_fd(),
                iov,
                &[ControlMessage::ScmRights(rfds)],
                MsgFlags::empty(),
                None,
            )
            .map_err(|e| e.into())
        } else {
            sendmsg(self.as_raw_fd(), iov, &[], MsgFlags::empty(), None).map_err(|e| e.into())
        }
    }

    /// Sends bytes from a slice over the socket with optional attached file
    /// descriptors.
    pub fn send_slice(&mut self, data: &[u8], fds: Option<&[RawFd]>) -> Result<usize> {
        let iov = [IoVec::from_slice(data)];
        self.send_iovec(&iov[..], fds)
    }

    /// Reads bytes from the socket into the given scatter/gather array with
    /// optional attached file descriptors. Received file descriptors are set
    /// close-on-exec.
    ///
    /// The underline communication channel is a Unix domain socket in STREAM
    /// mode. It's a little tricky to pass file descriptors through such a
    /// communication channel. Let's assume that a sender sending a message
    /// with some file descriptors attached. To successfully receive those
    /// attached file descriptors, the receiver must obey following rules:
    ///   1) file descriptors are attached to a message.
    ///   2) message(packet) boundaries must be respected on the receive side.
    ///   In other words, recvmsg() operations must not cross the packet
    ///   boundary, otherwise the attached file descriptors will get lost.
    pub fn recv_into_iovec<F: Default + AsMut<[RawFd]>>(
        &mut self,
        iov: &[IoVec<&mut [u8]>],
    ) -> Result<(usize, Option<Vec<RawFd>>)> {
        let mut cmsgspace: CmsgSpace<F> = CmsgSpace::new();
        let msg = recvmsg(
            self.as_raw_fd(),
            iov,
            Some(&mut cmsgspace),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )?;

        let mut rfds = None;
        for cmsg in msg.cmsgs() {
            if let ControlMessage::ScmRights(fds) = cmsg {
                if fds.len() >= 1 {
                    let mut fd_arr = Vec::with_capacity(fds.len());
                    fd_arr.extend_from_slice(fds);
                    rfds = Some(fd_arr);
                }
            }
        }

        Ok((msg.bytes, rfds))
    }

    /// Reads bytes from the socket into a new buffer with optional attached
    /// file descriptors. Received file descriptors are set close-on-exec.
    pub fn recv_into_buf<F: Default + AsMut<[RawFd]>>(
        &mut self,
        buf_size: usize,
    ) -> Result<(usize, Vec<u8>, Option<Vec<RawFd>>)> {
        let mut buf = vec![0u8; buf_size];
        let (bytes, rfds) = {
            let iov = [IoVec::from_mut_slice(&mut buf[..])];
            self.recv_into_iovec::<F>(&iov)?
        };
        Ok((bytes, buf, rfds))
    }
}

impl AsRawFd for Endpoint {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    extern crate tempfile;

    use self::tempfile::tempfile;
    use super::*;
    use libc;
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::io::FromRawFd;

    const UNIX_SOCKET_LISTENER: &'static str = "/tmp/vhost_user_test_rust_listener";
    const UNIX_SOCKET_CONNECTION: &'static str = "/tmp/vhost_user_test_rust_connection";
    const UNIX_SOCKET_DATA: &'static str = "/tmp/vhost_user_test_rust_data";
    const UNIX_SOCKET_FD: &'static str = "/tmp/vhost_user_test_rust_fd";

    fn remove_temp_file(path: &str) {
        let _ = fs::remove_file(path);
    }

    #[test]
    fn create_listener() {
        remove_temp_file(UNIX_SOCKET_LISTENER);
        let _ = Listener::new(UNIX_SOCKET_LISTENER).unwrap();
    }

    #[test]
    fn accept_connection() {
        remove_temp_file(UNIX_SOCKET_CONNECTION);
        let listener = Listener::new(UNIX_SOCKET_CONNECTION).unwrap();

        // accept on a fd without incoming connection
        let conn = listener.accept().unwrap();
        assert!(conn.is_none());

        // accept on a closed fd
        unsafe {
            libc::close(listener.as_raw_fd());
        }
        let conn2 = listener.accept();
        assert!(conn2.is_err());
    }

    #[test]
    fn send_data() {
        remove_temp_file(UNIX_SOCKET_DATA);
        let listener = Listener::new(UNIX_SOCKET_DATA).unwrap();
        let mut master = Endpoint::new_master(UNIX_SOCKET_DATA).unwrap();
        let mut slave = listener.accept().unwrap().unwrap();

        let buf1 = vec![0x1, 0x2, 0x3, 0x4];
        let mut len = master.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let (bytes, buf2, _) = slave.recv_into_buf::<[RawFd; 0]>(0x1000).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..bytes]);

        len = master.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let (bytes, buf2, _) = slave.recv_into_buf::<[RawFd; 0]>(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        let (bytes, buf2, _) = slave.recv_into_buf::<[RawFd; 0]>(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
    }

    #[test]
    fn send_fd() {
        remove_temp_file(UNIX_SOCKET_FD);
        let listener = Listener::new(UNIX_SOCKET_FD).unwrap();
        let mut master = Endpoint::new_master(UNIX_SOCKET_FD).unwrap();
        let mut slave = listener.accept().unwrap().unwrap();

        let mut fd = tempfile().unwrap();
        write!(fd, "test").unwrap();

        // Normal case for sending/receiving file descriptors
        let buf1 = vec![0x1, 0x2, 0x3, 0x4];
        let len = master
            .send_slice(&buf1[..], Some(&[fd.as_raw_fd()]))
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, rfds) = slave.recv_into_buf::<[RawFd; 2]>(4).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..]);
        assert!(rfds.is_some());
        let fds = rfds.unwrap();
        {
            assert_eq!(fds.len(), 1);
            let mut file = unsafe { File::from_raw_fd(fds[0]) };
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }

        // Following communication pattern should work:
        // Sending side: data(header, body) with fds
        // Receiving side: data(header) with fds, data(body)
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, rfds) = slave.recv_into_buf::<[RawFd; 3]>(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        assert!(rfds.is_some());
        let fds = rfds.unwrap();
        {
            assert_eq!(fds.len(), 3);
            let mut file = unsafe { File::from_raw_fd(fds[1]) };
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }
        let (bytes, buf2, rfds) = slave.recv_into_buf::<[RawFd; 2]>(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(rfds.is_none());

        // Following communication pattern should not work:
        // Sending side: data(header, body) with fds
        // Receiving side: data(header), data(body) with fds
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, rfds) = slave.recv_into_buf::<[RawFd; 0]>(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        assert!(rfds.is_none());
        let (bytes, buf2, rfds) = slave.recv_into_buf::<[RawFd; 3]>(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(rfds.is_none());

        // Following communication pattern should work:
        // Sending side: data, data with fds
        // Receiving side: data, data with fds
        let len = master.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, buf2, rfds) = slave.recv_into_buf::<[RawFd; 0]>(0x4).unwrap();
        assert_eq!(bytes, 4);
        assert_eq!(&buf1[..], &buf2[..]);
        assert!(rfds.is_none());

        let (bytes, buf2, rfds) = slave.recv_into_buf::<[RawFd; 10]>(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[..2], &buf2[..]);
        assert!(rfds.is_some());
        let fds = rfds.unwrap();
        {
            assert_eq!(fds.len(), 3);
            let mut file = unsafe { File::from_raw_fd(fds[1]) };
            let mut content = String::new();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_to_string(&mut content).unwrap();
            assert_eq!(content, "test");
        }
        let (bytes, buf2, rfds) = slave.recv_into_buf::<[RawFd; 2]>(0x2).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(&buf1[2..], &buf2[..]);
        assert!(rfds.is_none());

        // Following communication pattern should not work:
        // Sending side: data1, data2 with fds
        // Receiving side: data + partial of data2, left of data2 with fds
        let len = master.send_slice(&buf1[..], None).unwrap();
        assert_eq!(len, 4);
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, _, rfds) = slave.recv_into_buf::<[RawFd; 0]>(0x5).unwrap();
        assert_eq!(bytes, 5);
        assert!(rfds.is_none());

        let (bytes, _, rfds) = slave.recv_into_buf::<[RawFd; 3]>(0x4).unwrap();
        assert_eq!(bytes, 3);
        assert!(rfds.is_none());

        // If the target fd array is too small, extra file descriptors will get lost.
        let len = master
            .send_slice(
                &buf1[..],
                Some(&[fd.as_raw_fd(), fd.as_raw_fd(), fd.as_raw_fd()]),
            )
            .unwrap();
        assert_eq!(len, 4);

        let (bytes, _, rfds) = slave.recv_into_buf::<[RawFd; 2]>(0x4).unwrap();
        assert_eq!(bytes, 4);
        assert!(rfds.is_some());
    }
}
