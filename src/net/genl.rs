// SPDX-License-Identifier: MIT
// Copyright (C) 2025-2026 Shane Fagan

//! Plain generic netlink with no extra dependencies: enough to talk to
//! nl80211 (Wi-Fi power save) and netdev (receive queues).
//!
//! A generic netlink request is an `nlmsghdr`, a `genlmsghdr` and a list
//! of attributes, each 4-byte aligned. Family ids aren't fixed, so a
//! caller first asks the generic netlink controller for one by name.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NETLINK_GENERIC: i32 = 16;
pub(super) const GENL_ID_CTRL: u16 = 16;
pub(super) const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

pub const NLM_F_REQUEST: u16 = 1;
pub const NLM_F_ACK: u16 = 4;
/// NLM_F_ROOT | NLM_F_MATCH: list every object the filter matches.
pub const NLM_F_DUMP: u16 = 0x300;
pub(super) const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_HDRLEN: usize = 16;
const GENL_HDRLEN: usize = 4;
const NLA_HDRLEN: usize = 4;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// One generic netlink request: nlmsghdr + genlmsghdr + attributes.
pub fn encode(family: u16, flags: u16, seq: u32, cmd: u8, attrs: &[(u16, &[u8])]) -> Vec<u8> {
    let mut m = vec![0u8; NLMSG_HDRLEN];
    m.extend_from_slice(&[cmd, 1, 0, 0]); // genlmsghdr: cmd, version, reserved
    for (ty, payload) in attrs {
        let len = NLA_HDRLEN + payload.len();
        m.extend_from_slice(&(len as u16).to_ne_bytes());
        m.extend_from_slice(&ty.to_ne_bytes());
        m.extend_from_slice(payload);
        m.resize(align4(m.len()), 0);
    }
    let total = m.len() as u32;
    m[0..4].copy_from_slice(&total.to_ne_bytes());
    m[4..6].copy_from_slice(&family.to_ne_bytes());
    m[6..8].copy_from_slice(&(flags | NLM_F_REQUEST).to_ne_bytes());
    m[8..12].copy_from_slice(&seq.to_ne_bytes());
    m
}

/// Parsed reply: either an error/ack code or a genl message's attributes.
#[derive(Debug, PartialEq, Eq)]
pub enum Reply {
    /// NLMSG_ERROR: 0 is an ACK, otherwise -errno
    Ack(i32),
    Attrs(Vec<(u16, Vec<u8>)>),
    Done,
}

pub fn decode(buf: &[u8]) -> Vec<Reply> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + NLMSG_HDRLEN <= buf.len() {
        let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap());
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            break;
        }
        let body = &buf[off + NLMSG_HDRLEN..off + len];
        match ty {
            NLMSG_ERROR if body.len() >= 4 => {
                out.push(Reply::Ack(i32::from_ne_bytes(
                    body[0..4].try_into().unwrap(),
                )));
            }
            NLMSG_DONE => out.push(Reply::Done),
            _ if body.len() >= GENL_HDRLEN => {
                let mut attrs = Vec::new();
                let mut a = GENL_HDRLEN;
                while a + NLA_HDRLEN <= body.len() {
                    let alen = u16::from_ne_bytes(body[a..a + 2].try_into().unwrap()) as usize;
                    let aty = u16::from_ne_bytes(body[a + 2..a + 4].try_into().unwrap()) & 0x3fff;
                    if alen < NLA_HDRLEN || a + alen > body.len() {
                        break;
                    }
                    attrs.push((aty, body[a + NLA_HDRLEN..a + alen].to_vec()));
                    a += align4(alen);
                }
                out.push(Reply::Attrs(attrs));
            }
            _ => {}
        }
        off += align4(len);
    }
    out
}

pub struct Genl {
    fd: OwnedFd,
    seq: u32,
}

impl Genl {
    pub fn open() -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // 1s receive timeout so a confused kernel can never hang the daemon
        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast(),
                size_of::<libc::timeval>() as u32,
            );
        }
        Ok(Self { fd, seq: 1 })
    }

    /// Send one request and collect its replies. A dump (`NLM_F_DUMP`) can
    /// span several reads; it ends with NLMSG_DONE.
    pub fn call(
        &mut self,
        family: u16,
        flags: u16,
        cmd: u8,
        attrs: &[(u16, &[u8])],
    ) -> io::Result<Vec<Reply>> {
        self.seq += 1;
        let msg = encode(family, flags, self.seq, cmd, attrs);
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        let n = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                msg.as_ptr().cast(),
                msg.len(),
                0,
                (&sa as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        let mut replies = Vec::new();
        // family replies list every op; 64 KiB is far more than one read needs
        let mut buf = vec![0u8; 65536];
        loop {
            let n =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let batch = decode(&buf[..n as usize]);
            let done = batch.is_empty()
                || batch
                    .iter()
                    .any(|r| matches!(r, Reply::Done | Reply::Ack(_)));
            replies.extend(batch);
            if !dump || done {
                break;
            }
        }
        if let Some(Reply::Ack(e)) = replies
            .iter()
            .find(|r| matches!(r, Reply::Ack(e) if *e != 0))
        {
            return Err(io::Error::from_raw_os_error(-e));
        }
        Ok(replies)
    }

    pub fn family(&mut self, name: &str) -> io::Result<u16> {
        let mut n = name.as_bytes().to_vec();
        n.push(0);
        let replies = self.call(
            GENL_ID_CTRL,
            0,
            CTRL_CMD_GETFAMILY,
            &[(CTRL_ATTR_FAMILY_NAME, &n)],
        )?;
        find_attr(&replies, CTRL_ATTR_FAMILY_ID)
            .filter(|v| v.len() >= 2)
            .map(|v| u16::from_ne_bytes([v[0], v[1]]))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("{name} family id missing"))
            })
    }
}

/// The first attribute of type `ty` in any reply.
pub fn find_attr(replies: &[Reply], ty: u16) -> Option<Vec<u8>> {
    replies.iter().find_map(|r| match r {
        Reply::Attrs(a) => a.iter().find(|(t, _)| *t == ty).map(|(_, v)| v.clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_string_attributes() {
        let m = encode(GENL_ID_CTRL, 0, 1, CTRL_CMD_GETFAMILY, &[(2, b"nl80211\0")]);
        // attr len 12 (4 + 8), already aligned
        assert_eq!(m.len(), 16 + 4 + 12);
        let m = encode(
            GENL_ID_CTRL,
            0,
            1,
            CTRL_CMD_GETFAMILY,
            &[(2, b"abc\0x"), (1, &[1, 0])],
        );
        assert_eq!(u16::from_ne_bytes(m[20..22].try_into().unwrap()), 9);
        assert_eq!(&m[29..32], &[0, 0, 0]); // padding before the next attribute
        assert_eq!(u16::from_ne_bytes(m[34..36].try_into().unwrap()), 1);
    }

    #[test]
    fn decodes_replies() {
        // a reply carrying attribute 93 = 1, then an ACK
        let mut reply = encode(0x1c, 0, 2, 62, &[(93, &1u32.to_ne_bytes())]);
        let mut ack = vec![0u8; 16 + 4 + 16];
        ack[0..4].copy_from_slice(&36u32.to_ne_bytes());
        ack[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        reply.extend(ack);
        let r = decode(&reply);
        assert_eq!(r.len(), 2);
        assert_eq!(find_attr(&r, 93), Some(1u32.to_ne_bytes().to_vec()));
        assert_eq!(r[1], Reply::Ack(0));
        // error ack (-EOPNOTSUPP)
        let mut e = vec![0u8; 36];
        e[0..4].copy_from_slice(&36u32.to_ne_bytes());
        e[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        e[16..20].copy_from_slice(&(-95i32).to_ne_bytes());
        assert_eq!(decode(&e), vec![Reply::Ack(-95)]);
        // truncated garbage doesn't panic
        assert!(decode(&reply[..10]).is_empty());
    }

    /// Needs a kernel; the controller family always exists.
    #[test]
    fn resolves_a_real_genl_family() {
        let Ok(mut g) = Genl::open() else { return };
        assert_eq!(g.family("nlctrl").unwrap(), GENL_ID_CTRL);
        assert!(g.family("no-such-family-bpfrag").is_err());
    }
}
