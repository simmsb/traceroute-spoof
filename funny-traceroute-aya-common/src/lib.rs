#![no_std]

#[cfg(feature = "userspace")]
use aya::Pod;

#[repr(packed)]
#[derive(Clone, Copy)]
pub struct MyAddr(pub [u8; 16]);

#[cfg(feature = "userspace")]
unsafe impl Pod for MyAddr {}

#[repr(packed)]
#[derive(Clone, Copy)]
pub struct ResponseKey {
    pub idx: u8,
    pub ttl: u8,
}

#[cfg(feature = "userspace")]
unsafe impl Pod for ResponseKey {}
