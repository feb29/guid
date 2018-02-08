#![feature(getpid, integer_atomics)]

extern crate byteorder;
extern crate crc;
extern crate crypto;
extern crate hostname;
#[macro_use]
extern crate lazy_static;
extern crate rand;

pub mod xid;
// pub mod ksuid;
// pub mod ulid;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Return duration from epoch.
fn now() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}
