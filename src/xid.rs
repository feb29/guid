use std::{fmt, fs, io, process};
use std::sync::atomic::{AtomicU32, Ordering};
use byteorder::{BigEndian, WriteBytesExt};
use crc::crc32;
use crypto::digest::Digest;
use crypto::md5;
use hostname;
use rand::{thread_rng, Rng};

#[derive(Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Xid {
    bytes: [u8; SIZEOF_RAW],
}

const SIZEOF_RAW: usize = 12;
const SIZEOF_STR: usize = 20;

lazy_static! {
    static ref ENCODING: [u8; 32] = {
        let mut buf = [0; 32];
        let text = b"0123456789abcdefghijklmnopqrstuv";
        (&mut buf[..]).clone_from_slice(text);
        buf
    };

    static ref DECODING: [u8; 256] = {
        let mut buf = [0; 256];
        for p in &mut buf[..] {
            *p = 0xFF;
        }
        for i in 0..ENCODING.len() {
            buf[ENCODING[i] as usize] = i as u8;
        }
        buf
    };
}

lazy_static! {
    static ref PROCESS: u32 = {
        let getpid = || {
            let pid = process::id();
            if pid == 1 {
                if let Ok(mut file) = fs::File::open("/proc/1/cpuset") {
                    let mut buf = Vec::new();
                    io::copy(&mut file, &mut buf).unwrap();
                    if buf.len() > 1 {
                        return crc32::checksum_ieee(&buf[..]);
                    }
                }
            }
            pid
        };
        getpid()
    };

    static ref MACHINE: [u8; 3] = {
        let getmid = || {
            if let Some(host) = hostname::get_hostname() {
                let host = host.into_bytes();
                let mut hw = md5::Md5::new();
                let mut id = vec![0; hw.output_bytes()];
                hw.input(&host[..]);
                hw.result(&mut id);
                id
            } else {
                let mut id = vec![0u8; 3];
                thread_rng().fill_bytes(&mut id);
                id
            }
        };

        let mut id = [0; 3];
        id[..3].clone_from_slice(&getmid()[..3]);
        id
    };

    static ref COUNTER: AtomicU32 = {
        let mut buf = [0u8; 3];
        thread_rng().fill_bytes(&mut buf);
        AtomicU32::new((u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]))
    };
}

impl Default for Xid {
    fn default() -> Self {
        let bytes = [0; SIZEOF_RAW];
        Xid { bytes }
    }
}

impl fmt::Debug for Xid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.bytes.fmt(f)
    }
}
impl fmt::Display for Xid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::str::from_utf8_unchecked;
        let mut buf = [0; SIZEOF_STR];
        self.encode(&mut buf);
        f.write_str(unsafe { from_utf8_unchecked(&buf) })
    }
}

impl<T> From<T> for Xid
where
    T: AsRef<[u8]>,
{
    fn from(data: T) -> Self {
        let mut bytes = [0; SIZEOF_RAW];
        bytes[..SIZEOF_RAW].clone_from_slice(&data.as_ref()[..SIZEOF_RAW]);
        Xid { bytes }
    }
}

impl Xid {
    pub fn new() -> Xid {
        let now = ::now().as_secs() as u32;
        let old = COUNTER.fetch_add(1, Ordering::SeqCst);
        Xid::from_parts(now, *MACHINE, *PROCESS, old + 1)
    }

    fn from_parts(ts: u32, mid: [u8; 3], pid: u32, obj: u32) -> Xid {
        let mut bytes = [0; SIZEOF_RAW];

        (&mut bytes[..4]).write_u32::<BigEndian>(ts).unwrap();

        bytes[4] = mid[0];
        bytes[5] = mid[1];
        bytes[6] = mid[2];

        bytes[7] = (pid >> 8) as u8;
        bytes[8] = pid as u8;

        bytes[9] = (obj >> 16) as u8;
        bytes[10] = (obj >> 8) as u8;
        bytes[11] = obj as u8;

        Xid { bytes }
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub fn encode(&self, dst: &mut [u8]) {
        let bytes = self.bytes();
        macro_rules! enc {
            ( $i:expr ) => { ENCODING[$i as usize] }
        }

        dst[0] = enc!(bytes[0] >> 3);
        dst[1] = enc!((bytes[1] >> 6) & 0x1F | (bytes[0] << 2) & 0x1F);
        dst[2] = enc!((bytes[1] >> 1) & 0x1F);
        dst[3] = enc!((bytes[2] >> 4) & 0x1F | (bytes[1] << 4) & 0x1F);
        dst[4] = enc!(bytes[3] >> 7 | (bytes[2] << 1) & 0x1F);
        dst[5] = enc!((bytes[3] >> 2) & 0x1F);
        dst[6] = enc!(bytes[4] >> 5 | (bytes[3] << 3) & 0x1F);
        dst[7] = enc!(bytes[4] & 0x1F);
        dst[8] = enc!(bytes[5] >> 3);
        dst[9] = enc!((bytes[6] >> 6) & 0x1F | (bytes[5] << 2) & 0x1F);
        dst[10] = enc!((bytes[6] >> 1) & 0x1F);
        dst[11] = enc!((bytes[7] >> 4) & 0x1F | (bytes[6] << 4) & 0x1F);
        dst[12] = enc!(bytes[8] >> 7 | (bytes[7] << 1) & 0x1F);
        dst[13] = enc!((bytes[8] >> 2) & 0x1F);
        dst[14] = enc!((bytes[9] >> 5) | (bytes[8] << 3) & 0x1F);
        dst[15] = enc!(bytes[9] & 0x1F);
        dst[16] = enc!(bytes[10] >> 3);
        dst[17] = enc!((bytes[11] >> 6) & 0x1F | (bytes[10] << 2) & 0x1F);
        dst[18] = enc!((bytes[11] >> 1) & 0x1F);
        dst[19] = enc!((bytes[11] << 4) & 0x1F);
    }

    pub fn decode(&mut self, src: &[u8]) {
        let bytes = self.bytes_mut();
        macro_rules! dec {
            ( $i:expr ) => { DECODING[src[$i] as usize] }
        }

        bytes[0] = (dec!(0) << 3) | (dec!(1) >> 2);
        bytes[1] = (dec!(1) << 6) | (dec!(2) << 1) | (dec!(3) >> 4);
        bytes[2] = (dec!(3) << 4) | (dec!(4) >> 1);
        bytes[3] = (dec!(4) << 7) | (dec!(5) << 2) | (dec!(6) >> 3);
        bytes[4] = (dec!(6) << 5) | dec!(7);
        bytes[5] = (dec!(8) << 3) | (dec!(9) >> 2);
        bytes[6] = (dec!(9) << 6) | (dec!(10) << 1) | (dec!(11) >> 4);
        bytes[7] = (dec!(11) << 4) | (dec!(12) >> 1);
        bytes[8] = (dec!(12) << 7) | (dec!(13) << 2) | (dec!(14) >> 3);
        bytes[9] = (dec!(14) << 5) | dec!(15);
        bytes[10] = (dec!(16) << 3) | (dec!(17) >> 2);
        bytes[11] = (dec!(17) << 6) | (dec!(18) << 1) | (dec!(19) >> 4);
    }
}

#[cfg(test)]
impl Xid {
    fn timestamp(&self) -> u32 {
        use byteorder::ReadBytesExt;
        let mut r = io::Cursor::new(&self.bytes[0..4]);
        r.read_u32::<BigEndian>().unwrap()
    }

    fn machine(&self) -> &[u8] {
        &self.bytes[4..7]
    }

    fn process(&self) -> u32 {
        use byteorder::ReadBytesExt;
        let mut r = io::Cursor::new(&self.bytes[7..9]);
        r.read_u16::<BigEndian>().map(u32::from).unwrap()
    }

    fn counter(&self) -> u32 {
        let buf = &self.bytes[9..12];
        (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ord() {
        let id1 = Xid::new();
        let id2 = Xid::new();
        let id3 = Xid::new();
        assert!(id1 < id2);
        assert!(id2 < id3);
        assert!(id1.to_string() < id2.to_string());
        assert!(id2.to_string() < id3.to_string());
    }

    #[test]
    fn test_encode_decode() {
        let mut buf = [0; SIZEOF_STR];

        for _ in 0..10 {
            let id1 = Xid::new();
            id1.encode(&mut buf);
            let mut id2 = Xid::default();
            id2.decode(&buf);
            assert_eq!(id1, id2);
            assert_eq!(id1.to_string(), id2.to_string());
        }
    }

    struct PartsTest {
        timestamp: u32,
        machine: [u8; 3],
        process: u32,
        counter: u32,
        expect_id: Xid,
    }
    impl PartsTest {
        fn run(&self) {
            assert_eq!(
                self.expect_id,
                Xid::from_parts(self.timestamp, self.machine, self.process, self.counter)
            );
            assert_eq!(self.timestamp, self.expect_id.timestamp());
            assert_eq!(self.machine, self.expect_id.machine());
            assert_eq!(self.process, self.expect_id.process());
            assert_eq!(self.counter, self.expect_id.counter());
        }
    }

    #[test]
    fn test_from_parts() {
        let tests = &[
            PartsTest {
                timestamp: 1300816219,
                machine: [0x60, 0xf4, 0x86],
                process: 0xe428,
                counter: 4271561,
                expect_id: Xid::from([
                    0x4d, 0x88, 0xe1, 0x5b, 0x60, 0xf4, 0x86, 0xe4, 0x28, 0x41, 0x2d, 0xc9
                ]),
            },
            PartsTest {
                timestamp: 0,
                machine: [0x00, 0x00, 0x00],
                process: 0x0000,
                counter: 0,
                expect_id: Xid::from([
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ]),
            },
            PartsTest {
                timestamp: 0,
                machine: [0xaa, 0xbb, 0xcc],
                process: 0xddee,
                counter: 1,
                expect_id: Xid::from([
                    0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00, 0x00, 0x01
                ]),
            },
        ];

        for test in tests {
            test.run();
        }
    }
}
