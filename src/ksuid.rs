use std::fmt;
use std::time::{self, Duration, SystemTime, UNIX_EPOCH};
use byteorder::{BigEndian, WriteBytesExt};
use rand::{thread_rng, Rng};

/// K-Sortable Unique ID.
///    - 00-03: unsigned int32 BE UTC timestamp with custom epoch
///    - 04-19: random payload
#[derive(Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Ksuid {
    bytes: [u8; SIZEOF_RAW],
}

const SIZEOF_RAW: usize = SIZEOF_TIME + SIZEOF_RAND;
const SIZEOF_STR: usize = 27;
const SIZEOF_TIME: usize = 4;
const SIZEOF_RAND: usize = 16;

static ID_MIN_STR: &str = "000000000000000000000000000";
static ID_MAX_STR: &str = "aWgEPTl1tmebfsQzFP4bxwgy80V";

// const DEFAULT_CUSTOM_EPOCH: u64 = 1400000000;

lazy_static! {
    static ref DEFAULT_CUSTOM_EPOCH: SystemTime = {
        let elapsed = Duration::from_secs(1_400_000_000);
        time::UNIX_EPOCH + elapsed
    };
}

impl fmt::Debug for Ksuid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.bytes.fmt(f)
    }
}

/// `CustomEpoch` represents epoch that starts more recently.
#[derive(Debug, Clone)]
pub struct CustomEpoch {
    // diff from UNIX_EPOCH
    diff: Duration,
    // UNIX_EPOCH + diff_from_unix_epoch
    epoch: SystemTime,
}

impl Default for Ksuid {
    fn default() -> Self {
        Ksuid {
            bytes: [0; SIZEOF_RAW],
        }
    }
}

impl Default for CustomEpoch {
    fn default() -> Self {
        CustomEpoch {
            diff: Duration::from_secs(1_400_000_000),
            epoch: *DEFAULT_CUSTOM_EPOCH,
        }
    }
}

impl CustomEpoch {
    fn new(diff: Duration) -> Self {
        CustomEpoch {
            diff,
            epoch: UNIX_EPOCH + diff,
        }
    }

    // Adjust a timestamp to a custom epoch one.
    fn adjust_to_custom_epoch(&self, ts: Duration) -> Duration {
        ts - self.diff
    }

    // Adjust a timestamp to an unix epoch one.
    fn adjust_to_unix_epoch(&self, ts: Duration) -> Duration {
        ts + self.diff
    }

    fn ksuid(&self, unixtime: Duration) -> Ksuid {
        let mut bytes = [0u8; SIZEOF_RAW];
        thread_rng().fill_bytes(&mut bytes[SIZEOF_TIME..]);
        let ts = self.adjust_to_custom_epoch(unixtime);
        (&mut bytes[..SIZEOF_TIME])
            .write_u32::<BigEndian>(ts.as_secs() as u32)
            .expect("write timestamp");
        Ksuid { bytes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_epoch() {
        let epoch = CustomEpoch::default();

        for _ in 0..10 {
            println!("{:?}", epoch.ksuid(::now()));
        }
    }
}
