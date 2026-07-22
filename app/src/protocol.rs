//! Binary protocol for tray ↔ service IPC.
//!
//! Request:  [magic: u8; 2] [command: u8] [payload: u8]   (4 bytes)
//! Response: [status: u8]   [result: u8]                   (2 bytes)

/// Magic bytes prefixed to every pipe request. "HT" = HP Thermal.
/// Rejects accidental or scanning connections at the wire level.
pub const PIPE_MAGIC: [u8; 2] = [0x48, 0x54];

pub const CMD_READ_THERMAL: u8 = 0x01;
pub const CMD_SET_THERMAL: u8 = 0x02;
pub const CMD_READ_COOLSENSE: u8 = 0x03;
pub const CMD_SET_COOLSENSE: u8 = 0x04;
pub const CMD_SET_LOGGING: u8 = 0x05;
pub const CMD_READ_BUILD_ID: u8 = 0x06;
pub const CMD_SET_STACK_MONITOR: u8 = 0x07;
pub const CMD_READ_TEMP: u8 = 0x08;
pub const CMD_READ_BRIGHTNESS: u8 = 0x09;
pub const CMD_SET_BRIGHTNESS: u8 = 0x0A;

/// Compile-time fingerprint of the build. Both tray and service are compiled
/// from the same source, so this value matches when they're the same build.
/// Returned as [hi, lo] by CMD_READ_BUILD_ID.
pub const BUILD_FINGERPRINT: [u8; 2] = build_fingerprint();

const fn build_fingerprint() -> [u8; 2] {
    // Hash BUILD_ID + BUILD_DATE together — unique per compile
    let mut h: u32 = 0x811c_9dc5;
    let id = env!("BUILD_ID").as_bytes();
    let date = env!("BUILD_DATE").as_bytes();
    let mut i = 0;
    while i < id.len() {
        h ^= id[i] as u32;
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    i = 0;
    while i < date.len() {
        h ^= date[i] as u32;
        h = h.wrapping_mul(0x0100_0193);
        i += 1;
    }
    [(h >> 8) as u8, h as u8]
}

pub const STATUS_OK: u8 = 0x00;
pub const STATUS_INVALID_CMD: u8 = 0x01;
pub const STATUS_INVALID_PAYLOAD: u8 = 0x02;
pub const STATUS_WMI_ERROR: u8 = 0x03;

/// Bit flag OR'd into status byte when the response is a cached value
/// rather than a fresh WMI read. The payload is still valid.
pub const STATUS_CACHED: u8 = 0x80;

/// Check if a status byte indicates success (fresh or cached).
pub fn status_ok(s: u8) -> bool {
    s & !STATUS_CACHED == STATUS_OK
}

pub struct Request {
    pub command: u8,
    pub payload: u8,
}

impl TryFrom<[u8; 2]> for Request {
    type Error = u8;

    fn try_from(buf: [u8; 2]) -> Result<Self, u8> {
        match buf[0] {
            CMD_READ_THERMAL => Ok(Request {
                command: buf[0],
                payload: 0,
            }),
            CMD_SET_THERMAL => {
                if buf[1] > 3 {
                    return Err(STATUS_INVALID_PAYLOAD);
                }
                Ok(Request {
                    command: buf[0],
                    payload: buf[1],
                })
            }
            CMD_READ_COOLSENSE => Ok(Request {
                command: buf[0],
                payload: 0,
            }),
            CMD_SET_COOLSENSE => {
                if buf[1] > 1 {
                    return Err(STATUS_INVALID_PAYLOAD);
                }
                Ok(Request {
                    command: buf[0],
                    payload: buf[1],
                })
            }
            CMD_SET_LOGGING => {
                if buf[1] > 1 {
                    return Err(STATUS_INVALID_PAYLOAD);
                }
                Ok(Request {
                    command: buf[0],
                    payload: buf[1],
                })
            }
            CMD_READ_BUILD_ID => Ok(Request {
                command: buf[0],
                payload: 0,
            }),
            CMD_SET_STACK_MONITOR => {
                if buf[1] > 1 {
                    return Err(STATUS_INVALID_PAYLOAD);
                }
                Ok(Request {
                    command: buf[0],
                    payload: buf[1],
                })
            }
            CMD_READ_TEMP => Ok(Request {
                command: buf[0],
                payload: 0,
            }),
            CMD_READ_BRIGHTNESS => Ok(Request {
                command: buf[0],
                payload: 0,
            }),
            CMD_SET_BRIGHTNESS => {
                if buf[1] > 100 {
                    return Err(STATUS_INVALID_PAYLOAD);
                }
                Ok(Request {
                    command: buf[0],
                    payload: buf[1],
                })
            }
            _ => Err(STATUS_INVALID_CMD),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(cmd: u8, payload: u8) -> Result<Request, u8> {
        Request::try_from([cmd, payload])
    }

    #[test]
    fn read_commands_accept_and_normalize_payload_to_zero() {
        // Read commands ignore the payload byte — it must be forced to 0 so a
        // client can't smuggle state in via an unused field.
        for cmd in [
            CMD_READ_THERMAL,
            CMD_READ_COOLSENSE,
            CMD_READ_BUILD_ID,
            CMD_READ_TEMP,
            CMD_READ_BRIGHTNESS,
        ] {
            let req = parse(cmd, 0xFF).expect("read command should parse");
            assert_eq!(req.command, cmd);
            assert_eq!(req.payload, 0, "read cmd 0x{cmd:02X} must zero the payload");
        }
    }

    #[test]
    fn set_thermal_accepts_only_modes_0_through_3() {
        for mode in 0..=3u8 {
            assert_eq!(parse(CMD_SET_THERMAL, mode).unwrap().payload, mode);
        }
        for bad in [4u8, 5, 100, 255] {
            assert_eq!(
                parse(CMD_SET_THERMAL, bad).err(),
                Some(STATUS_INVALID_PAYLOAD),
                "thermal mode {bad} must be rejected",
            );
        }
    }

    #[test]
    fn toggle_commands_accept_only_0_or_1() {
        for cmd in [CMD_SET_COOLSENSE, CMD_SET_LOGGING, CMD_SET_STACK_MONITOR] {
            assert_eq!(parse(cmd, 0).unwrap().payload, 0);
            assert_eq!(parse(cmd, 1).unwrap().payload, 1);
            for bad in [2u8, 3, 255] {
                assert_eq!(
                    parse(cmd, bad).err(),
                    Some(STATUS_INVALID_PAYLOAD),
                    "toggle cmd 0x{cmd:02X} must reject {bad}",
                );
            }
        }
    }

    #[test]
    fn set_brightness_accepts_0_through_100() {
        for level in [0u8, 1, 50, 99, 100] {
            assert_eq!(parse(CMD_SET_BRIGHTNESS, level).unwrap().payload, level);
        }
        for bad in [101u8, 200, 255] {
            assert_eq!(
                parse(CMD_SET_BRIGHTNESS, bad).err(),
                Some(STATUS_INVALID_PAYLOAD),
                "brightness {bad} must be rejected",
            );
        }
    }

    #[test]
    fn unknown_commands_are_rejected() {
        // 0x00 (below range), 0x0B (just past the table), and high bytes.
        for cmd in [0x00u8, 0x0B, 0x40, 0x7F, 0xFF] {
            assert_eq!(
                parse(cmd, 0).err(),
                Some(STATUS_INVALID_CMD),
                "cmd 0x{cmd:02X} must be rejected as unknown",
            );
        }
    }

    #[test]
    fn status_ok_ignores_the_cached_bit() {
        assert!(status_ok(STATUS_OK), "fresh OK");
        assert!(status_ok(STATUS_OK | STATUS_CACHED), "cached OK");
        assert!(!status_ok(STATUS_INVALID_CMD));
        assert!(!status_ok(STATUS_INVALID_PAYLOAD));
        assert!(!status_ok(STATUS_WMI_ERROR));
        // A cached *error* is still an error — the cached bit must not mask it.
        assert!(!status_ok(STATUS_WMI_ERROR | STATUS_CACHED));
    }

    #[test]
    fn build_fingerprint_is_populated() {
        // Confirms build.rs injected BUILD_ID/BUILD_DATE and the FNV hash ran.
        assert_eq!(BUILD_FINGERPRINT, build_fingerprint());
        assert_ne!(
            BUILD_FINGERPRINT,
            [0, 0],
            "fingerprint should be non-trivial"
        );
    }
}
