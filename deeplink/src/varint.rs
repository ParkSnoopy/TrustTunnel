use crate::error::{DeepLinkError, Result};
use std::io::{self, ErrorKind};

/// Encode an integer using TLS/QUIC variable-length encoding (RFC 9000 §16).
///
/// The two most-significant bits of the first byte encode the length:
/// - 00: 1 byte (values 0-63)
/// - 01: 2 bytes (values 0-16383)
/// - 10: 4 bytes (values 0-1073741823)
/// - 11: 8 bytes (values 0-2^62-1)
///
/// # Errors
///
/// Returns [`DeepLinkError::VarintOverflow`] if the value is too large (> 2^62-1).
pub fn encode_varint(value: u64) -> Result<Vec<u8>> {
    if value <= 0x3F {
        Ok(vec![value as u8])
    } else if value <= 0x3FFF {
        Ok(((value | 0x4000) as u16).to_be_bytes().to_vec())
    } else if value <= 0x3FFF_FFFF {
        Ok(((value | 0x8000_0000) as u32).to_be_bytes().to_vec())
    } else if value <= 0x3FFF_FFFF_FFFF_FFFF {
        Ok((value | 0xC000_0000_0000_0000).to_be_bytes().to_vec())
    } else {
        Err(DeepLinkError::VarintOverflow(value))
    }
}

/// Decode a TLS/QUIC variable-length integer from data at the given offset.
///
/// Returns (value, `new_offset`) on success.
///
/// # Errors
///
/// Returns [`ErrorKind::UnexpectedEof`] if the offset is outside the data or
/// the encoded integer is truncated.
pub fn decode_varint(data: &[u8], offset: usize) -> io::Result<(u64, usize)> {
    if offset >= data.len() {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "unexpected end of data while reading varint",
        ));
    }

    let first = data[offset];
    let prefix = first >> 6;

    match prefix {
        0 => {
            // 1 byte
            Ok((u64::from(first & 0x3F), offset + 1))
        }
        1 => {
            // 2 bytes
            if offset + 2 > data.len() {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "truncated 2-byte varint",
                ));
            }
            let bytes = [data[offset], data[offset + 1]];
            let value = u16::from_be_bytes(bytes) & 0x3FFF;
            Ok((u64::from(value), offset + 2))
        }
        2 => {
            // 4 bytes
            if offset + 4 > data.len() {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "truncated 4-byte varint",
                ));
            }
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            let value = u32::from_be_bytes(bytes) & 0x3FFF_FFFF;
            Ok((u64::from(value), offset + 4))
        }
        3 => {
            // 8 bytes
            if offset + 8 > data.len() {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "truncated 8-byte varint",
                ));
            }
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ];
            let value = u64::from_be_bytes(bytes) & 0x3FFF_FFFF_FFFF_FFFF;
            Ok((value, offset + 8))
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::{prop_assert, prop_assert_eq};

    type TestResult = proptest::test_runner::TestCaseResult;

    #[test]
    fn test_encode_varint_1_byte() -> TestResult {
        prop_assert_eq!(encode_varint(0)?, vec![0x00]);
        prop_assert_eq!(encode_varint(37)?, vec![0x25]);
        prop_assert_eq!(encode_varint(63)?, vec![0x3F]);
        Ok(())
    }

    #[test]
    fn test_encode_varint_2_bytes() -> TestResult {
        prop_assert_eq!(encode_varint(64)?, vec![0x40, 0x40]);
        prop_assert_eq!(encode_varint(1000)?, vec![0x43, 0xE8]);
        prop_assert_eq!(encode_varint(16383)?, vec![0x7F, 0xFF]);
        Ok(())
    }

    #[test]
    fn test_encode_varint_4_bytes() -> TestResult {
        prop_assert_eq!(encode_varint(16384)?, vec![0x80, 0x00, 0x40, 0x00]);
        prop_assert_eq!(encode_varint(1_073_741_823)?, vec![0xBF, 0xFF, 0xFF, 0xFF]);
        Ok(())
    }

    #[test]
    fn test_encode_varint_8_bytes() -> TestResult {
        prop_assert_eq!(
            encode_varint(1_073_741_824)?,
            vec![0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
        );
        prop_assert_eq!(
            encode_varint(0x3FFF_FFFF_FFFF_FFFF)?,
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
        Ok(())
    }

    #[test]
    fn test_encode_varint_too_large() -> TestResult {
        let result = encode_varint(0x4000_0000_0000_0000);
        prop_assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_decode_varint_1_byte() -> TestResult {
        prop_assert_eq!(decode_varint(&[0x25], 0)?, (37, 1));
        prop_assert_eq!(decode_varint(&[0x3F], 0)?, (63, 1));
        Ok(())
    }

    #[test]
    fn test_decode_varint_2_bytes() -> TestResult {
        prop_assert_eq!(decode_varint(&[0x40, 0x40], 0)?, (64, 2));
        prop_assert_eq!(decode_varint(&[0x7F, 0xFF], 0)?, (16383, 2));
        Ok(())
    }

    #[test]
    fn test_decode_varint_4_bytes() -> TestResult {
        prop_assert_eq!(decode_varint(&[0x80, 0x00, 0x40, 0x00], 0)?, (16384, 4));
        Ok(())
    }

    #[test]
    fn test_decode_varint_8_bytes() -> TestResult {
        prop_assert_eq!(
            decode_varint(&[0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00], 0)?,
            (1_073_741_824, 8)
        );
        Ok(())
    }

    #[test]
    fn test_decode_varint_at_offset() -> TestResult {
        let data = vec![0xFF, 0x25, 0x00];
        prop_assert_eq!(decode_varint(&data, 1)?, (37, 2));
        Ok(())
    }

    #[test]
    fn test_decode_varint_truncated() -> TestResult {
        let result = decode_varint(&[0x40], 0);
        prop_assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_encode_decode_roundtrip() -> TestResult {
        for value in [0, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824] {
            let encoded = encode_varint(value)?;
            let (decoded, _) = decode_varint(&encoded, 0)?;
            prop_assert_eq!(decoded, value);
        }
        Ok(())
    }
}
