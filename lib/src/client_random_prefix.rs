//! Random client-random prefix and bit-mask generation.

use rand::rngs::OsRng;
use rand::Rng;

/// Invalid client-random prefix generation parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An explicit mask contains no bytes.
    EmptyMask,
    /// The requested prefix length is outside 1..=32 bytes.
    InvalidLength(usize),
    /// The requested mask-bit probability is outside 1..=100 percent.
    InvalidPercent(u8),
    /// An explicit mask exceeds 32 bytes.
    MaskTooLong(usize),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyMask => write!(f, "mask must not be empty"),
            Self::InvalidLength(length) => {
                write!(f, "length must be in range 1..=32 bytes, got {length}")
            }
            Self::InvalidPercent(percent) => {
                write!(f, "percent must be in range 1..=100, got {percent}")
            }
            Self::MaskTooLong(length) => {
                write!(f, "mask length must be in range 1..=32 bytes, got {length}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Length and mask-bit probability for a generated client-random prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratorParams {
    /// Prefix length in bytes, from 1 through 32.
    pub length: usize,
    /// Probability in percent that each mask bit is set, from 1 through 100.
    pub percent: u8,
}

impl Default for GeneratorParams {
    fn default() -> Self {
        Self {
            length: 4,
            percent: 70,
        }
    }
}

/// A random prefix and its matching bit mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedPrefix {
    value: Vec<u8>,
    mask: Vec<u8>,
}

impl GeneratedPrefix {
    const fn new(value: Vec<u8>, mask: Vec<u8>) -> Self {
        Self { value, mask }
    }

    /// Return the prefix bytes, with unmasked bits cleared.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Return the mask bytes.
    #[must_use]
    pub fn mask(&self) -> &[u8] {
        &self.mask
    }

    /// Format the prefix and mask as `prefix/mask` hexadecimal strings.
    #[must_use]
    pub fn to_masked_hex_string(&self) -> String {
        format!("{}/{}", hex::encode(&self.value), hex::encode(&self.mask))
    }
}

/// Generate a random client-random prefix and mask.
///
/// # Errors
/// Returns an error when the length or percentage is out of range.
pub fn generate(params: GeneratorParams) -> Result<GeneratedPrefix, Error> {
    validate_params(params)?;

    let mask = generate_mask(params.length, params.percent);
    let value = generate_value(&mask);

    Ok(GeneratedPrefix::new(value, mask))
}

/// Generate a random client-random prefix using an explicit mask.
///
/// # Errors
/// Returns an error when the mask is empty or exceeds 32 bytes.
pub fn generate_with_mask(mask: Vec<u8>) -> Result<GeneratedPrefix, Error> {
    validate_mask(&mask)?;

    let value = generate_value(&mask);

    Ok(GeneratedPrefix::new(value, mask))
}

const fn validate_params(params: GeneratorParams) -> Result<(), Error> {
    if params.length == 0 || params.length > 32 {
        return Err(Error::InvalidLength(params.length));
    }

    if params.percent == 0 || params.percent > 100 {
        return Err(Error::InvalidPercent(params.percent));
    }

    Ok(())
}

const fn validate_mask(mask: &[u8]) -> Result<(), Error> {
    if mask.is_empty() {
        return Err(Error::EmptyMask);
    }

    if mask.len() > 32 {
        return Err(Error::MaskTooLong(mask.len()));
    }

    Ok(())
}

fn generate_mask(length: usize, percent: u8) -> Vec<u8> {
    let mut mask = vec![0u8; length];
    let mut rng = rand::thread_rng();

    for byte in &mut mask {
        for bit in 0..8 {
            if rng.gen_range(0..100) < percent {
                *byte |= 1 << bit;
            }
        }
    }

    mask
}

fn generate_value(mask: &[u8]) -> Vec<u8> {
    let mut value = vec![0u8; mask.len()];

    for (byte, mask_byte) in value.iter_mut().zip(mask.iter().copied()) {
        *byte = OsRng.gen::<u8>() & mask_byte;
    }

    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_uses_default_length() -> Result<(), Box<dyn std::error::Error>> {
        let generated = generate(GeneratorParams::default())?;

        let (actual, expected) = (&(generated.value().len()), &(4));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        let (actual, expected) = (&(generated.mask().len()), &(4));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn generate_rejects_invalid_length() {
        let err = generate(GeneratorParams {
            length: 0,
            percent: 70,
        });

        assert_eq!(err, Err(Error::InvalidLength(0)));
    }

    #[test]
    fn generate_rejects_invalid_percent() {
        let err = generate(GeneratorParams {
            length: 4,
            percent: 0,
        });

        assert_eq!(err, Err(Error::InvalidPercent(0)));
    }

    #[test]
    fn generated_value_respects_mask_bits() -> Result<(), Box<dyn std::error::Error>> {
        let generated = generate(GeneratorParams {
            length: 16,
            percent: 50,
        })?;

        for (value, mask) in generated.value().iter().zip(generated.mask().iter()) {
            let (actual, expected) = (&(value & !mask), &(0));
            if actual != expected {
                return Err(format!(
                    "{} (left: {actual:?}, right: {expected:?})",
                    "assertion failed"
                )
                .into());
            }
        }
        Ok(())
    }

    #[test]
    fn generate_with_mask_preserves_explicit_mask() -> Result<(), Box<dyn std::error::Error>> {
        let mask = vec![0xff, 0x00, 0xf0, 0x0f];
        let generated = generate_with_mask(mask.clone())?;

        let (actual, expected) = (&(generated.mask()), &(mask));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        let (actual, expected) = (&(generated.value()[1]), &(0));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        Ok(())
    }

    #[test]
    fn generate_with_mask_rejects_empty_mask() {
        let err = generate_with_mask(Vec::new());

        assert_eq!(err, Err(Error::EmptyMask));
    }

    #[test]
    fn generated_prefix_formats_as_value_and_mask() -> Result<(), Box<dyn std::error::Error>> {
        let generated = generate_with_mask(vec![0xff, 0xf0])?;
        let hex_str = generated.to_masked_hex_string();

        if !(hex_str.ends_with("/fff0")) {
            return Err(format!(
                "assertion failed: {}",
                stringify!(hex_str.ends_with("/fff0"))
            )
            .into());
        }
        let (actual, expected) = (&(hex_str.len()), &("abcd/fff0".len()));
        if actual != expected {
            return Err(format!(
                "{} (left: {actual:?}, right: {expected:?})",
                "assertion failed"
            )
            .into());
        }
        Ok(())
    }
}
