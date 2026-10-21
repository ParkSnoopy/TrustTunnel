//! Shared hexadecimal, certificate, and configuration-formatting utilities.

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io;
use std::io::{BufReader, ErrorKind, Read};

/// Encode bytes as lowercase hexadecimal without separators.
#[must_use]
pub fn hex_dump(buf: &[u8]) -> String {
    hex::encode(buf)
}

/// Encode bytes as uppercase hexadecimal without separators.
#[must_use]
pub fn hex_dump_uppercase(buf: &[u8]) -> String {
    hex::encode_upper(buf)
}

/// Can hold either of the options
#[derive(Debug, Clone, Copy)]
#[must_use]
pub enum Either<L, R> {
    /// Contains the left option.
    Left(L),
    /// Contains the right option.
    Right(R),
}

impl<L, R> Either<L, R> {
    /// Construct the left option.
    pub const fn with_left(l: L) -> Self {
        Self::Left(l)
    }

    /// Construct the right option.
    pub const fn with_right(r: R) -> Self {
        Self::Right(r)
    }

    /// Apply the function to the object in case it contains the [`Self::Left`] option.
    /// Otherwise, do nothing.
    pub fn map_left<F, T>(self, f: F) -> Either<T, R>
    where
        F: FnOnce(L) -> T,
    {
        match self {
            Self::Left(x) => Either::<T, R>::Left(f(x)),
            Self::Right(x) => Either::<T, R>::Right(x),
        }
    }

    /// Apply the function to the object in case it contains the [`Self::Right`] option.
    /// Otherwise, do nothing.
    pub fn map_right<F, T>(self, f: F) -> Either<L, T>
    where
        F: FnOnce(R) -> T,
    {
        match self {
            Self::Left(x) => Either::<L, T>::Left(x),
            Self::Right(x) => Either::<L, T>::Right(f(x)),
        }
    }

    /// Apply the functions to the object accordingly to a contained option.
    pub fn map<FL, FR, T>(self, left: FL, right: FR) -> T
    where
        FL: FnOnce(L) -> T,
        FR: FnOnce(R) -> T,
    {
        match self {
            Self::Left(x) => left(x),
            Self::Right(x) => right(x),
        }
    }
}

/// Load PEM-encoded certificates from a file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or contains invalid PEM data.
pub fn load_certs(filename: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(filename)?);
    let mut pem_data = String::new();
    reader.read_to_string(&mut pem_data).map_err(|e| {
        io::Error::new(ErrorKind::InvalidInput, format!("Failed to read file: {e}"))
    })?;

    CertificateDer::pem_slice_iter(pem_data.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("Invalid cert: {e}")))
        .map(|certs| certs.into_iter().map(CertificateDer::into_owned).collect())
}

/// Load a PEM-encoded private key from a file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or contains an invalid private key.
pub fn load_private_key(filename: &str) -> io::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(filename)?);
    let mut pem_data = String::new();
    reader.read_to_string(&mut pem_data).map_err(|e| {
        io::Error::new(ErrorKind::InvalidInput, format!("Failed to read file: {e}"))
    })?;

    PrivateKeyDer::from_pem_slice(pem_data.as_bytes())
        .map_err(|e| io::Error::new(ErrorKind::InvalidInput, format!("Invalid key: {e}")))
        .map(|key| key.clone_key())
}

/// Join string-like iterator items with a separator.
pub trait IterJoin {
    /// The joined representation.
    type Output;

    /// Like [`Iterator::fold`] but drops the trailing separator
    fn join(self, sep: impl AsRef<str>) -> Self::Output;
}

impl<I, T> IterJoin for I
where
    I: Iterator<Item = T>,
    T: AsRef<str>,
{
    type Output = String;

    fn join(self, sep: impl AsRef<str>) -> Self::Output {
        let mut ret = self.fold(String::new(), |acc, x| acc + x.as_ref() + sep.as_ref());
        if ret.len() > sep.as_ref().len() {
            ret.replace_range((ret.len() - sep.as_ref().len()).., "");
        }

        ret
    }
}

/// Render text as a TOML comment.
pub trait ToTomlComment {
    /// Prepend each line of string with "# " turning
    /// the whole string it into TOML comment.
    fn to_toml_comment(&self) -> String;
}

impl ToTomlComment for &str {
    fn to_toml_comment(&self) -> String {
        self.lines().map(|x| format!("# {x}")).join("\n")
    }
}

impl ToTomlComment for String {
    fn to_toml_comment(&self) -> String {
        self.as_str().to_toml_comment()
    }
}

#[cfg(test)]
pub(crate) fn check(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::other(message.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::{hex_dump, hex_dump_uppercase, IterJoin};

    #[test]
    fn hexadecimal_output_preserves_case_and_zero_padding() {
        assert_eq!(hex_dump(&[]), "");
        assert_eq!(hex_dump_uppercase(&[]), "");
        assert_eq!(hex_dump(&[0, 1, 15, 16, 171, 255]), "00010f10abff");
        assert_eq!(
            hex_dump_uppercase(&[0, 1, 15, 16, 171, 255]),
            "00010F10ABFF"
        );
    }

    #[test]
    fn iter_join() {
        assert_eq!("a.b.c", ["a", "b", "c"].iter().join("."));
        assert_eq!("a", std::iter::once("a").join("x"));
        assert_eq!("", std::iter::empty::<&str>().join("x"));
    }
}
