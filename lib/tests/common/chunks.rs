//! Deterministic upload and download payloads.

use crate::common::{check, TestResult};

/// Create zero-filled chunks with the requested total and individual sizes.
///
/// # Errors
/// Returns an error for invalid chunk sizes or a total not divisible by its chunk size.
pub fn make_stream_of_chunks(
    total_size: usize,
    chunk_size: Option<usize>,
) -> TestResult<futures::stream::Iter<impl Iterator<Item = &'static [u8]>>> {
    const SIZE: usize = 16 * 1024;
    static CHUNK: [u8; SIZE] = [0; SIZE];

    let size = chunk_size.unwrap_or(SIZE);
    check(size > 0 && size <= SIZE, "invalid chunk size")?;
    check(total_size >= size, format_args!("{total_size}"))?;
    check(
        total_size.is_multiple_of(size),
        format_args!("{total_size}"),
    )?;

    Ok(futures::stream::iter(std::iter::repeat_n(
        &CHUNK[..size],
        total_size / size,
    )))
}
