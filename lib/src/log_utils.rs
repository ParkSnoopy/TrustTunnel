//! Log destinations, flushing guards, and hierarchical connection identifiers.

use dynfmt::Format;
use log::{Log, Metadata, Record};
use once_cell::sync::OnceCell;
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::sync::Mutex;

/// Logs records in the standard output stream
#[derive(Debug, Clone, Copy)]
pub struct StdoutLogger;

/// Logs records in the provided file by path
#[derive(Debug)]
pub struct FileLogger {
    file: Mutex<BufWriter<File>>,
}

/// Forces flushing buffered records to a destination while dropping
#[derive(Debug)]
pub struct LogFlushGuard;

/// Return the process-wide standard-output logger.
#[must_use]
pub const fn make_stdout_logger() -> &'static impl Log {
    const LOGGER: StdoutLogger = StdoutLogger;
    &LOGGER
}

/// Initialize the process-wide file logger.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or the logger is already initialized.
pub fn make_file_logger(path: &str) -> std::io::Result<&'static impl Log> {
    static LOGGER: OnceCell<FileLogger> = OnceCell::new();
    let mut initialized = false;
    let logger = LOGGER.get_or_try_init(|| {
        let logger = FileLogger::new(path)?;
        initialized = true;
        Ok::<_, std::io::Error>(logger)
    })?;
    if initialized {
        Ok(logger)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "file logger is already initialized",
        ))
    }
}

fn write_record(mut w: impl Write, record: &Record<'_>) -> std::io::Result<()> {
    writeln!(
        w,
        "{} [{:?}] [{}] [{}] {}",
        chrono::Local::now().format("%T.%6f"),
        std::thread::current().id(),
        record.level(),
        record.target(),
        record.args(),
    )
}

impl Log for StdoutLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            if let Err(e) = write_record(std::io::stdout(), record) {
                report_log_error("write", &e);
            }
        }
    }

    fn flush(&self) {}
}

impl FileLogger {
    /// Open a log file, replacing its existing contents.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or opened for writing.
    pub fn new(path: &str) -> std::io::Result<Self> {
        Ok(Self {
            file: Mutex::new(BufWriter::new(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(path)?,
            )),
        })
    }
}

impl Log for FileLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            let result = self
                .file
                .lock()
                .map_err(|e| std::io::Error::other(e.to_string()))
                .and_then(|mut file| write_record(&mut *file, record));
            if let Err(e) = result {
                report_log_error("write", &e);
            }
        }
    }

    fn flush(&self) {
        let result = self
            .file
            .lock()
            .map_err(|e| std::io::Error::other(e.to_string()))
            .and_then(|mut file| file.flush());
        if let Err(e) = result {
            report_log_error("flush", &e);
        }
    }
}

impl Drop for FileLogger {
    fn drop(&mut self) {
        self.flush();
    }
}

impl Drop for LogFlushGuard {
    fn drop(&mut self) {
        log::logger().flush();
    }
}

fn report_log_error(operation: &str, error: &std::io::Error) {
    // The logging callback cannot return errors; stderr is the final best-effort sink.
    let _ = writeln!(std::io::stderr().lock(), "Log {operation} failure: {error}");
}

/// Log a message prefixed with its hierarchical connection identifier.
#[macro_export]
macro_rules! log_id {
    ($lvl:ident, $id_chain:expr, $msg:expr) => {
        $lvl!("[{}] {}", $id_chain, format_args!($msg))
    };
    ($lvl:ident, $id_chain:expr, $fmt:expr, $($arg:tt)*) => {
        $lvl!("[{}] {}", $id_chain, format_args!($fmt, $($arg)*))
    };
}

pub(crate) const CLIENT_ID_FMT: &str = "CLIENT={}";
pub(crate) const TUNNEL_ID_FMT: &str = "TUN={}";
pub(crate) const CONNECTION_ID_FMT: &str = "CONN={}";

/// One formatted identifier in a connection's logging hierarchy.
#[derive(Debug, Copy, Clone)]
pub struct IdItem<T: Copy + serde::ser::Serialize> {
    fmt: &'static str,
    id: T,
}

/// A sequence of identifiers rendered with slash separators.
#[derive(Debug, Clone)]
#[must_use]
pub struct IdChain<T: Copy + serde::ser::Serialize> {
    list: Vec<IdItem<T>>,
}

impl<T: Copy + serde::ser::Serialize> IdItem<T> {
    /// Pair an identifier with its runtime format string.
    #[must_use]
    pub const fn new(fmt: &'static str, id: T) -> Self {
        Self { fmt, id }
    }
}

impl<T: Copy + serde::ser::Serialize> IdChain<T> {
    /// Construct an empty identifier hierarchy.
    pub const fn empty() -> Self {
        Self { list: Vec::new() }
    }

    /// Return this hierarchy with one more identifier appended.
    pub fn extended(&self, new: IdItem<T>) -> Self {
        let mut x = Self::with_capacity(self.list.len() + 1);
        x.list.extend(self.list.iter());
        x.list.push(new);
        x
    }

    fn with_capacity(cap: usize) -> Self {
        Self {
            list: Vec::with_capacity(cap),
        }
    }
}

impl<T: Copy + serde::ser::Serialize> From<IdItem<T>> for IdChain<T> {
    fn from(x: IdItem<T>) -> Self {
        Self { list: vec![x] }
    }
}

impl<T: Copy + serde::ser::Serialize> Display for IdChain<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = self.list.iter().try_fold(String::new(), |mut acc, i| {
            let x = dynfmt::curly::SimpleCurlyFormat
                .format(i.fmt, [i.id])
                .map_err(|_| std::fmt::Error)?;

            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(x.as_ref());
            Ok::<_, std::fmt::Error>(acc)
        })?;
        f.write_str(&str)
    }
}

#[cfg(test)]
mod tests {
    use crate::log_utils::{write_record, IdChain, IdItem};
    use crate::utils::check;

    #[test]
    fn test() {
        let mut chain = IdChain::from(IdItem::new("hello {}", 42));
        assert_eq!("hello 42", format!("{chain}"));

        chain = chain.extended(IdItem::new("ok {}", 73));
        assert_eq!("hello 42/ok 73", format!("{chain}"));
    }

    #[test]
    fn empty_and_invalid_identifier_formats() {
        assert_eq!(IdChain::<u64>::empty().to_string(), "");
        let chain = IdChain::from(IdItem::new("{missing}", 42));
        let mut output = String::new();
        assert!(std::fmt::write(&mut output, format_args!("{chain}")).is_err());
    }

    #[test]
    fn log_prefix_preserves_captured_and_explicit_format_arguments() {
        macro_rules! capture {
            ($($args:tt)*) => { format!($($args)*) };
        }
        let chain = IdChain::from(IdItem::new("hello {}", 42));
        let value = 7;
        assert_eq!(
            log_id!(capture, chain, "value={value}"),
            "[hello 42] value=7"
        );
        assert_eq!(
            log_id!(capture, chain, "value={}", value),
            "[hello 42] value=7"
        );
    }

    #[test]
    fn records_preserve_format_and_propagate_writer_errors() -> std::io::Result<()> {
        let record = log::Record::builder()
            .level(log::Level::Info)
            .target("test")
            .args(format_args!("message"))
            .build();
        let mut output = Vec::new();
        write_record(&mut output, &record)?;
        check(
            output.ends_with(b" [INFO] [test] message\n"),
            "record format changed",
        )?;
        let full: &mut [u8] = &mut [];
        check(
            write_record(full, &record).is_err(),
            "writer failure was lost",
        )?;
        Ok(())
    }
}
