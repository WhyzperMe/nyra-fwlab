//! One policy for CLI output: propagate stdout failures, keep diagnostics best effort.
use nyra_fw_core::{Result, errors::io};
use std::{fmt, io::Write, path::Path};

const STDOUT: &str = "<stdout>";

pub(crate) fn closed_stdout(error: &nyra_fw_core::FwError) -> bool {
    matches!(error, nyra_fw_core::FwError::Io { path, source }
        if path == Path::new(STDOUT) && source.kind() == std::io::ErrorKind::BrokenPipe)
}

pub(crate) fn line(arguments: fmt::Arguments<'_>) -> Result<()> {
    write_line(&mut std::io::stdout().lock(), arguments)
        .map_err(|error| io(Path::new(STDOUT), error))
}

pub(crate) fn diagnostic(arguments: fmt::Arguments<'_>) {
    let _ = write_line(&mut std::io::stderr().lock(), arguments);
}

fn write_line(writer: &mut impl Write, arguments: fmt::Arguments<'_>) -> std::io::Result<()> {
    writeln!(writer, "{arguments}")
}

macro_rules! out {
    ($($args:tt)*) => { crate::output::line(format_args!($($args)*))? };
}
macro_rules! diag {
    ($($args:tt)*) => { crate::output::diagnostic(format_args!($($args)*)) };
}
pub(crate) use {diag, out};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_stdout_does_not_hide_other_processing_errors() {
        assert!(closed_stdout(&io(
            STDOUT,
            std::io::ErrorKind::BrokenPipe.into()
        )));
        assert!(!closed_stdout(&io(
            STDOUT,
            std::io::ErrorKind::PermissionDenied.into()
        )));
        assert!(!closed_stdout(&io(
            "workspace/file",
            std::io::ErrorKind::BrokenPipe.into()
        )));
    }

    #[test]
    fn stdout_errors_are_returned_without_panicking() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let error = write_line(&mut Closed, format_args!("report {}", 1)).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        let mut bytes = Vec::new();
        write_line(&mut bytes, format_args!("report {}", 1)).unwrap();
        assert_eq!(bytes, b"report 1\n");
    }
}
