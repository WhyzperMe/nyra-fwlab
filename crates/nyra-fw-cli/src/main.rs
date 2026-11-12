//! NYRA FWLab offline CLI. Firmware is never executed.
#![forbid(unsafe_code)]
mod analyze;
mod app;
mod args;
mod output;
mod scan;

fn main() {
    if let Err(err) = app::run() {
        if output::closed_stdout(&err) {
            return;
        }
        output::diagnostic(format_args!("nyra-fw: {err}"));
        std::process::exit(1);
    }
}
