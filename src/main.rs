use clap::Parser;
use std::io::IsTerminal;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use vani_rs::{app, cli::Cli};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    if let Err(e) = ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst)) {
        eprintln!("error: cannot install Ctrl-C handler: {e}");
        return ExitCode::FAILURE;
    }
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(e) => {
            eprintln!("error: cannot determine the current directory: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let progress: Option<&mut dyn std::io::Write> = if stderr.is_terminal() {
        Some(&mut stderr)
    } else {
        None
    };
    match app::execute(
        &cli,
        &cwd,
        &mut std::io::stdin().lock(),
        &mut stdout,
        progress,
        &stop,
    ) {
        Ok(app::Status::Found) => ExitCode::SUCCESS,
        Ok(app::Status::Interrupted) => ExitCode::from(130),
        Ok(app::Status::Exhausted) => ExitCode::from(2),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
