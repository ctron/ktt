use clap::{Parser, Subcommand};
use log::LevelFilter;
use simplelog::{ColorChoice, ConfigBuilder, TermLogger, TerminalMode};
use std::process::ExitCode;

mod cmd;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            log::error!("Error: {err}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about, author)]
struct Cli {
    /// Don't output anything
    #[arg(global = true, short, long, default_value = "false")]
    quiet: bool,

    /// Increase verbosity level
    #[arg(global = true, short, long, action=clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Extract an SBOM
    SBOM {
        /// The binary to analyze
        #[arg(value_parser)]
        input: String,
    },
}

fn setup_logger(cli: &Cli) {
    let log_level = match (cli.quiet, cli.verbose) {
        (true, _) => LevelFilter::Off,
        (_, 0) => LevelFilter::Warn,
        (_, 1) => LevelFilter::Info,
        (_, 2) => LevelFilter::Debug,
        (_, _) => LevelFilter::Trace,
    };

    TermLogger::init(
        log_level,
        ConfigBuilder::new()
            .set_time_level(LevelFilter::Debug)
            .set_max_level(LevelFilter::Debug)
            .build(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .expect("Unable to setup logging");

    log::debug!("Log Level: {log_level}");
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    setup_logger(&cli);

    match cli.command {
        Command::SBOM { input } => cmd::sbom::run(cmd::sbom::Options {
            input: Some(input).filter(|input| !input.is_empty() && input != "-"),
        }),
    }
}
