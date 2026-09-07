use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::exit;

mod load;
mod res;
mod verify;
use clap::{Parser, ValueEnum};
use dialoguer::{theme::ColorfulTheme, Password as PasswordDialog};
use log::{debug, error, info, warn, LevelFilter};
use res::constants::*;
use res::*;
use serde::Serialize;
use zff::footer::{EncryptedObjectFooter, FileFooter, MainFooter, ObjectFooter, SegmentFooter};
use zff::header::{
    ChunkMaps, EncryptedObjectHeader, EncryptionInformation, FileHeader, ObjectHeader,
    SegmentHeader,
};
use zff::{HeaderCoding, Result, ZffError, ZffErrorKind};

#[derive(Parser)]
#[clap(about, version, author)]
struct Cli {
    /// The input files. This should be your zff image files. You can use this Option multiple times.
    #[clap(short='i', long="inputfiles", required=true, num_args = 1..)]
    inputfiles: Vec<String>,

    /// The output format.
    #[clap(
        short = 'f',
        long = "output-format",
        value_enum,
        default_value = "toml"
    )]
    output_format: OutputFormat,

    /// Verbose mode to show more information. Can be used multiple times.
    /// Use once for chunk maps (including chunk headers), twice for logical file metadata.
    #[arg(short='v', long="verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// The password(s), if the file(s) are encrypted. You can use this option multiple times to enter different passwords for different objects.
    /// If you don't provide a password for an object, you will be asked to enter the password interactively.
    #[clap(short='p', long="decryption-passwords", value_parser = parse_key_val::<String, String>)]
    decryption_passwords: Vec<(String, String)>,

    /// Do not ask interactively for passwords, if objects are encrypted.
    #[clap(short = 'I', long = "ignore-encryption")]
    ignore_encryption: bool,

    /// Verify data integrity and all stored hash signatures with this base64 public key.
    #[clap(short = 'k', long = "pub-key")]
    public_key: Option<String>,

    /// Checks the integrity of the imaged data by calculating/comparing the used hash values.
    #[clap(short = 'c', long = "integrity-check")]
    check_integrity: bool,

    /// The Loglevel
    #[clap(short = 'l', long = "log-level", value_enum, default_value = "info")]
    log_level: LogLevel,
}

#[derive(ValueEnum, Clone, PartialEq)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(ValueEnum, Clone)]
enum OutputFormat {
    Toml,
    Json,
    JsonPretty,
}

fn invalid(message: impl Into<String>) -> ZffError {
    ZffError::new(ZffErrorKind::Invalid, message.into())
}

fn main() {
    let args = Cli::parse();
    let level = match args.log_level {
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::Trace => LevelFilter::Trace,
    };
    env_logger::builder().filter_level(level).init();
    if let Err(e) = run(&args) {
        error!("{e}");
        exit(EXIT_STATUS_ERROR);
    }
}

fn run(args: &Cli) -> Result<()> {
    let paths: Vec<PathBuf> = args
        .inputfiles
        .iter()
        .map(|p| concat_prefix_path(INPUTFILES_PATH_PREFIX, p))
        .collect();
    let mut passwords = BTreeMap::new();
    let (mut container, files) = load::read_container(&paths, args, &mut passwords)?;
    if args.check_integrity || args.public_key.is_some() {
        verify::verify(&container, files, &passwords, args.public_key.as_deref())?;
        info!("Verification complete: all data checked successfully.");
    } else {
        if args.verbose == 0 {
            for segment in container.segments.values_mut() {
                segment.chunkmaps.clear();
            }
        }
        print_serialized_data(args, &container, &mut std::io::stdout().lock())?;
    }
    Ok(())
}

fn print_serialized_data<D: Serialize, W: Write>(
    args: &Cli,
    data: &D,
    output: &mut W,
) -> Result<()> {
    let serialized = match args.output_format {
        OutputFormat::Toml => {
            toml::to_string(data).map_err(|e| invalid(format!("Cannot serialize TOML: {e}")))?
        }
        OutputFormat::Json => serde_json::to_string(data)
            .map_err(|e| invalid(format!("Cannot serialize JSON: {e}")))?,
        OutputFormat::JsonPretty => serde_json::to_string_pretty(data)
            .map_err(|e| invalid(format!("Cannot serialize JSON: {e}")))?,
    };
    writeln!(output, "{serialized}")?;
    output.flush()?;
    Ok(())
}

fn password(args: &Cli, object: u64) -> Result<Option<String>> {
    let supplied: Vec<_> = args
        .decryption_passwords
        .iter()
        .filter(|(key, _)| key == &object.to_string())
        .collect();
    if supplied.len() > 1 {
        return Err(invalid(format!(
            "Multiple passwords supplied for object {object}"
        )));
    }
    if let Some((_, value)) = supplied.first() {
        return Ok(Some(value.clone()));
    }
    if args.ignore_encryption {
        return Ok(None);
    }
    PasswordDialog::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Enter the password for object {object}"))
        .interact().map(Some).map_err(|e| invalid(format!("Cannot obtain password for object {object}: {e}. Use --ignore-encryption to inspect encrypted metadata.")))
}

#[cfg(test)]
mod tests;
