mod crypto;
mod header;
mod utils;

use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};

use crate::header::Header;
use clap::{Parser, Subcommand};
use color_eyre::eyre::Context;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Dump the header of an encrypted file
    Dump {
        /// Path to the encrypted file
        filepath: PathBuf,
    },
    /// Encrypt a plaintext file and produce an encrypted output to stdout
    Encrypt {
        /// Path to the plaintext file
        filepath: PathBuf,
    },
    /// Decrypt an encrypted file and produce a plaintext output to stdout
    Decrypt {
        /// Path to the encrypted file
        filepath: PathBuf,
    },
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let args = Args::parse();

    match args.command {
        Command::Dump { filepath } => dump_header(&filepath).wrap_err("cannot dump header")?,
        Command::Encrypt { filepath } => encrypt(&filepath).wrap_err("cannot encrypt")?,
        Command::Decrypt { filepath } => decrypt(&filepath).wrap_err("cannot decrypt")?,
    }

    Ok(())
}

fn dump_header(filepath: &Path) -> color_eyre::Result<()> {
    let mut f = File::open(filepath)?;

    let header = Header::read(&mut f)?;
    header.dump();

    Ok(())
}

fn encrypt(filepath: &Path) -> color_eyre::Result<()> {
    let mut input_file = File::open(filepath)
        .wrap_err_with(|| format!("cannot open input file {}", filepath.display()))?;
    let metadata = input_file.metadata()?;

    let password = utils::ask_password_confirm()?;

    let (header, master_key) = Header::from_password(&password, metadata.len())?;

    let output_file_path = utils::append_extension(filepath);
    let mut output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output_file_path)
        .wrap_err_with(|| format!("cannot open output file {}", filepath.display()))?;

    header.write(&mut output_file)?;
    crypto::encrypt_file(
        &mut input_file,
        &mut output_file,
        master_key,
        header.nonce(),
    )?;

    Ok(())
}

fn decrypt(filepath: &Path) -> color_eyre::Result<()> {
    let mut input_file = File::open(filepath)
        .wrap_err_with(|| format!("cannot open input file {}", filepath.display()))?;

    let header = Header::read(&mut input_file)?;

    let password = utils::ask_password()?;
    let master_key = header.decrypt_master_key(&password)?;

    if !utils::has_extension(filepath) {
        eprintln!(
            "The provided file '{}' does not have a '.filecrypt' extension.\n\
                 Please rename it so that it ends with '.filecrypt'.",
            filepath.display()
        );
        return Ok(());
    }

    let output_file_path = utils::remove_extension(filepath);

    let mut output_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output_file_path)
        .wrap_err_with(|| format!("cannot open output file {}", filepath.display()))?;

    crypto::decrypt_file(
        &mut input_file,
        &mut output_file,
        master_key,
        header.nonce(),
    )?;

    Ok(())
}
