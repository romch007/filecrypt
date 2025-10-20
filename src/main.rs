mod crypto;
mod header;
mod utils;

use std::{
    fs::File,
    io::stdout,
    path::{Path, PathBuf},
};

use crate::header::Header;
use clap::{Parser, Subcommand};
use color_eyre::eyre::{Context, bail};

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

fn ask_password() -> color_eyre::Result<String> {
    let password = rpassword::prompt_password("Password: ").wrap_err("failed to read password")?;

    Ok(password)
}

fn ask_password_confirm() -> color_eyre::Result<String> {
    let password = rpassword::prompt_password("Password: ").wrap_err("failed to read password")?;
    let password_confirm =
        rpassword::prompt_password("Retype password: ").wrap_err("failed to read password")?;

    if password.as_str() != password_confirm.as_str() {
        bail!("password mismatch");
    }

    Ok(password)
}

fn encrypt(filepath: &Path) -> color_eyre::Result<()> {
    let mut input_file =
        File::open(filepath).wrap_err_with(|| format!("cannot read {}", filepath.display()))?;
    let metadata = input_file.metadata()?;

    let password = ask_password_confirm()?;

    let (header, master_key) = Header::from_password(&password, metadata.len())?;

    if atty::is(atty::Stream::Stdout) {
        eprintln!("stdout is a terminal! Please redirect to a file or pipe.");
        return Ok(());
    }

    let mut stdout = stdout().lock();

    header.write(&mut stdout)?;
    crypto::encrypt_file(&mut input_file, &mut stdout, master_key, header.nonce())?;

    Ok(())
}

fn decrypt(filepath: &Path) -> color_eyre::Result<()> {
    let mut input_file =
        File::open(filepath).wrap_err_with(|| format!("cannot read {}", filepath.display()))?;

    let header = Header::read(&mut input_file)?;

    let password = ask_password()?;
    let master_key = header.decrypt_master_key(&password)?;

    let mut stdout = stdout().lock();

    crypto::decrypt_file(&mut input_file, &mut stdout, master_key, header.nonce())?;

    Ok(())
}
