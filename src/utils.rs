use std::{
    io::{self, Write, stdout},
    path::{Path, PathBuf},
};

use color_eyre::eyre::{Context, bail};

pub fn print_hex_param(param: &str, bytes: &[u8], bytes_per_line: usize) -> io::Result<()> {
    let mut stdout = stdout().lock();
    let indent_str = " ".repeat(param.len());

    stdout.write_all(param.as_bytes())?;

    for (i, byte) in bytes.iter().enumerate() {
        if i % bytes_per_line == 0 && i != 0 {
            writeln!(&mut stdout)?;
            stdout.write_all(indent_str.as_bytes())?;
        }
        write!(&mut stdout, "{:02x} ", byte)?;
    }
    writeln!(&mut stdout)?;

    Ok(())
}

pub fn ask_password() -> color_eyre::Result<String> {
    let password = rpassword::prompt_password("Password: ").wrap_err("failed to read password")?;

    Ok(password)
}

pub fn ask_password_confirm() -> color_eyre::Result<String> {
    let password = rpassword::prompt_password("Password: ").wrap_err("failed to read password")?;
    let password_confirm =
        rpassword::prompt_password("Retype password: ").wrap_err("failed to read password")?;

    if password.as_str() != password_confirm.as_str() {
        bail!("password mismatch");
    }

    Ok(password)
}

pub fn ask_confirmation(msg: &str) -> color_eyre::Result<bool> {
    print!("{msg} (y/N) ");
    io::stdout().flush()?;

    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;

    let buffer = buffer.trim_end().to_lowercase();

    Ok(buffer.as_str() == "y")
}

const FILE_EXTENSION: &str = "filecrypt";

pub fn has_extension(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some(FILE_EXTENSION)
}

pub fn append_extension(path: &Path) -> PathBuf {
    let mut path = path.to_owned();

    match path.extension() {
        Some(ext) => {
            let mut ext = ext.to_os_string();
            ext.push(".");
            ext.push(FILE_EXTENSION);
            path.set_extension(ext)
        }
        None => path.set_extension(FILE_EXTENSION),
    };

    path
}

pub fn remove_extension(path: &Path) -> PathBuf {
    let mut path = path.to_owned();

    path.set_extension("");

    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn append_extension_with_ext() {
        let p = Path::new("file.txt");
        let res = append_extension(p);

        assert_eq!(res, Path::new("file.txt.filecrypt"));
    }

    #[test]
    fn append_extension_with_no_ext() {
        let p = Path::new("file");
        let res = append_extension(p);

        assert_eq!(res, Path::new("file.filecrypt"));
    }

    #[test]
    fn remove_extension_with_ext() {
        let p = Path::new("file.txt.filecrypt");
        let res = remove_extension(p);

        assert_eq!(res, Path::new("file.txt"));
    }

    #[test]
    fn remove_extension_with_no_ext() {
        let p = Path::new("file.filecrypt");
        let res = remove_extension(p);

        assert_eq!(res, Path::new("file"));
    }
}
