use std::io::{self, Write, stdout};

pub fn print_hex_param(param: &str, bytes: &[u8], bytes_per_line: usize) -> io::Result<()> {
    let mut stdout = stdout().lock();
    let indent_str = " ".repeat(param.len());

    stdout.write_all(param.as_bytes())?;

    for (i, byte) in bytes.iter().enumerate() {
        if i % bytes_per_line == 0 {
            if i != 0 {
                writeln!(&mut stdout)?;
                stdout.write_all(indent_str.as_bytes())?;
            }
        }
        write!(&mut stdout, "{:02x} ", byte)?;
    }
    writeln!(&mut stdout)?;

    Ok(())
}
