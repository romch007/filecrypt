use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, aead::Payload};
use color_eyre::eyre::{bail, eyre};
use std::io::{self, ErrorKind, Read, Write};

use crate::header;

/// Maximum plaintext bytes per chunk.
const CHUNK_SIZE: usize = 4096;
const TAG_SIZE: usize = 16;
const MAX_CIPHERTEXT: usize = CHUNK_SIZE + TAG_SIZE;
const LAST_FLAG: u32 = 1 << 31;

fn chunk_nonce(header_nonce: &[u8; 12], counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&header_nonce[..4]);
    let counter_bytes = counter.to_le_bytes();
    for i in 0..8 {
        nonce[4 + i] = header_nonce[4 + i] ^ counter_bytes[i];
    }
    nonce
}

fn chunk_aad(counter: u64, is_last: bool) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[..8].copy_from_slice(&counter.to_le_bytes());
    aad[8] = is_last as u8;
    aad
}

fn fill_buf<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

pub fn encrypt_file<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: header::MasterKey,
    header_nonce: &[u8; 12],
) -> color_eyre::Result<()> {
    let cipher = Aes256Gcm::new(&key.into());
    let mut buf = [0u8; CHUNK_SIZE];
    let mut chunk_counter = 0u64;

    loop {
        let n = fill_buf(reader, &mut buf)?;
        let is_last = n < buf.len();

        let nonce_bytes = chunk_nonce(header_nonce, chunk_counter);
        let nonce = (&nonce_bytes).into();
        let aad = chunk_aad(chunk_counter, is_last);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &buf[..n],
                    aad: &aad,
                },
            )
            .map_err(|_| eyre!("encryption failed"))?;

        let mut prefix = ciphertext.len() as u32;
        if is_last {
            prefix |= LAST_FLAG;
        }
        writer.write_all(&prefix.to_le_bytes())?;
        writer.write_all(&ciphertext)?;

        chunk_counter += 1;
        if is_last {
            break;
        }
    }

    Ok(())
}

pub fn decrypt_file<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: header::MasterKey,
    header_nonce: &[u8; 12],
    file_len: u64,
) -> color_eyre::Result<()> {
    let cipher = Aes256Gcm::new(&key.into());
    let mut chunk_counter = 0u64;
    let mut total_plaintext = 0u64;

    loop {
        let mut prefix_bytes = [0u8; 4];
        match reader.read_exact(&mut prefix_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                bail!("file is truncated (missing final chunk)");
            }
            Err(e) => return Err(e.into()),
        }

        let raw = u32::from_le_bytes(prefix_bytes);
        let is_last = raw & LAST_FLAG != 0;
        let len = (raw & !LAST_FLAG) as usize;
        if len > MAX_CIPHERTEXT || len < TAG_SIZE {
            bail!("invalid chunk length");
        }

        let mut ciphertext = vec![0u8; len];
        reader.read_exact(&mut ciphertext).map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                eyre!("file is truncated (incomplete chunk)")
            } else {
                e.into()
            }
        })?;

        let nonce_bytes = chunk_nonce(header_nonce, chunk_counter);
        let nonce = (&nonce_bytes).into();
        let aad = chunk_aad(chunk_counter, is_last);

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| eyre!("decryption failed"))?;

        writer.write_all(&plaintext)?;
        total_plaintext += plaintext.len() as u64;

        chunk_counter += 1;
        if is_last {
            break;
        }
    }

    if total_plaintext != file_len {
        bail!("decrypted length mismatch (file may be corrupted or tampered)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::Header;

    fn round_trip(plaintext: &[u8]) -> Vec<u8> {
        let (header, master_key) = Header::from_password("pw", plaintext.len() as u64).unwrap();

        let mut encrypted = Vec::new();
        encrypt_file(
            &mut &plaintext[..],
            &mut encrypted,
            master_key,
            header.nonce(),
        )
        .unwrap();

        let mk = header.decrypt_master_key("pw").unwrap();
        let mut decrypted = Vec::new();
        decrypt_file(
            &mut &encrypted[..],
            &mut decrypted,
            mk,
            header.nonce(),
            header.file_len(),
        )
        .unwrap();

        decrypted
    }

    #[test]
    fn round_trip_empty() {
        assert_eq!(round_trip(b""), b"");
    }

    #[test]
    fn round_trip_small() {
        assert_eq!(round_trip(b"hello world"), b"hello world");
    }

    #[test]
    fn round_trip_exact_multiple() {
        let data = vec![0xABu8; CHUNK_SIZE * 3];
        assert_eq!(round_trip(&data), data);
    }

    #[test]
    fn round_trip_large_unaligned() {
        let data: Vec<u8> = (0..CHUNK_SIZE * 5 + 123).map(|i| i as u8).collect();
        assert_eq!(round_trip(&data), data);
    }

    #[test]
    fn truncation_is_detected() {
        let plaintext = vec![7u8; CHUNK_SIZE * 3 + 10];
        let (header, master_key) = Header::from_password("pw", plaintext.len() as u64).unwrap();

        let mut encrypted = Vec::new();
        encrypt_file(
            &mut &plaintext[..],
            &mut encrypted,
            master_key,
            header.nonce(),
        )
        .unwrap();

        encrypted.truncate(encrypted.len() - MAX_CIPHERTEXT);

        let mk = header.decrypt_master_key("pw").unwrap();
        let mut out = Vec::new();
        let err = decrypt_file(
            &mut &encrypted[..],
            &mut out,
            mk,
            header.nonce(),
            header.file_len(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("truncated"));
    }
}
