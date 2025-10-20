use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use color_eyre::eyre::eyre;
use std::io::{Read, Write};

use crate::header;

pub fn encrypt_file<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: header::MasterKey,
    header_nonce: &[u8; 12],
) -> color_eyre::Result<()> {
    let cipher = Aes256Gcm::new(&key.into());
    let mut buf = [0u8; 4096];
    let mut chunk_counter = 0u64;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }

        let mut chunk_nonce_bytes = [0u8; 12];
        chunk_nonce_bytes[..4].copy_from_slice(&header_nonce[..4]);
        let counter_bytes = chunk_counter.to_le_bytes();
        for i in 0..8 {
            chunk_nonce_bytes[4 + i] = header_nonce[4 + i] ^ counter_bytes[i];
        }
        let nonce = (&chunk_nonce_bytes).into();

        let ciphertext = cipher
            .encrypt(nonce, &buf[..n])
            .map_err(|_| eyre!("encryption failed"))?;

        writer.write_all(&ciphertext)?;

        chunk_counter += 1;
    }

    Ok(())
}

pub fn decrypt_file<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    key: header::MasterKey,
    header_nonce: &[u8; 12],
) -> color_eyre::Result<()> {
    let cipher = Aes256Gcm::new(&key.into());
    let mut buffer = [0u8; 4096 + 16]; // chunk + GCM tag (16 bytes)
    let mut chunk_counter = 0u64;

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }

        let mut chunk_nonce_bytes = [0u8; 12];
        chunk_nonce_bytes[..4].copy_from_slice(&header_nonce[..4]);
        let counter_bytes = chunk_counter.to_le_bytes();
        for i in 0..8 {
            chunk_nonce_bytes[4 + i] = header_nonce[4 + i] ^ counter_bytes[i];
        }
        let nonce = (&chunk_nonce_bytes).into();

        let plaintext = cipher
            .decrypt(nonce, &buffer[..n])
            .map_err(|_| color_eyre::eyre::eyre!("decryption failed"))?;

        writer.write_all(&plaintext)?;

        chunk_counter += 1;
    }

    Ok(())
}
