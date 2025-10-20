use std::io::{Read, Write};

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use argon2::Argon2;
use bincode::{Decode, Encode};
use color_eyre::eyre::{bail, eyre};
use colored::Colorize;
use rand::RngCore;

use crate::utils;

const MAGIC: &[u8; 9] = b"FILECRYPT";
const VERSION: u8 = 1;

pub type MasterKey = [u8; 32];

#[derive(Debug, Encode, Decode)]
pub struct Header {
    magic: [u8; 9],
    version: u8,
    salt: [u8; 16],
    mem_cost_kib: u32,
    iterations: u32,
    parallelism: u32,
    nonce: [u8; 12],
    enc_master_key: [u8; 48],
    file_len: u64,
}

impl Header {
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    pub fn from_password(password: &str, file_len: u64) -> color_eyre::Result<(Self, MasterKey)> {
        let mut rng = rand::rng();

        // generate salt
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);

        // derive password
        let argon2 = Argon2::default();
        let mut kek = [0u8; 32];
        argon2.hash_password_into(password.as_bytes(), &salt, &mut kek)?;

        // generate master key
        let mut master_key = [0u8; 32];
        rng.fill_bytes(&mut master_key);

        // encrypt master key
        let cipher = Aes256Gcm::new(&kek.into());

        let mut nonce_bytes = [0u8; 12];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = (&nonce_bytes).into();

        let ciphertext = cipher
            .encrypt(nonce, master_key.as_ref())
            .map_err(|_| eyre!("failed to encrypt"))?;
        let mut enc_master_key = [0u8; 48];
        enc_master_key.copy_from_slice(&ciphertext);

        Ok((
            Self {
                magic: *MAGIC,
                version: VERSION,
                salt,
                mem_cost_kib: argon2.params().m_cost(),
                iterations: argon2.params().t_cost(),
                parallelism: argon2.params().p_cost(),
                nonce: nonce_bytes,
                enc_master_key,
                file_len,
            },
            master_key,
        ))
    }

    pub fn decrypt_master_key(&self, password: &str) -> color_eyre::Result<MasterKey> {
        let mut kek = [0u8; 32];

        let argon2_params =
            argon2::Params::new(self.mem_cost_kib, self.iterations, self.parallelism, None)?;
        let argon2 = Argon2::new(
            argon2::Algorithm::default(),
            argon2::Version::default(),
            argon2_params,
        );
        argon2.hash_password_into(password.as_bytes(), &self.salt, &mut kek)?;

        let cipher = Aes256Gcm::new(&kek.into());
        let nonce = (&self.nonce).into();
        let plaintext = cipher
            .decrypt(nonce, self.enc_master_key.as_ref())
            .map_err(|_| eyre!("invalid password"))?;

        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&plaintext);

        Ok(master_key)
    }

    pub fn read<R: Read>(reader: &mut R) -> color_eyre::Result<Self> {
        let h: Self = bincode::decode_from_std_read(reader, bincode::config::standard())?;

        if &h.magic != MAGIC {
            bail!("invalid magic number");
        }

        Ok(h)
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> color_eyre::Result<()> {
        bincode::encode_into_std_write(self, writer, bincode::config::standard())?;

        Ok(())
    }

    pub fn dump(&self) {
        println!("file format: {}", String::from_utf8_lossy(&self.magic));
        println!("version:     {}", self.version);
        println!("file size:   {}", bytesize::ByteSize(self.file_len));
        println!();
        println!("{}", "argon2id parameters:".underline());
        let _ = utils::print_hex_param("  salt:        ", &self.salt, 8);
        println!("  memory cost: {} KiB", self.mem_cost_kib);
        println!("  iterations:  {}", self.iterations);
        println!("  parallelism: {}", self.parallelism);
        println!();
        println!("{}", "AES-GCM parameters:".underline());
        let _ = utils::print_hex_param("  nonce:                ", &self.nonce, 4);
        let _ = utils::print_hex_param("  encrypted master key: ", &self.enc_master_key, 16);
    }
}
