extern crate openssl;
extern crate rand;
extern crate serde;
extern crate serde_json;

use openssl::pkey::{Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::symm::{Cipher, Crypter, Mode};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use thiserror::Error;

const BUFFER_LEN: usize = 1024 * 1024;
const HEADER: &[u8; 12] = b"IDCRYPTER1.0";

#[derive(Error, Debug)]
pub enum FileCrypterError {
    #[error("Either a private key or a public key must be provided.")]
    MissingKey,

    #[error("Invalid header")]
    InvalidHeader,

    #[error("Encryption error: {0}")]
    EncryptionError(#[from] openssl::error::ErrorStack),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
}

pub struct FileCrypter {
    private_key: Option<Rsa<Private>>,
    public_key: Rsa<Public>,
}

impl FileCrypter {
    pub fn encrypter(public_key: Rsa<Public>) -> Self {
        FileCrypter {
            public_key,
            private_key: None,
        }
    }

    pub fn decrypter(private_key: Rsa<Private>) -> Result<Self, FileCrypterError> {
        let public_key = Rsa::public_key_from_pem(&private_key.public_key_to_pem()?)?;
        Ok(FileCrypter {
            public_key,
            private_key: Some(private_key),
        })
    }

    /// Encrypts the contents of a file with AES-256 encryption algorithm and RSA public key encryption.
    ///
    /// # Arguments
    ///
    /// * `reader` - A mutable reference to an object implementing the `Read` trait which is used to read the contents of the file to be encrypted.
    /// * `writer` - A mutable reference to an object implementing the `Write` trait which is used to write the encrypted file contents to disk.
    /// * `metadata` - A reference to a value of any type that implements the `Serialize` trait, which is used to encrypt metadata about the file.
    ///
    /// # Returns
    ///
    /// An empty `Result` type `()` on success, or a boxed dynamic error object implementing the `Error` trait on failure.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::fs::File;
    /// use std::io::Read;
    /// use std::io::Write;
    /// use openssl::rsa::Rsa;
    ///
    /// let mut input_file = File::open("plaintext.txt").unwrap();
    /// let mut output_file = File::create("encrypted.bin").unwrap();
    ///
    /// let private_key = Rsa::generate(2048).unwrap();
    ///
    /// let metadata = Some("This is a metadata string.".to_string());
    ///
    /// let result = FileCrpyter::new(private_key).encrypt(&mut input_file, &mut output_file, &metadata);
    ///
    /// assert!(result.is_ok());
    /// ```
    pub fn encrypt<R, W, T>(
        &self,
        reader: &mut R,
        writer: &mut W,
        metadata: &T,
    ) -> Result<(), FileCrypterError>
    where
        R: Read,
        W: Write,
        T: Serialize,
    {
        let public_key = self.public_key.as_ref();

        // Generate an AES key 256 bits
        let aes_bytes = rand::random::<[u8; 32]>();

        // Prepare AES Cypher
        let cipher = Cipher::aes_256_cbc();
        let iv = rand::random::<[u8; 16]>();
        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, &aes_bytes, Some(iv.as_ref()))?;

        // Encrypt the AES key with the public key
        let mut encrypted_aes_key = vec![0; public_key.size() as usize];
        let encrypted_aes_key_len =
            public_key.public_encrypt(&aes_bytes, &mut encrypted_aes_key, Padding::PKCS1)?;

        // Encrypt the metadata with the AES key
        let json = serde_json::to_string(metadata)?;
        let mut encrypted_metadata = vec![0; json.len() + cipher.block_size()];
        let mut count = encrypter.update(json.as_bytes(), &mut encrypted_metadata)?;
        count += encrypter.finalize(&mut encrypted_metadata[count..])?;
        encrypted_metadata.truncate(count);

        // Write the hedaer
        writer.write_all(HEADER)?;

        // Write the encrypted AES Key
        writer.write_all(&(encrypted_aes_key_len as u32).to_be_bytes())?;
        writer.write_all(&encrypted_aes_key)?;

        // Write the encrypted IV
        let mut encrypted_iv = vec![0; public_key.size() as usize];
        let encrypted_iv_len = public_key.public_encrypt(&iv, &mut encrypted_iv, Padding::PKCS1)?;
        writer.write_all(&(encrypted_iv_len as u32).to_be_bytes())?;
        writer.write_all(&encrypted_iv)?;

        // Write the encrypted metadata
        writer.write_all(&(encrypted_metadata.len() as u32).to_be_bytes())?;
        writer.write_all(&encrypted_metadata)?;

        // Write the encrypted file contents
        let mut buffer = [0u8; BUFFER_LEN];
        let mut encrypted_chunk = vec![0; BUFFER_LEN + cipher.block_size()];

        loop {
            let read_count = reader.read(&mut buffer)?;

            if read_count == 0 {
                break;
            }

            let count = encrypter.update(&buffer[..read_count], &mut encrypted_chunk)?;
            writer.write_all(&encrypted_chunk[..count])?;
        }

        let count = encrypter.finalize(&mut encrypted_chunk)?;
        writer.write_all(&encrypted_chunk[..count])?;

        writer.flush()?;

        Ok(())
    }

    /// Decrypts a file that has been encrypted with the `encrypt` method.
    ///
    /// # Arguments
    ///
    /// * `reader` - A mutable reference to an object implementing the `Read` trait which is used to read the encrypted file contents.
    /// * `writer` - A mutable reference to an object implementing the `Write` trait which is used to write the decrypted file contents to disk.
    ///
    /// # Returns
    ///
    /// The metadata decrypted from the file on success, or a boxed dynamic error object implementing the `Error` trait on failure.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::fs::File;
    /// use std::io::Read;
    /// use std::io::Write;
    /// use file_crypter::{decrypt, FileCrypter};
    ///
    /// let mut input_file = File::open("encrypted.bin").unwrap();
    /// let mut output_file = File::create("decrypted.txt").unwrap();
    ///
    /// let private_key = Rsa::generate(2048).unwrap();
    ///
    /// let result = FileCrypter::decrypter(private_key).decrypt(&mut input_file, &mut output_file);
    ///
    /// assert!(result.is_ok());
    /// ```
    pub fn decrypt<R, W, T>(&self, reader: &mut R, writer: &mut W) -> Result<T, FileCrypterError>
    where
        R: Read,
        W: Write,
        for<'a> T: Deserialize<'a>,
    {
        let (metadata, cipher, mut decrypter) = self.grab_metadata(reader)?;

        // Decrypt the file contents with the AES key
        let mut buffer = [0u8; BUFFER_LEN];
        let mut encrypted_chunk = vec![0; BUFFER_LEN + cipher.block_size()];

        loop {
            let read_count = reader.read(&mut buffer)?;

            if read_count == 0 {
                break;
            }

            let count = decrypter.update(&buffer[..read_count], &mut encrypted_chunk)?;
            writer.write_all(&encrypted_chunk[..count])?;
        }

        let count = decrypter.finalize(&mut encrypted_chunk)?;

        writer.write_all(&encrypted_chunk[..count])?;
        writer.flush()?;

        Ok(metadata)
    }

    pub fn fetch_metadata<R, T>(&self, reader: &mut R) -> Result<T, FileCrypterError>
    where
        R: Read,
        for<'a> T: Deserialize<'a>,
    {
        let (metadata, _, _) = self.grab_metadata(reader)?;
        
        Ok(metadata)
    }

    fn grab_metadata<R, T>(&self, reader: &mut R) -> Result<(T, Cipher, Crypter), FileCrypterError>
    where
        R: Read,
        for<'a> T: Deserialize<'a>,
    {
        if self.private_key.is_none() {
            return Err(FileCrypterError::MissingKey);
        }

        let private_key = self.private_key.as_ref().unwrap();

        // Validate the header
        let mut header = [0; HEADER.len()];
        reader.read_exact(&mut header)?;

        if &header != HEADER {
            return Err(FileCrypterError::InvalidHeader);
        }

        // Read the first 4 bytes to get the length of the encrypted AES key
        let mut encrypted_aes_key_len_bytes = [0; 4];
        reader.read_exact(&mut encrypted_aes_key_len_bytes)?;
        let encrypted_aes_key_len = u32::from_be_bytes(encrypted_aes_key_len_bytes) as usize;

        // Read the encrypted AES key
        let mut encrypted_aes_key = vec![0; encrypted_aes_key_len];
        reader.read_exact(&mut encrypted_aes_key)?;

        // Read the iv
        let mut encrpyted_iv_len = [0; 4];
        reader.read_exact(&mut encrpyted_iv_len)?;
        let encrpyted_iv_len = u32::from_be_bytes(encrpyted_iv_len) as usize;

        let mut encrypted_iv = vec![0; encrpyted_iv_len];
        reader.read_exact(&mut encrypted_iv)?;

        // Decrypt IV
        let mut iv = vec![0; private_key.size() as usize];
        let size = private_key.private_decrypt(&encrypted_iv, &mut iv, Padding::PKCS1)?;
        iv.truncate(size);

        // Decrypt the AES key with the private key
        let mut aes_key = vec![0; private_key.size() as usize];

        let aes_key_len =
            private_key.private_decrypt(&encrypted_aes_key, &mut aes_key, Padding::PKCS1)?;

        aes_key.truncate(aes_key_len);

        // Read the length of the encrypted metadata
        let mut encrypted_metadata_length = [0; 4];
        reader.read_exact(&mut encrypted_metadata_length)?;
        let encrypted_metadata_length = u32::from_be_bytes(encrypted_metadata_length) as usize;

        // Read the encrypted metadata
        let mut encrypted_metadata = vec![0; encrypted_metadata_length];
        reader.read_exact(&mut encrypted_metadata)?;

        // Decrypt the metadata with the AES key
        let cipher = Cipher::aes_256_cbc();
        let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &aes_key, Some(iv.as_ref()))?;

        let mut decrypted_metadata = vec![0; encrypted_metadata_length + cipher.block_size()];
        let mut count = decrypter.update(&encrypted_metadata, &mut decrypted_metadata)?;
        count += decrypter.finalize(&mut decrypted_metadata[count..])?;
        decrypted_metadata.truncate(count);

        // Deserialize the json
        let metadata: T = serde_json::from_slice(&decrypted_metadata)?;

        return Ok((metadata, cipher, decrypter));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Metadata {
        file_name: String,
    }

    fn create_file_crypter() -> FileCrypter {
        let rsa_key = Rsa::generate(2048).unwrap();
        FileCrypter::decrypter(rsa_key).expect("Unable to create file crypter")
    }

    #[test]
    fn test_empty_file() {
        let data = b"";

        let file_crypter = create_file_crypter();

        let mut input_stream: Cursor<Vec<u8>> = Cursor::new(data.to_vec());
        let mut output_stream: Cursor<Vec<u8>> = Cursor::new(Vec::new());

        let metadata = Metadata {
            file_name: "empty.txt".to_string(),
        };

        let result = file_crypter
            .encrypt(&mut input_stream, &mut output_stream, &metadata)
            .expect("Unable to encrypt");

        // Now to test decryption
        let mut input_stream: Cursor<Vec<u8>> = Cursor::new(output_stream.into_inner());
        let mut output_stream: Cursor<Vec<u8>> = Cursor::new(Vec::new());

        let decrypted_metadata: Metadata = file_crypter
            .decrypt(&mut input_stream, &mut output_stream)
            .expect("Unable to decrypt");

        assert_eq!(decrypted_metadata.file_name, "empty.txt");
        assert_eq!(output_stream.into_inner(), data);
    }

    #[test]
    fn test_large_file() {
        let data = vec![0u8; 1024 * 1024 * 10]; // 10 MB

        let file_crypter = create_file_crypter();

        let mut input_stream: Cursor<Vec<u8>> = Cursor::new(data.clone());
        let mut output_stream: Cursor<Vec<u8>> = Cursor::new(Vec::new());

        let metadata = Metadata {
            file_name: "large_file.bin".to_string(),
        };

        let result = file_crypter
            .encrypt(&mut input_stream, &mut output_stream, &metadata)
            .expect("Unable to encrypt");

        // Now to test decryption
        let mut input_stream: Cursor<Vec<u8>> = Cursor::new(output_stream.into_inner());
        let mut output_stream: Cursor<Vec<u8>> = Cursor::new(Vec::new());

        let metadata: Metadata = file_crypter
            .decrypt(&mut input_stream, &mut output_stream)
            .expect("Unable to decrypt");

        assert_eq!(metadata.file_name, "large_file.bin");
        assert_eq!(output_stream.into_inner(), data);
    }

    #[test]
    fn test_invalid_header() {
        let data = b"InvalidHeader";

        let file_crypter = create_file_crypter();

        let mut input_stream: Cursor<Vec<u8>> = Cursor::new(data.to_vec());
        let mut output_stream: Cursor<Vec<u8>> = Cursor::new(Vec::new());

        let result: Result<Metadata, FileCrypterError> =
            file_crypter.decrypt(&mut input_stream, &mut output_stream);

        assert!(result.is_err());
        assert!(matches!(result, Err(FileCrypterError::InvalidHeader)));
    }

    #[test]
    fn test_wrong_private_key() {
        let data = b"Hello, world!";

        let file_crypter = create_file_crypter();

        let mut input_stream: Cursor<Vec<u8>> = Cursor::new(data.to_vec());
        let mut output_stream: Cursor<Vec<u8>> = Cursor::new(Vec::new());

        let metadata = Metadata {
            file_name: "hello.txt".to_string(),
        };

        let result = file_crypter
            .encrypt(&mut input_stream, &mut output_stream, &metadata)
            .expect("Unable to encrypt");

        // Now to test decryption with the wrong private key
        let rsa_key = Rsa::generate(2048).unwrap();
        let wrong_file_crypter = FileCrypter::decrypter(rsa_key);

        let mut input_stream: Cursor<Vec<u8>> = Cursor::new(output_stream.into_inner());
        let mut output_stream: Cursor<Vec<u8>> = Cursor::new(Vec::new());

        let result: Result<Metadata, FileCrypterError> = wrong_file_crypter
            .expect("Unable to create crypter")
            .decrypt(&mut input_stream, &mut output_stream);

        assert!(result.is_err());
        assert!(matches!(result, Err(FileCrypterError::EncryptionError(_))));
    }
}
