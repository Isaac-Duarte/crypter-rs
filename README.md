# File Crypter

This is a Rust crate that provides a simple interface for encrypting and decrypting files using AES-256 encryption and RSA public key encryption. The crate uses OpenSSL for encryption and decryption, and serde for serializing and deserializing metadata.

## Usage

```rust
use file_crypter::FileCrypter;
use openssl::rsa::Rsa;
use std::fs::File;
use std::io::{Read, Write};

fn main() {
    // Generate a 2048-bit RSA key pair
    let rsa_key = Rsa::generate(2048).unwrap();

    // Create a FileCrypter instance with the public and private RSA keys
    let file_crypter = FileCrypter::decrypter(
        rsa_key,
    );

    // Encrypt a file
    let mut input_file = File::open("plaintext.txt").unwrap();
    let mut output_file = File::create("encrypted.bin").unwrap();
    let metadata = "This is a metadata string.".to_string();
    file_crypter
        .encrypt(&mut input_file, &mut output_file, &metadata)
        .expect("Encryption failed");

    // Decrypt a file
    let mut input_file = File::open("encrypted.bin").unwrap();
    let mut output_file = File::create("decrypted.txt").unwrap();
    let decrypted_metadata: String = file_crypter
        .decrypt(&mut input_file, &mut output_file)
        .expect("Decryption failed");

    println!("Decrypted metadata: {}", decrypted_metadata);
}
```

## File Structure

The `FileCrypter` library creates encrypted files with a specific structure to store the encrypted data and metadata. Here's a breakdown of the file structure:

1. **Header**: The file starts with a 12-byte header that identifies the file as a `FileCrypter` encrypted file. The header is a constant value: `IDCRYPTER1.0`.

2. **Encrypted AES Key Length**: The next 4 bytes represent the length of the encrypted AES key as an unsigned 32-bit integer in big-endian format.

3. **Encrypted AES Key**: The encrypted AES key follows, with a length specified by the previous field. This key is encrypted using the RSA public key.

4. **Encrypted IV Length**: A 4-byte field follows, representing the length of the encrypted Initialization Vector (IV) as an unsigned 32-bit integer in big-endian format.

5. **Encrypted IV**: The encrypted IV follows, with a length specified by the previous field. The IV is encrypted using the RSA public key.

6. **Encrypted Metadata Length**: The next 4 bytes represent the length of the encrypted metadata as an unsigned 32-bit integer in big-endian format.

7. **Encrypted Metadata**: The encrypted metadata follows, with a length specified by the previous field. The metadata is encrypted using the AES key and IV.

8. **Encrypted File Contents**: The rest of the file contains the encrypted file contents. The file contents are encrypted using the AES key and IV.

When decrypting a file, `FileCrypter` reads and processes these sections in order, decrypting the AES key and IV using the RSA private key, and then decrypting the metadata and file contents using the decrypted AES key and IV.

Here's a visual representation of the file structure:

```
+--------------+---------------------+----------------+-------------------+-------------+---------------------+----------------+--------------------+
|    Header    | Encrypted AES Key L | Encrypted AES  | Encrypted IV Leng | Encrypted   | Encrypted Metadata  | Encrypted Meta | Encrypted File Con |
|              | ength               | Key            | th                | IV          | Length              | data           | tents              |
+--------------+---------------------+----------------+-------------------+-------------+---------------------+----------------+--------------------+
| 12 bytes     | 4 bytes             | Variable       | 4 bytes           | Variable    | 4 bytes             | Variable       | Remaining bytes    |
+--------------+---------------------+----------------+-------------------+-------------+---------------------+----------------+--------------------+
```