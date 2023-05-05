# File Crypter

This is a Rust crate that provides a simple interface for encrypting and decrypting files using AES-256 encryption and RSA public key encryption. The crate uses OpenSSL for encryption and decryption, and serde for serializing and deserializing metadata.

## Usage

### Creating a new `FileCrypter` instance

You can create a new instance of `FileCrypter` by calling its constructor `new` with a public key and a private key. Alternatively, you can create an encrypter or a decrypter by calling the `encrypter` or `decrypter` methods respectively, and passing a public or private key.

```rust
use openssl::rsa::Rsa;
use file_crypter::FileCrypter;

let private_key = Rsa::generate(2048).unwrap();
let public_key = Rsa::public_key_from_pem(&private_key.public_key_to_pem().unwrap()).unwrap();

let file_crypter = FileCrypter::new(public_key, private_key);
```

### Encrypting a file

To encrypt a file, you need to provide a mutable reference to a reader object that implements the `Read` trait, a mutable reference to a writer object that implements the `Write` trait, and a reference to a value of any type that implements the `Serialize` trait, which is used to encrypt metadata about the file.

```rust
use std::fs::File;
use std::io::{Read, Write};
use file_crypter::FileCrypter;

let mut input_file = File::open("plaintext.txt").unwrap();
let mut output_file = File::create("encrypted.bin").unwrap();

let private_key = include_bytes!("private_key.pem");

let metadata = Some("This is a metadata string.".to_string());

let file_crypter = FileCrypter::new(private_key).encrypt(&mut input_file, &mut output_file, &metadata);

assert!(result.is_ok());
```

### Decrypting a file

To decrypt a file, you need to provide a mutable reference to a reader object that implements the `Read` trait and a mutable reference to a writer object that implements the `Write` trait.

```rust
use std::fs::File;
use std::io::{Read, Write};
use file_crypter::{decrypt, FileCrypter};

let mut input_file = File::open("encrypted.bin").unwrap();
let mut output_file = File::create("decrypted.txt").unwrap();

let private_key = include_bytes!("private_key.pem");

let result: Metadata = FileCrypter::decrypter(private_key).decrypt(&mut input_file, &mut output_file).expect("Unable to decrypt");

assert_eq!(result.file_name, "test.txt");
assert_eq!(output_stream.into_inner(), data);
```

### File Structure

The encrypted file consists of a header followed by several encrypted sections:

| Field | Size (bytes) | Description |
| --- | --- | --- |
| Header | 12 | The string "IDCRYPTER1.0" to identify the file format |
| Encrypted AES key length | 4 | The length of the encrypted AES key in bytes |
| Encrypted AES key | Variable | The AES key encrypted with the public key |
| Encrypted IV length | 4 | The length of the encrypted IV in bytes |
| Encrypted IV | Variable | The IV encrypted with the public key |
| Encrypted metadata length | 4 | The length of the encrypted metadata in bytes |
| Encrypted metadata | Variable | The metadata encrypted with the AES key |
| Encrypted file contents | Variable | The file contents encrypted with the AES key |

### Header

The first 12 bytes of the file contain the header, which is a string identifying the file format. The header is always "IDCRYPTER1.0". If the header is not present or is invalid, the decryption process will fail.

### Encrypted AES Key

The next section of the file contains the encrypted AES key. The length of the encrypted key is stored as a 4-byte big-endian integer. The AES key is encrypted using RSA public key encryption with the recipient's public key. The encrypted AES key is used to encrypt the file contents.

### Encrypted IV

After the encrypted AES key, the next section of the file contains the encrypted IV. The length of the encrypted IV is stored as a 4-byte big-endian integer. The IV is encrypted using RSA public key encryption with the recipient's public key. The IV is used to initialize the AES cipher used to encrypt the file contents.

### Encrypted Metadata

The next section of the file contains the encrypted metadata. The length of the encrypted metadata is stored as a 4-byte big-endian integer. The metadata is serialized using serde and then encrypted using AES encryption with the AES key.

### Encrypted File Contents

The final section of the file contains the encrypted file contents. The file contents are encrypted using AES encryption with the AES key and the IV. The encrypted contents are written to the file in chunks, with each chunk being encrypted separately.


### TODO

- Improve error handling by adding custom error structs and implementing the `Error` trait for them.
- Add more detailed error messages to aid debugging and make it easier to handle errors gracefully.