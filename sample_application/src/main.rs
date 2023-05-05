use clap::{Arg, Parser, Subcommand};
use file_crypter::FileCrypter;
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;

extern crate file_crypter;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    file_name: PathBuf,

    #[arg(long)]
    output_file: PathBuf,

    #[arg(long)]
    private_key: Option<PathBuf>,

    #[arg(long)]
    public_key: Option<PathBuf>,

    #[arg(short, long, default_value_t = 2048 * 2048)]
    buffer: usize,

    #[arg(long)]
    encrypt: bool,

    #[arg(long)]
    decrypt: bool,
}

#[derive(Serialize, Deserialize)]
struct FileMetadata {
    file_name: String,
}

fn main() {
    let mut args = Args::parse();

    if (args.encrypt && args.decrypt) || (!args.encrypt && !args.decrypt) {
        eprintln!("You must specify either --encrypt or --decrypt");
        return;
    }

    let file_crypter;

    if args.public_key.is_none() && args.private_key.is_none() {
        // We'll generate one
        let private_key = Rsa::generate(2048).unwrap();
        let public_key =
            Rsa::public_key_from_pem(private_key.public_key_to_pem().unwrap().as_ref())
                .unwrap();

        // Write private and public to file
        std::fs::write("private.pem", private_key.private_key_to_pem().unwrap()).unwrap();
        std::fs::write("public.pem", public_key.public_key_to_pem().unwrap()).unwrap();


        file_crypter = FileCrypter::new(public_key, private_key);


    } else if args.private_key.is_none() && args.public_key.is_some() {
        let public_key =
            Rsa::public_key_from_pem(&std::fs::read(args.public_key.unwrap()).unwrap())
                .unwrap();

        file_crypter = FileCrypter::encrypter(public_key);
    } else {
        let private_key =
            Rsa::private_key_from_pem(&std::fs::read(args.private_key.unwrap()).unwrap())
                .unwrap();

        let public_key =
            Rsa::public_key_from_pem(private_key.public_key_to_pem().unwrap().as_ref())
                .unwrap();

        file_crypter = FileCrypter::new(public_key, private_key);
    }

    if args.encrypt {
        let file = std::fs::File::open(&args.file_name).unwrap();
        let mut input_stream = BufReader::new(file);

        let output_file = std::fs::File::create(&args.output_file).unwrap();
        let mut output_stream = BufWriter::new(output_file);

        let metadata = FileMetadata {
            file_name: String::from(args.file_name.to_str().unwrap()),
        };

        file_crypter
            .encrypt(&mut input_stream, &mut output_stream, &metadata)
            .expect("Failed to encrypt file");

        return;
    }

    if args.decrypt {
        let file = std::fs::File::open(&args.file_name).unwrap();
        let mut input_stream = BufReader::new(file);

        let output_file = std::fs::File::create(&args.output_file).unwrap();
        let mut output_stream = BufWriter::new(output_file);

        let metadata: FileMetadata = file_crypter
            .decrypt(&mut input_stream, &mut output_stream)
            .expect("Failed to decrypt file");

        println!("File name: {}", metadata.file_name);
        return;
    }

    println!("Hello, world!");
}
