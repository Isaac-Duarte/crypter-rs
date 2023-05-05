use clap::{Parser, Subcommand};
use file_crypter::FileCrypter;
use openssl::rsa::Rsa;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Seek};
use std::path::PathBuf;
use uuid::Uuid;

extern crate file_crypter;
extern crate glob;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    file_path: PathBuf,

    #[arg(long)]
    private_key: Option<PathBuf>,

    #[arg(long)]
    public_key: Option<PathBuf>,

    #[arg(long)]
    encrypt: bool,

    #[arg(long)]
    decrypt: bool,

    #[arg(long)]
    delete: bool,

    #[arg(long)]
    same_dir: bool,

    #[arg(long, default_value = "4")]
    threads: usize,
}

#[derive(Serialize, Deserialize)]
struct FileMetadata {
    file_name: String,
    file_path: String,
}

fn main() {
    let args = Args::parse();

    if (args.encrypt && args.decrypt) || (!args.encrypt && !args.decrypt) {
        eprintln!("You must specify either --encrypt or --decrypt");
        return;
    }

    let file_crypter;

    if args.public_key.is_none() && args.private_key.is_none() {
        // We'll generate one
        let private_key = Rsa::generate(2048).unwrap();
        let public_key =
            Rsa::public_key_from_pem(private_key.public_key_to_pem().unwrap().as_ref()).unwrap();

        // Write private and public to file
        fs::write("private.pem", private_key.private_key_to_pem().unwrap()).unwrap();
        fs::write("public.pem", public_key.public_key_to_pem().unwrap()).unwrap();

        file_crypter = FileCrypter::decrypter(private_key).expect("Failed to create decrypter");
    } else if args.private_key.is_none() && args.public_key.is_some() {
        let public_key =
            Rsa::public_key_from_pem(&fs::read(args.public_key.unwrap()).unwrap()).unwrap();

        file_crypter = FileCrypter::encrypter(public_key);
    } else {
        let private_key =
            Rsa::private_key_from_pem(&fs::read(args.private_key.unwrap()).unwrap()).unwrap();

        file_crypter = FileCrypter::decrypter(private_key).expect("Failed to create decrypter");
    }

    // Validate the input_path
    if !args.file_path.is_dir() {
        eprintln!("Input path must be a directory");
    }

    let pattern = if args.decrypt { "**/*.enc" } else { "**/*" };

    let files: Vec<PathBuf> = glob::glob(args.file_path.join(pattern).to_str().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .collect();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build()
        .unwrap();

    pool.install(|| {
        files.par_iter().for_each(|path| {
            println!("Processing file: {}", path.to_str().unwrap());
            if path.is_dir() {
                return;
            }

            let file_name = path.file_name().unwrap().to_str().unwrap().to_string();
            let file_path = path.parent().unwrap().to_str().unwrap().to_string();

            let metadata = FileMetadata {
                file_name,
                file_path,
            };

            if args.encrypt {
                println!("Encrypting file: {}", path.to_str().unwrap());

                let file = File::open(&path).unwrap();
                encrypt_file(&file, &metadata, &file_crypter, args.same_dir);
            } else {
                println!("Decrypting file: {}", path.to_str().unwrap());

                let file = File::open(&path).unwrap();
                decrypt_file(&file, &file_crypter);
            }

            if args.delete {
                fs::remove_file(&path).unwrap();
            }
        });
    });

    if args.same_dir && args.encrypt {
        fs::remove_dir_all(args.file_path).unwrap();
    }
}

fn encrypt_file(file: &File, metadata: &FileMetadata, file_crypter: &FileCrypter, same_dir: bool) {
    let mut input_stream = BufReader::new(file);

    // Create the output file of a guid in the same path as the file
    let output_path = PathBuf::from(&metadata.file_path);
    let output_file_name = Uuid::new_v4().to_string();
    let output_file_path;

    if same_dir {
        output_file_path = PathBuf::from(output_file_name + ".enc");
    } else {
        output_file_path = output_path.join(output_file_name + ".enc");
    }

    let output_file = File::create(output_file_path).unwrap();
    let mut output_stream = BufWriter::new(output_file);

    file_crypter
        .encrypt(&mut input_stream, &mut output_stream, &metadata)
        .unwrap();
}

// Function to decrypt file
fn decrypt_file(file: &File, file_crypter: &FileCrypter) {
    let mut input_stream = BufReader::new(file);
    let metadata: FileMetadata = file_crypter.fetch_metadata(&mut input_stream).unwrap();

    input_stream.rewind().unwrap();

    // Create the output file of a guid in the same path as the file
    let output_path = PathBuf::from(&metadata.file_path);
    let output_file_name = metadata.file_name;
    let output_file_path = output_path.join(output_file_name);

    fs::create_dir_all(output_path).unwrap();

    let output_file = File::create(output_file_path).unwrap();
    let mut output_stream = BufWriter::new(output_file);

    let _: FileMetadata = file_crypter
        .decrypt(&mut input_stream, &mut output_stream)
        .unwrap();
}
