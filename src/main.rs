use clap::Parser;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

mod cracker;

use cracker::analyze;

#[derive(Parser)]
#[command(version)]
/// HashNebula, Password Hash searcher
struct Config {
    /// Password lists file
    file: String,
}

fn get_input_hash() -> String {
    let mut password_hash = String::new();
    print!("🗝️  Paste Password Hash: ");
    io::stdout().flush().unwrap();
    io::stdin()
        .read_line(&mut password_hash)
        .expect("Failed to read line");
    let password_hash = password_hash.trim();
    password_hash.to_string()
}

fn main() {
    let config = Config::parse();
    let path = Path::new(&config.file);
    match File::open(path) {
        Ok(mut file) => {
            let mut file_data = String::new();
            if let Err(e) = file.read_to_string(&mut file_data) {
                eprintln!("Error: {e}");
            } else {
                let password_hash = get_input_hash();
                analyze(&file_data, &password_hash);
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}
