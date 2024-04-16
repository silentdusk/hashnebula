use argon2::{
    password_hash::{PasswordHash, PasswordVerifier},
    Argon2,
};
use bcrypt::verify;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::iter::{IntoParallelIterator, ParallelIterator};

#[derive(PartialEq)]
enum HashType {
    Argon2Hash,
    BCryptHash,
}

fn find_hash_type(hashed_string: &str) -> Option<HashType> {
    let test_password = "test";
    if verify(test_password, hashed_string).is_ok() {
        return Some(HashType::BCryptHash);
    } else if PasswordHash::new(hashed_string).is_ok() {
        return Some(HashType::Argon2Hash);
    }
    None
}

fn compare_bcrypt(hashed_string: &str, target: &str) -> bool {
    if let Ok(value) = verify(target, hashed_string) {
        return value;
    }
    false
}

fn compare_argon2(hashed_string: &str, target: &str) -> bool {
    if let Ok(parsed_hash) = PasswordHash::new(hashed_string) {
        return Argon2::default()
            .verify_password(target.as_bytes(), &parsed_hash)
            .is_ok();
    }
    false
}

// Use bruteforce to iterate over the data and find a match
pub fn analyze(data: &str, hashed_string: &str) {
    if let Some(hash_type) = find_hash_type(hashed_string) {
        let data = data.lines().collect::<Vec<&str>>();
        let password_list_size = data.len() as u64;
        let progress_bar = ProgressBar::new(password_list_size);
        progress_bar.set_style(
        ProgressStyle::with_template(
            "{bar:40.green/blue} {pos:>7}/{len:7} [{elapsed_precise}] [{eta_precise}] [{per_sec}]",
        )
        .expect("Indicatiff Error"),
    );
        progress_bar.inc(0);

        match hash_type {
            HashType::BCryptHash => {
                let result = data.into_par_iter().any(|password| {
                    progress_bar.inc(1);
                    if compare_bcrypt(hashed_string, password) {
                        progress_bar.finish_and_clear();
                        println!("⚡ Match found: {}", password.green());
                        true
                    } else {
                        false
                    }
                });
                if !result {
                    println!("No match found");
                }
            }

            HashType::Argon2Hash => {
                let result = data.into_par_iter().any(|password| {
                    progress_bar.inc(1);
                    if compare_argon2(hashed_string, password) {
                        progress_bar.finish_and_clear();
                        println!("⚡ Match found: {}", password.green());
                        true
                    } else {
                        false
                    }
                });
                if !result {
                    println!("No match found");
                }
            }
        }
    } else {
        println!("Failed to recognize hash");
    }
}
