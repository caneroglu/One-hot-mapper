#![allow(non_snake_case)]
use main_lib::arg_parser::Opt;
use main_lib::cryptor::Cryptor;
use main_lib::rng_functions::RngFunctions;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use structopt::StructOpt;


macro_rules! show_error {
    ($msg:expr) => {
        eprintln!("error: {}.", $msg)
    };
}

macro_rules! encrypt_string {
    ($i_string: expr,$alg: expr) => {{
        match Cryptor::from($i_string).encrypt($alg) {
            Ok(T) => {
                println!("Input: {}", $i_string);
                println!("Key: {}", T.0.to_binary_string());
                println!("Cipher: {}", T.1.to_binary_string());
            }
            Err(E) => {
                show_error!(E)
            }
        }
    }};
    //with -o
    ($i_string: expr,$alg: expr,$output_path: expr) => {{
        match Cryptor::from($i_string).encrypt($alg) {
            Ok(T) => {
                let report = format!(
                    "Message: {}\nKey: {}\nCipher: {}",
                    $i_string,
                    T.0.to_binary_string(),
                    T.1.to_binary_string()
                );
                match write_to_file($output_path, report.as_bytes()) {
                    Ok(_) => {
                        println!("Success.Output has saved.")
                    }
                    Err(E) => {
                        show_error!(E)
                    }
                }
            }
            Err(E) => {
                show_error!(E)
            }
        }
    }};
}

macro_rules! encrypt_file {
    ($file_path: expr, $alg: expr) => { {
        // Since we know it has Some value it's safe to call unwrap.
            // Also we just saving a file, so it doesn't matter. OS could accept non-UTF8 symbols at path.
            let file_path = $file_path.first().unwrap();
            let message_file = &*file_path.to_string_lossy();
            let key_path = PathBuf::from(format!("{}.{}",message_file,"keyfile"));
            let cipher_path = PathBuf::from(format!("{}.{}",message_file,"cipherfile"));

            let result = Cryptor::from_file(file_path);
            match result {
                Ok(T) => {
                    match T.encrypt($alg) {
                        Ok(T) => {
                            match T.0.write_to_file(&key_path).and(T.1.write_to_file(&cipher_path)) {
                                Ok(_) => {
                                    println!("Success: key and cipher files are saved at plain file's path.")
                                }
                                Err(E) => {
                                    show_error!(E)
                                }
                            }
                        }
                        Err(E) => {
                            show_error!(E)
                        }
                    }
                },
                Err(E) => {
                    show_error!(E)
                }
            }
    }};
    ($file_path: expr, $alg: expr,$output: expr) => {{
           // Since we know it has Some value it's safe to call unwrap.
            // Also we just saving a file, so it doesn't matter. OS could accept non-UTF8 symbols at path.
            let file_path = $file_path.first().unwrap();
            let output_file_name = $output.to_string_lossy();


            let key_path = PathBuf::from(format!("{}.{}",&*output_file_name,"keyfile"));
            let cipher_path = PathBuf::from(format!("{}.{}",&*output_file_name,"cipherfile"));

            let result = Cryptor::from_file(file_path);
            match result {
                Ok(T) => {
                    match T.encrypt($alg) {
                        Ok(T) => {
                            match T.0.write_to_file(&key_path).and(T.1.write_to_file(&cipher_path)) {
                                Ok(_) => {
                                    println!("Success: key and cipher files are saved at specified path.")
                                }
                                Err(E) => {
                                    show_error!(E)
                                }
                            }
                        }
                        Err(E) => {
                            show_error!(E)
                        }
                    }
                },
                Err(E) => {
                    show_error!(E)
                }
            }
    }}
}
#[allow(non_camel_case_types)]
macro_rules! encrypt_parse {
    ($args: expr,$alg: expr) => {{
        let helper_fn = |parameter: &str, seed: u64| {
            match $alg {
                RngFunctions::Xoshiro256 => match parameter {
                    "t" => RngFunctions::Xoshiro256T,
                    "crg" => RngFunctions::Xoshiro256Crg(seed),
                    _ => RngFunctions::Xoshiro256,
                },
                RngFunctions::HC128 => match parameter {
                    "t" => RngFunctions::HC128T,
                    "crg" => RngFunctions::HC128Crg(seed),
                    _ => RngFunctions::HC128,
                },
                RngFunctions::Chacha20 => match parameter {
                    "t" => RngFunctions::Chacha20T,
                    "crg" => RngFunctions::Chacha20Crg(seed),
                    _ => RngFunctions::Chacha20,
                },
                //this branch won't execute
                _ => std::panic::panic_any(DEFAULT_ERROR),
            }
        };
        // check if its file or string
        match $args {
            // it's string
            Opt {
                i_string: Some(ref i_string),
                e_string: None,
                file: None,
                ..
            } => {
                let i_string = i_string.join(" ");

                // check for -s parameter
                match $args.crng {
                    // -s <seed>
                    // encode test -a hc128 -s <seed>
                    Some(ref seed) => {
                        // check for output parameter
                        match $args.output {
                            // -o <output_path>
                            Some(output_path) => {
                                // encode test -a $alg -s t -o <outputh_path>
                                if seed.eq_ignore_ascii_case("t") {
                                    encrypt_string!(&i_string, helper_fn("t", 0), &output_path)
                                    // encode test -a $alg -s <seed> -o <outputh_path>
                                } else {
                                    encrypt_string!(
                                        &i_string,
                                        helper_fn("crg", seed.parse().unwrap()),
                                        &output_path
                                    )
                                }
                            }
                            None => {
                                // encode test -a $alg -s t
                                if seed.eq_ignore_ascii_case("t") {
                                    encrypt_string!(&i_string, helper_fn("t", 0))
                                    // encode test -a $alg -s <seed>
                                } else {
                                    encrypt_string!(
                                        &i_string,
                                        helper_fn("crg", seed.parse().unwrap())
                                    )
                                }
                            }
                        }
                    }
                    // No seed, full auto
                    // encode test -a $alg
                    None => {
                        // check for output parameter
                        match $args.output {
                            // -o <output_path>
                            Some(output_path) => {
                                // encode test -a $alg -o <outputh_path>
                                encrypt_string!(&i_string, helper_fn("", 0), &output_path);
                            }
                            None => {
                                // encode test -a $alg
                                encrypt_string!(&i_string, helper_fn("", 0))
                            }
                        }
                    }
                }
            }
            //it's file
            Opt {
                i_string: None,
                e_string: None,
                file: Some(file),
                ..
            } if file.len() == 1 => {
                // check for -s parameter
                match $args.crng {
                    // -s <seed>
                    // encode -f <file_path> -a $alg -s <seed>
                    Some(ref seed) => {
                        // check for output parameter
                        match $args.output {
                            // -o <output_path>
                            Some(output_path) => {
                                // encode -f <file_path> -a $alg -s t -o <outputh_path>
                                if seed.eq_ignore_ascii_case("t") {
                                    encrypt_file!(file, helper_fn("t", 0), &output_path)

                                    // encode -f <file_path> -a $alg -s <seed> -o <outputh_path>
                                } else {
                                    encrypt_file!(
                                        file,
                                        helper_fn("crg", seed.parse().unwrap()),
                                        &output_path
                                    )
                                }
                            }
                            None => {
                                // encode test -a $alg -s t
                                if seed.eq_ignore_ascii_case("t") {
                                    encrypt_file!(file, helper_fn("t", 0))
                                    // encode test -a $alg -s <seed>
                                } else {
                                    encrypt_file!(file, helper_fn("crg", seed.parse().unwrap()))
                                }
                            }
                        }
                    }
                    // No seed, full auto
                    // encode test -a $alg
                    None => {
                        // check for output parameter
                        match $args.output {
                            // -o <output_path>
                            // encode -f <file_path> -a $alg -o <outputh_path>
                            Some(output_path) => {
                                encrypt_file!(file, helper_fn("", 0), &output_path)
                            }
                            // encode -f <file_path> -a $alg
                            None => {
                                encrypt_file!(file, helper_fn("", 0))
                            }
                        }
                    }
                }
            }
            _ => {
                show_error!(DEFAULT_ERROR)
            }
        }
    }};
}

const DEFAULT_ERROR: &str = "Invalid syntax. Please use -h for help";
#[allow(non_camel_case_types)]
fn main() {
    let args = Opt::from_args();

    match &*args.choice {
        "encode" => {
            match args.algorithm {
                Some(ref al) if al.eq_ignore_ascii_case("hc128") => {
                    encrypt_parse!(args, RngFunctions::HC128)
                }
                Some(ref al) if al.eq_ignore_ascii_case("chacha20") => {
                    encrypt_parse!(args, RngFunctions::Chacha20)
                }

                // Xoshiro branch
                _ => {
                    encrypt_parse!(args, RngFunctions::Xoshiro256)
                }
            }
        }
        "decode" => {
            match args {
                //string decrypt
                Opt {
                    i_string: Some(i_string),
                    e_string: Some(e_string),
                    file: None,
                    ..
                } => {
                    match args.output {
                        Some(output_path) => {
                            let ciphertext = Cryptor::from_binary_string(i_string.concat());
                            let key = Cryptor::from_binary_string(e_string.concat());

                            // We do little trolling.
                            ciphertext.map_or_else(|e|show_error!(e),
                                                   |cipher| key.map_or_else(|e|show_error!(e),|key|
                                                       cipher.decrypt(key).map_or_else(|e|show_error!(e),|t|
                                                           t.to_utf8_string().map_or_else(|e|show_error!(e),|t|
                                                               write_to_file(&output_path,t.as_bytes()).map_or_else(|e|show_error!(e),|_|println!("Success: message decrypted and saved at specified path."))
                                                           ))));
                        }
                        None => {
                            let ciphertext = Cryptor::from_binary_string(i_string.concat());
                            let key = Cryptor::from_binary_string(e_string.concat());

                            // We do little trolling.
                            ciphertext.map_or_else(
                                |e| show_error!(e),
                                |cipher| {
                                    key.map_or_else(
                                        |e| show_error!(e),
                                        |key| {
                                            cipher.decrypt(key).map_or_else(
                                                |e| show_error!(e),
                                                |t| {
                                                    t.to_utf8_string().map_or_else(
                                                        |e| show_error!(e),
                                                        |t| println!("Message: {}", t),
                                                    )
                                                },
                                            )
                                        },
                                    )
                                },
                            );
                        }
                    }
                }
                //file decrypt
                Opt {
                    file: Some(file),
                    i_string: None,
                    e_string: None,
                    ..
                } if file.len() == 2 => match args.output {
                    Some(output_path) => {
                        let cipher_file = Cryptor::from_file(file.first().unwrap());
                        let key_file = Cryptor::from_file(file.get(1).unwrap());

                        cipher_file.map_or_else(|cipher_err|show_error!(cipher_err),|cipher_file|
                                key_file.map_or_else(|key_err|show_error!(key_err),|key_file|
                                    cipher_file.decrypt(key_file).map_or_else(|err|show_error!(err),|result|
                                        result.write_to_file(&output_path).map_or_else(|io_err|show_error!(io_err), |_| println!("Success: file decrypted. Saved at specified path."))
                                    )));
                    }
                    None => {
                        let cipher_file = Cryptor::from_file(file.first().unwrap());
                        let key_file = Cryptor::from_file(file.get(1).unwrap());
                        let message_file_path = PathBuf::from(format!("{}.{}",&*file.first().unwrap().to_string_lossy(),"decrypted"));

                        cipher_file.map_or_else(|cipher_err|show_error!(cipher_err),|cipher_file|
                                key_file.map_or_else(|key_err|show_error!(key_err),|key_file|
                                    cipher_file.decrypt(key_file).map_or_else(|err|show_error!(err),|result|
                                        result.write_to_file(&message_file_path).map_or_else(|io_err|show_error!(io_err), |_| println!("Success: file decrypted. Saved at cipher's path."))
                                    )));
                    }
                },
                _ => {
                    show_error!(DEFAULT_ERROR)
                }
            }
        }
        _ => {
            show_error!(DEFAULT_ERROR)
        }
    }
}

fn write_to_file(path: &PathBuf, data: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    Ok(())
}
