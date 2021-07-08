#![allow(non_snake_case)]

macro_rules! impl_to_le_bytes {
    ($type:ty) => {
        impl From<$type> for Cryptor {
            fn from(val: $type) -> Self {
                Self {
                    byte_data: val.to_le_bytes().to_vec(),
                }
            }
        }
    };
}

pub mod cryptor {

    use std::fmt::{Display, Formatter};
    use std::io::{BufReader, Read, Write};
    use std::iter::FromIterator;

    use crate::rng_functions::RngFunctions;
    use std::fs::File;
    use std::path::PathBuf;

    #[derive(Debug)]
    pub enum CryptorError {
        ParseError,
        NotSameSize,
        NotValid,
    }
    impl Display for CryptorError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match *self {
                CryptorError::ParseError => write!(f, "Parse error. Please use correct input"),
                CryptorError::NotValid => write!(
                    f,
                    "Invalid binary string. Use eight-bit formatted binary input"
                ),
                CryptorError::NotSameSize => {
                    write!(f, "Invalid input. Key and Cipher must be equal size")
                }
            }
        }
    }

    #[derive(Debug)]
    pub struct Cryptor {
        byte_data: Vec<u8>,
    }

    impl Cryptor {
        pub fn len(&self) -> usize {
            self.byte_data.len()
        }

        pub fn encrypt(&self, rng: RngFunctions) -> Result<(Self, Self), CryptorError> {
            let key = rng.generate(self.len());
            if key.len() == self.len() {
                let ciphertext: Cryptor = key
                    .byte_data
                    .iter()
                    .zip(self.byte_data.iter())
                    .map(|x| x.0 ^ x.1)
                    .collect();
                Ok((key, ciphertext))
            } else {
                Err(CryptorError::NotSameSize)
            }
        }

        pub fn decrypt(&self, key: Cryptor) -> Result<Self, CryptorError> {
            if key.len() == self.len() {
                let message: Cryptor = self
                    .byte_data
                    .iter()
                    .zip(key.byte_data.iter())
                    .map(|val| val.1 ^ val.0)
                    .collect();
                Ok(message)
            } else {
                Err(CryptorError::NotSameSize)
            }
        }

        pub fn to_binary_string(&self) -> String {
            self.byte_data
                .iter()
                .map(|s| format!("{:08b}", *s))
                .collect()
        }

        pub fn to_utf8_string(&self) -> Result<&str, CryptorError> {
            std::str::from_utf8(self.byte_data.as_slice()).map_err(|_s| CryptorError::ParseError)
            // String::from_utf8 does samething but needs consumable Vec<u8>
            //std::str::from_utf8 needs u8 slice. So we don't need to consume or mutate self's vector.
        }

        pub fn from_file(path: &PathBuf) -> Result<Self, std::io::Error> {
            let open_file = File::open(path)?;
            let mut reader = BufReader::new(open_file);
            let mut content: Vec<u8> = Vec::new();
            reader
                .read_to_end(&mut content)
                .map_or_else(|e| Err(e), |_| Ok(Self::from(content)))
        }

        //it overwrites if file exists
        pub fn write_to_file(&self, path: &PathBuf) -> Result<(), std::io::Error> {
            let mut file = File::create(path)?;
            file.write_all(self.byte_data.as_slice())?;

            Ok(())
        }

        pub fn from_binary_string(mut val: String) -> Result<Self, CryptorError> {
            /*
            Ex.case: "ali".

            1. 01100001 01101100 01101001 veya 011000010110110001101001
            2.  ["01100001","01101100","01101001"]
            3. [97, 108, 105]
            4. ali.as_bytes() : [97, 108, 105]

            */
            val.retain(|s| !s.is_whitespace());
            if val.len() % 8 == 0 {
                if val.bytes().all(|s| s == b'1' || s == b'0') {
                    let to_sekizerli_string: Vec<String> = val
                        .as_bytes()
                        .chunks_exact(8)
                        .map(|s| {
                            s.into_iter()
                                .map(|s| match *s {
                                    b'1' => "1",
                                    b'0' => "0",
                                    _ => panic!("lel"),
                                })
                                .collect::<String>()
                        })
                        .collect();

                    let to_u8_vec: Result<Cryptor, CryptorError> = to_sekizerli_string
                        .into_iter()
                        .map(|s| {
                            u8::from_str_radix(s.as_str(), 2).map_err(|_| CryptorError::ParseError)
                        })
                        .collect();

                    to_u8_vec
                } else {
                    Err(CryptorError::NotValid)
                }
            } else {
                Err(CryptorError::NotValid)
            }
        }
    }
    impl_to_le_bytes!(i8);
    impl_to_le_bytes!(i16);
    impl_to_le_bytes!(i32);
    impl_to_le_bytes!(i64);
    impl_to_le_bytes!(i128);
    impl_to_le_bytes!(isize);
    impl_to_le_bytes!(u8);
    impl_to_le_bytes!(u16);
    impl_to_le_bytes!(u32);
    impl_to_le_bytes!(u64);
    impl_to_le_bytes!(u128);
    impl_to_le_bytes!(usize);
    impl_to_le_bytes!(f32);
    impl_to_le_bytes!(f64);
    impl From<String> for Cryptor {
        fn from(val: String) -> Self {
            Self {
                byte_data: val.as_bytes().to_vec(),
            }
        }
    }
    impl From<&String> for Cryptor {
        fn from(val: &String) -> Self {
            Self {
                byte_data: val.as_bytes().to_vec(),
            }
        }
    }

    impl From<&str> for Cryptor {
        fn from(val: &str) -> Self {
            Self {
                byte_data: val.as_bytes().to_vec(),
            }
        }
    }

    impl<T: Into<Cryptor>> From<Vec<T>> for Cryptor {
        fn from(val: Vec<T>) -> Self {
            val.into_iter()
                .map(|s| s.into().into_iter().map(|s| s))
                .flatten()
                .collect()
        }
    }

    // we need Clone trait to convert slice to heap based vector.
    // It does copying stack based &[T] slice.
    impl<T: Into<Cryptor> + Clone> From<&[T]> for Cryptor {
        fn from(val: &[T]) -> Self {
            val.iter()
                .map(|s| s.clone().into().into_iter().map(|s| s))
                .flatten()
                .collect()
        }
    }

    impl FromIterator<u8> for Cryptor {
        // "I" needs to have IntoIterator<Item=u8> trait, collect() has it.
        fn from_iter<I: IntoIterator<Item = u8>>(iter: I) -> Self {
            let mut fill: Vec<u8> = Vec::new();
            for i in iter {
                fill.push(i)
            }
            Self { byte_data: fill }
        }
    }

    impl Into<Vec<u8>> for Cryptor {
        fn into(self) -> Vec<u8> {
            self.byte_data
        }
    }

    impl IntoIterator for Cryptor {
        type Item = u8;
        type IntoIter = std::vec::IntoIter<Self::Item>;

        fn into_iter(self) -> Self::IntoIter {
            self.byte_data.into_iter()
        }
    }
}

pub mod rng_functions {
    use crate::cryptor::Cryptor;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rand_hc::Hc128Rng;
    use rand_xoshiro::Xoshiro256PlusPlus;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug)]
    pub enum RngFunctions {
        Xoshiro256,
        Xoshiro256Crg(u64),
        Xoshiro256T,
        HC128,
        HC128Crg(u64),
        HC128T,
        Chacha20,
        Chacha20Crg(u64),
        Chacha20T,
    }

    impl RngFunctions {
        pub fn generate(&self, len: usize) -> Cryptor {
            match self {
                RngFunctions::Xoshiro256 => self::xoshiro_256(len),
                RngFunctions::Xoshiro256Crg(t) => self::xoshiro_256_crng(len, *t),
                RngFunctions::Xoshiro256T => self::xoshiro_256_t(len),
                RngFunctions::HC128 => self::hc_128(len),
                RngFunctions::HC128Crg(t) => self::hc_128_crng(len, *t),
                RngFunctions::HC128T => self::hc_128_t(len),
                RngFunctions::Chacha20 => self::chacha_20(len),
                RngFunctions::Chacha20Crg(t) => self::chacha_20_crng(len, *t),
                RngFunctions::Chacha20T => self::chacha_20_t(len),
            }
        }
    }

    /*
    Also, works:

    #[derive(Debug)]
    pub enum RngFunctions {
        Xoshiro256(usize),
        HC128(usize),
        Chacha20(usize)
    }

    impl RngFunctions {
        pub fn generate(&self) -> Cryptor {
            match self {
                RngFunctions::Xoshiro256(t) => self::xoshiro_256(*t),
                RngFunctions::HC128(t) => self::hc_128(*t),
                RngFunctions::Chacha20(t) => self::chacha_20(*t)
            }
        }
    }
    */

    fn xoshiro_256(len: usize) -> Cryptor {
        let mut rand_xoshiro = Xoshiro256PlusPlus::from_entropy();
        (0..len).map(|_| rand_xoshiro.gen()).collect()
    }
    fn xoshiro_256_crng(len: usize, crng: u64) -> Cryptor {
        let mut rand_xoshiro = Xoshiro256PlusPlus::seed_from_u64(crng);
        (0..len).map(|_| rand_xoshiro.gen()).collect()
    }
    fn xoshiro_256_t(len: usize) -> Cryptor {
        let utime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        xoshiro_256_crng(len, utime)
    }

    fn hc_128(len: usize) -> Cryptor {
        let mut hc_rand = Hc128Rng::from_entropy();
        (0..len).map(|_| hc_rand.gen()).collect()
    }
    fn hc_128_crng(len: usize, crng: u64) -> Cryptor {
        let mut hc_rand = Hc128Rng::seed_from_u64(crng);
        (0..len).map(|_| hc_rand.gen()).collect()
    }
    fn hc_128_t(len: usize) -> Cryptor {
        let utime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        hc_128_crng(len, utime)
    }

    fn chacha_20(len: usize) -> Cryptor {
        let mut chacha = ChaCha20Rng::from_entropy();
        (0..len).map(|_| chacha.gen()).collect()
    }
    fn chacha_20_crng(len: usize, crng: u64) -> Cryptor {
        let mut chacha = ChaCha20Rng::seed_from_u64(crng);
        (0..len).map(|_| chacha.gen()).collect()
    }
    fn chacha_20_t(len: usize) -> Cryptor {
        let utime = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        chacha_20_crng(len, utime)
    }
}

pub mod arg_parser {
    use std::path::PathBuf;
    use structopt::{clap::ArgGroup, StructOpt};

    #[derive(Debug, StructOpt, PartialEq)]
    #[structopt(name = "ONE HOT MAPPER",
    group = ArgGroup::with_name("file_or_string").required(true),
    author = "Can Eroglu, can.eroglu@outlook.com",
    version = "v0.1.0",
    about = "\nCryptographically secure one-hot encryptor for files and personal messages.",
    after_help ="One-hot encoding is only scientifically proven unbreakable encoding method.It needs equal length key for encryption.
\n\
Example usages:\n\
\tencode <message>\n\
\tencode <message> -s 42\n\
\tencode -f [PATH]\n\
\tdecode <ciphertext> -k <key>\n\
\tdecode -f [CIPHER_PATH] [KEY_PATH]\
\n
For more information use --help")]

    // App:ArgGroup: "Syntax must have at least one of this arguments(required(true)). There can't be two of them simultaneously"
    pub struct Opt {
        /// Choice of encryption.
        #[structopt(name = "choice",possible_values(&["encode","decode"]),index = 1)]
        pub choice: String,

        /// Plaintext(for encryption) or Ciphertext(for decryption)
        ///
        /// Texts must be valid UTF-8.
        ///
        /// It's default mode unless file option chosen.
        #[structopt(name = "input", group = "file_or_string", short = "")]
        pub i_string: Option<Vec<String>>,

        /// Key(for string - decryption)
        #[structopt(name = "key", requires("input"), short = "k", long = "key")]
        pub e_string: Option<Vec<String>>,

        ///
        /// Switch to file mode
        #[structopt(
            name = "file",
            short = "f",
            long = "file",
            max_values(2),
            group = "file_or_string",
            parse(from_os_str)
        )]
        pub file: Option<Vec<PathBuf>>,

        /// Set custom seed for cRNG.
        ///
        /// CAUTION!: Use strong and long positive integer.(Prefer 64 bits)
        /// You can enter "t" for use UNIX time as seed.
        #[structopt(name = "random", short = "s", long = "seed", validator(validate_t))]
        pub crng: Option<String>,

        /// Save to file
        /// It saves output at current PATH.
        #[structopt(name = "output", short = "o", long = "out")]
        pub output: Option<PathBuf>,

        /// Program uses Xoshiro256PlusPlus with entropy as default.
        ///
        /// It's not cryptographically secure algorithm but for most cases it can be accepted as secure and fast.
        ///
        /// You can use different algorithm for better protection but slower.

        #[structopt(name = "custom-algor", short = "a", long = "algorithm", possible_values(&["hc128","chacha20"]),case_insensitive=false)]
        pub algorithm: Option<String>,
    }
    fn validate_t(v: String) -> Result<(), String> {
        if v.eq_ignore_ascii_case("t") {
            return Ok(());
        } else {
            let parse = v.parse::<u64>();
            match parse {
                Ok(_T) => {
                    println!("it can be parsed!");
                    Ok(())
                }
                Err(_E) => Err("Invalid digit!".to_string()),
            }
        }
    }
}
