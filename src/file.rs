use std::path::PathBuf;
use std::fs::OpenOptions;
use std::collections::HashMap;
use std::io::{Write, Read};

pub type CryptData = HashMap<String, String>;

pub type LockedCrypt = CryptFile<LockedFile>;

pub type UnlockedCrypt = CryptFile<UnlockedFile>;

mod encryption {
    use rand::Rng;
    use aes::Aes256;
    use block_modes::{BlockMode, Cbc};
    use block_modes::block_padding::Pkcs7;

    const KEY_LEN: usize = 32;
    const IV_LEN: usize = 16;
    const SALT_LEN: usize = 16;
    const SECRET_LEN: usize = 128;

    type Salt = [u8; SALT_LEN];
    type Secret = [u8; SECRET_LEN];
    type Key = [u8; KEY_LEN];

    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    #[derive(Debug)]
    pub enum Error {
        DeriveKey(argonautica::Error),
        InvalidKeyLength(block_modes::InvalidKeyIvLength),
    }

    impl From<argonautica::Error> for Error {
        fn from(error: argonautica::Error) -> Self {
            Self::DeriveKey(error)
        }
    }

    impl From<block_modes::InvalidKeyIvLength> for Error {
        fn from(error: block_modes::InvalidKeyIvLength) -> Self {
            Self::InvalidKeyLength(error)
        }
    }

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{:?}", &self)
        }
    }

    impl std::error::Error for Error {}

    #[inline]
    fn random_bytes<const LEN: usize>() -> [u8; LEN] {
        let mut rng = rand::thread_rng();
        let mut bytes = [0_u8; LEN];
        rng.fill(&mut bytes[..]);
        bytes
    }

    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    fn recover_key(password: &str, salt: &[u8], secret: &[u8]) -> Result<Key, Error> {
        use argonautica::Hasher;

        let mut hasher = Hasher::new();
        hasher.configure_hash_len(KEY_LEN as u32);

        let key = hasher.with_password(password)
            .with_salt(salt)
            .with_secret_key(secret)
            .hash_raw()?;
        let mut key_bytes = [0_u8; KEY_LEN];
        key_bytes.copy_from_slice(key.raw_hash_bytes());
        Ok(key_bytes)
    }

    #[inline]
    fn create_key(password: &str) -> Result<(Salt, Secret, Key), Error> {
        let salt = random_bytes::<SALT_LEN>();
        let secret = random_bytes::<SECRET_LEN>();

        let key = recover_key(password, &salt, &secret)?;
        Ok((salt, secret, key))
    }

    #[inline]
    pub fn encrypt_slice(password: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
        let (salt, secret, key) = create_key(password)?;
        let iv = random_bytes::<IV_LEN>();

        let cipher = Aes256Cbc::new_from_slices(&key[..], &iv[..])?;

        let encrypted = cipher.encrypt_vec(data);
        let mut result = Vec::<u8>::with_capacity(encrypted.len() + SALT_LEN + SECRET_LEN + IV_LEN);
        result.extend_from_slice(&salt[..]);
        result.extend_from_slice(&secret[..]);
        result.extend_from_slice(&iv[..]);
        result.extend_from_slice(encrypted.as_slice());
        Ok(result)
    }

    #[inline]
    pub fn decrypt_slice(password: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
        const SALT_START: usize = 0;
        const SECRET_START: usize = SALT_START + SALT_LEN;
        const IV_START: usize = SECRET_START + SECRET_LEN;
        const DATA_START: usize = IV_START + IV_LEN;

        let salt = &data[SALT_START..SECRET_START];
        let secret = &data[SECRET_START..IV_START];
        let iv = &data[IV_START..DATA_START];
        let encrypted = &data[DATA_START..];

        let key = recover_key(password, salt, secret)?;

        let cipher = Aes256Cbc::new_from_slices(&key[..], iv)?;
        Ok(cipher.decrypt_vec(encrypted).unwrap())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn create_and_recover_key() {
            let password = "abc123 PAssWORd!";
            let (salt, secret, key) = create_key(password).unwrap();
            {
                let recovered_key = recover_key(password, &salt, &secret).unwrap();
                assert_eq!(recovered_key, key);
            }
            {
                let recovered_key = recover_key(password, &salt[..], &secret[..]).unwrap();
                assert_eq!(recovered_key, key);
            }
        }

        #[test]
        fn encrypt_and_decrypt() {
            let password = "abc123 PAssWORd!";
            let data = "ABCabc123!\"£";
            let encrypted = encrypt_slice(password, data.as_bytes()).unwrap();
            let decrypted = decrypt_slice(password, encrypted.as_slice()).unwrap();
            assert_eq!(decrypted.as_slice(), data.as_bytes());
        }
    }
}

pub use encryption::Error as EncryptError;

#[derive(Debug)]
pub enum CryptFileError {
    Encrypt(EncryptError),
    Io(std::io::Error),
    Bincode(bincode2::Error),
}

impl From<EncryptError> for CryptFileError {
    fn from(error: EncryptError) -> Self {
        Self::Encrypt(error)
    }
}

impl From<std::io::Error> for CryptFileError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<bincode2::Error> for CryptFileError {
    fn from(error: bincode2::Error) -> Self {
        Self::Bincode(error)
    }
}

impl std::fmt::Display for CryptFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl std::error::Error for CryptFileError {}

pub trait State {}

pub struct LockedFile;

impl State for LockedFile {}

pub struct UnlockedFile {
    data: CryptData,
}

impl State for UnlockedFile {}

pub struct CryptFile<S> {
    filepath: PathBuf,
    state: S,
}

impl<S> CryptFile<S> {
    pub fn filepath(&self) -> &PathBuf {
        &self.filepath
    }
}

impl CryptFile<LockedFile> {
    #[must_use]
    pub fn new(filepath: PathBuf) -> Self {
        Self { filepath, state: LockedFile }
    }

    // TODO: Change error to match lock()
    pub fn unlock(self, password: &str) -> Result<CryptFile<UnlockedFile>, CryptFileError> {
        let Self { filepath, .. } = self;
        if !filepath.exists() {
            return Ok(CryptFile { filepath, state: UnlockedFile { data: HashMap::new() } });
        }
        let mut file = OpenOptions::new().read(true).open(&filepath)?;
        let mut encrypted = Vec::new();
        file.read_to_end(&mut encrypted)?;
        let decrypted = encryption::decrypt_slice(password, encrypted.as_slice())?;
        let data = bincode2::deserialize(decrypted.as_slice())?;
        Ok(CryptFile { filepath, state: UnlockedFile { data } })
    }
}

impl CryptFile<UnlockedFile> {
    pub fn lock(self, password: &str) -> Result<CryptFile<LockedFile>, (CryptFile<UnlockedFile>, CryptFileError)> {
        let data = match bincode2::serialize(&self.state.data) {
            Ok(data) => data,
            Err(error) => {
                return Err((self, error.into()));
            }
        };
        let encrypted = match encryption::encrypt_slice(password, data.as_slice()) {
            Ok(encrypted) => encrypted,
            Err(error) => {
                return Err((self, error.into()));
            }
        };
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&self.filepath);
        let mut file = match file {
            Ok(file) => file,
            Err(error) => {
                return Err((self, error.into()));
            }
        };
        match file.write_all(encrypted.as_slice()) {
            Ok(_) => {}
            Err(error) => {
                return Err((self, error.into()));
            }
        }
        Ok(CryptFile { filepath: self.filepath, state: LockedFile })
    }

    #[must_use]
    pub fn data(&self) -> &CryptData {
        &self.state.data
    }

    pub fn data_mut(&mut self) -> &mut CryptData {
        &mut self.state.data
    }
}
