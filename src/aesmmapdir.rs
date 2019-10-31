use rand::{thread_rng, Rng};
use std::fs::File;
use std::io::Error as IoError;
use std::io::{BufWriter, Cursor, ErrorKind, Read, Write};
use std::ops::Deref;
use std::path::Path;

use crypto::aessafe::AesSafe256Encryptor;
use crypto::blockmodes::CtrMode;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::pbkdf2::pbkdf2;
use crypto::sha2::{Sha256, Sha512};
use crypto::symmetriccipher::{Decryptor, Encryptor};

use crate::aesstream::{AesReader, AesWriter};

use tantivy::directory::error::{
    DeleteError, LockError, OpenDirectoryError, OpenReadError, OpenWriteError,
};
use tantivy::directory::Directory;
use tantivy::directory::WatchHandle;
use tantivy::directory::{
    AntiCallToken, DirectoryLock, Lock, ReadOnlySource, TerminatingWrite, WatchCallback, WritePtr,
};

pub struct AesFile<E: crypto::symmetriccipher::BlockEncryptor, M: Mac, W: Write>(
    AesWriter<E, M, W>,
);

type KeyDerivationResult = (Vec<u8>, Vec<u8>, Vec<u8>);

const KEYFILE: &str = "seshat-index.key";
const SALT_SIZE: usize = 16;
const IV_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const MAC_LENGTH: usize = 32;
const VERSION: u8 = 1;
const PBKDF_COUNT: u32 = 1000;

impl<E: crypto::symmetriccipher::BlockEncryptor, M: Mac, W: Write> Write for AesFile<E, M, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl<E: crypto::symmetriccipher::BlockEncryptor, M: Mac, W: Write> TerminatingWrite
    for AesFile<E, M, W>
{
    fn terminate_ref(&mut self, _: AntiCallToken) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl<E: crypto::symmetriccipher::BlockEncryptor, M: Mac, W: Write> Deref for AesFile<E, M, W> {
    type Target = AesWriter<E, M, W>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct AesMmapDirectory {
    mmap_dir: tantivy::directory::MmapDirectory,
    store_key: Vec<u8>,
}

impl AesMmapDirectory {
    pub fn open<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, OpenDirectoryError> {
        let key_path = path.as_ref().join(KEYFILE);
        let mmap_dir = tantivy::directory::MmapDirectory::open(path)?;

        if passphrase.is_empty() {
            return Err(IoError::new(ErrorKind::Other, "empty passphrase").into());
        }

        let key_file = File::open(&key_path);

        let store_key = match key_file {
            Ok(k) => AesMmapDirectory::load_store_key(k, passphrase)?,
            Err(e) => {
                if e.kind() != ErrorKind::NotFound {
                    return Err(e.into());
                }
                AesMmapDirectory::create_new_store(&key_path, passphrase)?
            }
        };

        Ok(AesMmapDirectory {
            mmap_dir,
            store_key,
        })
    }

    fn load_store_key(mut key_file: File, passphrase: &str) -> Result<Vec<u8>, OpenDirectoryError> {
        let mut iv = [0u8; IV_SIZE];
        let mut salt = [0u8; SALT_SIZE];
        let mut expected_mac = [0u8; MAC_LENGTH];
        let mut version = [0u8; 1];
        let mut encrypted_key = vec![];

        // Read our iv, salt and encrypted key from our key file.
        key_file.read_exact(&mut version)?;
        key_file.read_exact(&mut iv)?;
        key_file.read_exact(&mut salt)?;
        key_file.read_exact(&mut expected_mac)?;
        key_file.read_to_end(&mut encrypted_key)?;

        if version[0] != VERSION {
            return Err(IoError::new(ErrorKind::Other, "invalid index store version").into());
        }

        // Rederive our key using the passphrase and salt.
        let (key, hmac_key) = AesMmapDirectory::rederive_key(passphrase, &salt);

        let expected_mac = MacResult::new(&expected_mac);
        let mac =
            AesMmapDirectory::calculate_hmac(version[0], &iv, &salt, &encrypted_key, &hmac_key);

        if mac != expected_mac {
            return Err(IoError::new(ErrorKind::Other, "invalid MAC of the store key").into());
        }

        let algorithm = AesSafe256Encryptor::new(&key);
        let mut decryptor = CtrMode::new(algorithm, iv.to_vec());

        let mut out = [0u8; KEY_SIZE];
        let mut write_buf = RefWriteBuffer::new(&mut out);

        let remaining;
        // Decrypt the encrypted key and return it.
        let res;
        {
            let mut read_buf = RefReadBuffer::new(&encrypted_key);
            res = decryptor
                .decrypt(&mut read_buf, &mut write_buf, true)
                .map_err(|e| {
                    IoError::new(
                        ErrorKind::Other,
                        format!("error decrypting store key: {:?}", e),
                    )
                })?;
            remaining = read_buf.remaining();
        }

        let len = encrypted_key.len();
        encrypted_key.drain(..(len - remaining));

        match res {
            BufferResult::BufferUnderflow => (),
            BufferResult::BufferOverflow => {
                return Err(IoError::new(ErrorKind::Other, "error decrypting store key").into())
            }
        }

        Ok(out.to_vec())
    }

    fn calculate_hmac(
        version: u8,
        iv: &[u8],
        salt: &[u8],
        encrypted_key: &[u8],
        key: &[u8],
    ) -> MacResult {
        let mut hmac = Hmac::new(Sha256::new(), key);
        hmac.input(&[version]);
        hmac.input(&iv);
        hmac.input(&salt);
        hmac.input(&encrypted_key);
        hmac.result()
    }

    fn create_new_store(key_path: &Path, passphrase: &str) -> Result<Vec<u8>, OpenDirectoryError> {
        // Derive a AES key from our passphrase using a randomly generated salt
        // to prevent bruteforce attempts using rainbow tables.
        let (key, hmac_key, salt) = AesMmapDirectory::derive_key(passphrase)?;

        // Generate a random initialization vector for our AES encryptor.
        let iv = AesMmapDirectory::generate_iv()?;
        // Generate a new random store key. This key will encrypt our tantivy
        // indexing files. The key itself is stored encrypted using the derived
        // key.
        let store_key = AesMmapDirectory::generate_key()?;
        // let algorithm = AesSafe128Encryptor::new(&key);
        let algorithm = AesSafe256Encryptor::new(&key);
        let mut encryptor = CtrMode::new(algorithm, iv.clone());

        let mut read_buf = RefReadBuffer::new(&store_key);
        let mut out = [0u8; 1024];
        let mut write_buf = RefWriteBuffer::new(&mut out);
        let mut encrypted_key = Vec::new();

        let mut key_file = File::create(key_path)?;

        // Write down our public salt and iv first, those will be needed to
        // decrypt the key again.
        key_file.write_all(&[VERSION])?;
        key_file.write_all(&iv)?;
        key_file.write_all(&salt)?;

        // Encrypt our key.
        loop {
            let res = encryptor
                .encrypt(&mut read_buf, &mut write_buf, true)
                .map_err(|e| {
                    IoError::new(
                        ErrorKind::Other,
                        format!("unable to encrypt store key: {:?}", e),
                    )
                })?;
            let mut enc = write_buf.take_read_buffer();
            let mut enc = Vec::from(enc.take_remaining());

            encrypted_key.append(&mut enc);

            match res {
                BufferResult::BufferUnderflow => break,
                _ => panic!("Couldn't encrypt the store key"),
            }
        }

        let mac = AesMmapDirectory::calculate_hmac(VERSION, &iv, &salt, &encrypted_key, &hmac_key);
        key_file.write_all(mac.code())?;

        // Write down the encrypted key.
        key_file.write_all(&encrypted_key)?;

        Ok(store_key)
    }

    fn generate_iv() -> Result<Vec<u8>, OpenDirectoryError> {
        let mut iv = vec![0u8; IV_SIZE];
        let mut rng = thread_rng();
        rng.try_fill(&mut iv[..])
            .map_err(|e| IoError::new(ErrorKind::Other, format!("error generating iv: {:?}", e)))?;
        Ok(iv)
    }

    fn generate_key() -> Result<Vec<u8>, OpenDirectoryError> {
        let mut key = vec![0u8; KEY_SIZE];
        let mut rng = thread_rng();
        rng.try_fill(&mut key[..]).map_err(|e| {
            IoError::new(ErrorKind::Other, format!("error generating key: {:?}", e))
        })?;
        Ok(key)
    }

    fn rederive_key(passphrase: &str, salt: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut mac = Hmac::new(Sha512::new(), passphrase.as_bytes());
        let mut pbkdf_result = [0u8; KEY_SIZE * 2];

        pbkdf2(&mut mac, &salt, PBKDF_COUNT, &mut pbkdf_result);
        let (key, hmac_key) = pbkdf_result.split_at(KEY_SIZE);
        (Vec::from(key), Vec::from(hmac_key))
    }

    fn derive_key(passphrase: &str) -> Result<KeyDerivationResult, OpenDirectoryError> {
        let mut rng = thread_rng();
        let mut salt = vec![0u8; SALT_SIZE];
        rng.try_fill(&mut salt[..]).map_err(|e| {
            IoError::new(ErrorKind::Other, format!("error generating salt: {:?}", e))
        })?;

        let (key, hmac_key) = AesMmapDirectory::rederive_key(passphrase, &salt);
        Ok((key, hmac_key, salt))
    }
}

impl Directory for AesMmapDirectory {
    fn open_read(&self, path: &Path) -> Result<ReadOnlySource, OpenReadError> {
        let source = self.mmap_dir.open_read(path)?;

        let decryptor = AesSafe256Encryptor::new(&self.store_key);
        // TODO don't use the same key for Mac as for encryption.
        let mac = Hmac::new(Sha256::new(), &self.store_key);
        let mut reader = AesReader::new(Cursor::new(source.as_slice()), decryptor, mac).unwrap();
        let mut decrypted = Vec::new();

        reader.read_to_end(&mut decrypted).unwrap();

        Ok(ReadOnlySource::from(decrypted))
    }

    fn delete(&self, path: &Path) -> Result<(), DeleteError> {
        self.mmap_dir.delete(path)
    }

    fn exists(&self, path: &Path) -> bool {
        self.mmap_dir.exists(path)
    }

    fn open_write(&mut self, path: &Path) -> Result<WritePtr, OpenWriteError> {
        let file = match self.mmap_dir.open_write(path)?.into_inner() {
            Ok(f) => f,
            Err(e) => panic!(e.to_string()),
        };

        let encryptor = AesSafe256Encryptor::new(&self.store_key);
        let mac = Hmac::new(Sha256::new(), &self.store_key);
        let writer = AesWriter::new(file, encryptor, mac).unwrap();
        let file = AesFile(writer);
        Ok(BufWriter::new(Box::new(file)))
    }

    fn atomic_read(&self, path: &Path) -> Result<Vec<u8>, OpenReadError> {
        let data = self.mmap_dir.atomic_read(path)?;

        let decryptor = AesSafe256Encryptor::new(&self.store_key);
        let mac = Hmac::new(Sha256::new(), &self.store_key);
        let mut reader = AesReader::new(Cursor::new(data), decryptor, mac).unwrap();
        let mut decrypted = Vec::new();

        reader.read_to_end(&mut decrypted).unwrap();
        Ok(decrypted)
    }

    fn atomic_write(&mut self, path: &Path, data: &[u8]) -> std::io::Result<()> {
        let encryptor = AesSafe256Encryptor::new(&self.store_key);
        let mac = Hmac::new(Sha256::new(), &self.store_key);
        let mut encrypted = Vec::new();
        {
            let mut writer = AesWriter::new(&mut encrypted, encryptor, mac)?;
            writer.write_all(data)?;
        }

        self.mmap_dir.atomic_write(path, &encrypted)
    }

    fn watch(&self, watch_callback: WatchCallback) -> Result<WatchHandle, tantivy::Error> {
        self.mmap_dir.watch(watch_callback)
    }

    fn acquire_lock(&self, lock: &Lock) -> Result<DirectoryLock, LockError> {
        self.mmap_dir.acquire_lock(lock)
    }
}

#[cfg(test)]
use tempfile::tempdir;

#[test]
fn create_new_store_and_reopen() {
    let tmpdir = tempdir().unwrap();
    let dir = AesMmapDirectory::open(tmpdir.path(), "wordpass").expect("Can't create a new store");
    drop(dir);
    let dir =
        AesMmapDirectory::open(tmpdir.path(), "wordpass").expect("Can't open the existing store");
    drop(dir);
    let dir = AesMmapDirectory::open(tmpdir.path(), "password");
    assert!(
        dir.is_err(),
        "Opened an existing store with the wrong passphrase"
    );
}

#[test]
fn create_store_with_empty_passphrase() {
    let tmpdir = tempdir().unwrap();
    let dir = AesMmapDirectory::open(tmpdir.path(), "");
    assert!(
        dir.is_err(),
        "Opened an existing store with the wrong passphrase"
    );
}
