use std::io::{Write, BufWriter, Read, Cursor};
use std::path::{Path};
use std::ops::Deref;

use crypto::aessafe::{AesSafe128Encryptor, AesSafe128Decryptor};
use aesstream::{AesWriter, AesReader};

use tantivy::directory::error::{DeleteError, LockError, OpenReadError, OpenWriteError};
use tantivy::directory::Directory;
use tantivy::directory::WatchHandle;
use tantivy::directory::{DirectoryLock, Lock, ReadOnlySource, WatchCallback, WritePtr, TerminatingWrite, AntiCallToken};
use tantivy::schema::SchemaBuilder;
use tantivy::Index;

pub struct AesFile<E: crypto::symmetriccipher::BlockEncryptor, W: Write> (AesWriter<E, W>);

impl<E: crypto::symmetriccipher::BlockEncryptor, W: Write> Write for AesFile<E, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<E: crypto::symmetriccipher::BlockEncryptor, W: Write> Drop for AesFile<E, W> {
    fn drop(&mut self) {
        self.flush().expect("Cannot flush thing");
    }
}


impl<E: crypto::symmetriccipher::BlockEncryptor, W: Write> TerminatingWrite for AesFile<E, W> {
    fn terminate_ref(&mut self, _: AntiCallToken) -> std::io::Result<()> {
        Ok(())
    }
}

impl<E: crypto::symmetriccipher::BlockEncryptor, W: Write> Deref for AesFile<E, W> {
    type Target = AesWriter<E, W>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}


#[derive(Clone, Debug)]
pub struct AesMmapDirectory {
    mmap_dir: tantivy::directory::MmapDirectory,
    passphrase: String
}

impl AesMmapDirectory {
    pub fn open<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, tantivy::directory::error::OpenDirectoryError> {
        let mmap_dir = tantivy::directory::MmapDirectory::open(path)?;
        Ok(AesMmapDirectory { mmap_dir, passphrase: passphrase.to_string() })
    }
}

impl Directory for AesMmapDirectory {
    fn open_read(&self, path: &Path) -> Result<ReadOnlySource, OpenReadError> {
        let source = self.mmap_dir.open_read(path)?;

        let decryptor = AesSafe128Decryptor::new(self.passphrase.as_bytes());
        let mut reader = AesReader::new(Cursor::new(source.as_slice()), decryptor).unwrap();
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
            Err(e) => panic!(e.to_string())
        };

        let encryptor = AesSafe128Encryptor::new(self.passphrase.as_bytes());
        let writer = AesWriter::new(file, encryptor).unwrap();
        let file = AesFile(writer);
        Ok(BufWriter::new(Box::new(file)))
    }

    fn atomic_read(&self, path: &Path) -> Result<Vec<u8>, OpenReadError> {
        let data = self.mmap_dir.atomic_read(path)?;

        let decryptor = AesSafe128Decryptor::new(self.passphrase.as_bytes());
        let mut reader = AesReader::new(Cursor::new(data), decryptor).unwrap();
        let mut decrypted = Vec::new();

        reader.read_to_end(&mut decrypted).unwrap();
        Ok(decrypted)
    }

    fn atomic_write(&mut self, path: &Path, data: &[u8]) -> std::io::Result<()> {
        let encryptor = AesSafe128Encryptor::new(self.passphrase.as_bytes());
        let mut encrypted = Vec::new();
        {
            let mut writer = AesWriter::new(&mut encrypted, encryptor)?;
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
