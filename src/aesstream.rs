// Copyright (c) 2015 The adb-remote-control Developers

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// This file originates from the rust-aes-stream repo[1], it has been moddified
// to include authentication for the encrypted files.
// [1] https://github.com/oberien/rust-aes-stream/

//! Read/Write Wrapper for AES Encryption and Decryption during I/O Operations
//!
use std::io::{Read, Write, Seek, SeekFrom, Result, Error, ErrorKind};

use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor, Encryptor, Decryptor};
use crypto::blockmodes::{PkcsPadding, CtrMode, CbcEncryptor, CbcDecryptor, EncPadding, DecPadding};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer, BufferResult, WriteBuffer, ReadBuffer};
use rand::{thread_rng, Rng};

const BUFFER_SIZE: usize = 8192;

/// Wraps a [`Write`](https://doc.rust-lang.org/std/io/trait.Write.html) implementation with CBC
/// based on given [`BlockEncryptor`][be]
///
/// [be]: https://docs.rs/rust-crypto/0.2.36/crypto/symmetriccipher/trait.BlockEncryptor.html
///
pub struct AesWriter<E: BlockEncryptor, W: Write> {
    /// Writer to write encrypted data to
    writer: Option<W>,
    /// Encryptor to encrypt data with
    enc: CtrMode<E>,
}

impl<E: BlockEncryptor, W: Write> AesWriter<E, W> {
    /// Creates a new AesWriter with a random IV.
    ///
    /// The IV will be written as first block of the file.
    ///
    /// # Parameters
    ///
    /// * **writer**: Writer to write encrypted data into
    /// * **enc**: [`BlockEncryptor`][be] to use for encyrption
    ///
    /// [be]: https://docs.rs/rust-crypto/0.2.36/crypto/symmetriccipher/trait.BlockEncryptor.html
    pub fn new(mut writer: W, enc: E) -> Result<AesWriter<E, W>> {
        let mut iv = vec![0u8; enc.block_size()];
        let mut rng = thread_rng();

        rng.try_fill(&mut iv[..])
            .map_err(|e| Error::new(ErrorKind::Other, format!("error generating iv: {:?}", e)))?;
        writer.write_all(&iv)?;
        Ok(AesWriter {
            writer: Some(writer),
            enc: CtrMode::new(enc, iv),
        })
    }

    /// Encrypts passed buffer and writes all resulting encrypted blocks to the underlying writer
    ///
    /// # Parameters
    ///
    /// * **buf**: Plaintext to encrypt and write
    /// * **eof**: If the provided buf is the last one to come and therefore encryption should be
    ///     finished and padding added.
    fn encrypt_write(&mut self, buf: &[u8], eof: bool) -> Result<usize> {
        let mut read_buf = RefReadBuffer::new(buf);
        let mut out = [0u8; BUFFER_SIZE];
        let mut write_buf = RefWriteBuffer::new(&mut out);
        loop {
            let res = self.enc.encrypt(&mut read_buf, &mut write_buf, eof)
                .map_err(|e| Error::new(ErrorKind::Other, format!("encryption error: {:?}", e)))?;
            let mut enc = write_buf.take_read_buffer();
            let enc = enc.take_remaining();
            self.writer.as_mut().unwrap().write_all(enc)?;
            match res {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow if eof =>
                    panic!("read_buf underflow during encryption with eof"),
                BufferResult::BufferOverflow => {},
            }
        }
        // CbcEncryptor has its own internal buffer and always consumes all input
        assert_eq!(read_buf.remaining(), 0);
        Ok(buf.len())
    }
}

impl<E: BlockEncryptor, W: Write> Write for AesWriter<E, W> {
    /// Encrypts the passed buffer and writes the result to the underlying writer.
    ///
    /// Due to the blocksize of CBC not all data will be written instantaneously.
    /// For example if 17 bytes are passed, the first 16 will be encrypted as one block and written
    /// the underlying writer, but the last byte won't be encrypted and written yet.
    ///
    /// If [`flush`](#method.flush) has been called, this method will always return an error.
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let written = self.encrypt_write(buf, false)?;
        Ok(written)
    }

    /// Flush this output stream, ensuring that all intermediately buffered contents reach their destination.
    /// [Read more](https://doc.rust-lang.org/nightly/std/io/trait.Write.html#tymethod.flush)
    ///
    /// **Warning**: When this method is called, the encryption will finish and insert final padding.
    /// After calling `flush`, this writer cannot be written to anymore and will always return an
    /// error.
    fn flush(&mut self) -> Result<()> {
        self.writer.as_mut().unwrap().flush()
    }
}

impl<E: BlockEncryptor, W: Write> Drop for AesWriter<E, W> {
    /// Drops this AesWriter trying to finish encryption and to write everything to the underlying writer.
    fn drop(&mut self) {
        if self.writer.is_some() {
            if !std::thread::panicking() {
                self.flush().unwrap();
            } else {
                let _ = self.flush();
            }
        }
    }
}

/// Wraps a [`Read`](https://doc.rust-lang.org/std/io/trait.Read.html) implementation with CBC
/// based on given [`BlockDecryptor`][bd]
///
/// [bd]: https://docs.rs/rust-crypto/0.2.36/crypto/symmetriccipher/trait.BlockDecryptor.html
pub struct AesReader<D: BlockEncryptor, R: Read>
{
    /// Reader to read encrypted data from
    reader: R,
    /// Decryptor to decrypt data with
    dec: CtrMode<D>,
    /// Buffer used to store blob needed to find out if we reached eof
    buffer: Vec<u8>,
    /// Indicates wheather eof of the underlying buffer was reached
    eof: bool,
}

impl<D: BlockEncryptor, R: Read> AesReader<D, R>
{
    /// Creates a new AesReader.
    ///
    /// Assumes that the first block of given reader is the IV.
    ///
    /// # Parameters
    ///
    /// * **reader**: Reader to read encrypted data from
    /// * **dec**: [`BlockDecryptor`][bd] to use for decyrption
    ///
    /// [bd]: https://docs.rs/rust-crypto/0.2.36/crypto/symmetriccipher/trait.BlockDecryptor.html
    pub fn new(mut reader: R, dec: D) -> Result<AesReader<D, R>> {
        let mut iv = vec![0u8; dec.block_size()];
        reader.read_exact(&mut iv)?;
        Ok(AesReader {
            reader,
            dec: CtrMode::new(dec, iv),
            buffer: Vec::new(),
            eof: false,
        })
    }

    /// Reads at max BUFFER_SIZE bytes, handles potential eof and returns the buffer as Vec<u8>
    fn fill_buf(&mut self) -> Result<Vec<u8>> {
        let mut eof_buffer = vec![0u8; BUFFER_SIZE];
        let read = self.reader.read(&mut eof_buffer)?;
        self.eof = read == 0;
        eof_buffer.truncate(read);
        Ok(eof_buffer)
    }

    /// Reads and decrypts data from the underlying stream and writes it into the passed buffer.
    ///
    /// The CbcDecryptor has an internal output buffer, but not an input buffer.
    /// Therefore, we need to take care of letfover input.
    /// Additionally, we need to handle eof correctly, as CbcDecryptor needs to correctly interpret
    /// padding.
    /// Thus, we need to read 2 buffers. The first one is read as input for decryption and the second
    /// one to determine if eof is reached.
    /// The next time this function is called, the second buffer is passed as input into decryption
    /// and the first buffer is filled to find out if we reached eof.
    ///
    /// # Parameters
    ///
    /// * **buf**: Buffer to write decrypted data into.
    fn read_decrypt(&mut self, buf: &mut [u8]) -> Result<usize> {
        // if this is the first iteration, fill internal buffer
        if self.buffer.is_empty() && !self.eof {
            self.buffer = self.fill_buf()?;
        }

        let buf_len = buf.len();
        let mut write_buf = RefWriteBuffer::new(buf);
        let res;
        let remaining;
        {
            let mut read_buf = RefReadBuffer::new(&self.buffer);

            // test if CbcDecryptor still has enough decrypted data or we have enough buffered
            res = self.dec.decrypt(&mut read_buf, &mut write_buf, self.eof)
                .map_err(|e| Error::new(ErrorKind::Other, format!("decryption error: {:?}", e)))?;
            remaining = read_buf.remaining();
        }
        // keep remaining bytes
        let len = self.buffer.len();
        self.buffer.drain(..(len - remaining));
        // if we were able to decrypt, return early
        match res {
            BufferResult::BufferOverflow => return Ok(buf_len),
            BufferResult::BufferUnderflow if self.eof => return Ok(write_buf.position()),
            _ => {}
        }

        // else read new buffer
        let mut dec_len = 0;
        // We must return something, if we have something.
        // If the reader doesn't return enough so that we can decrypt a block, we need to continue
        // reading until we have enough data to return one decrypted block, or until we reach eof.
        // If we reach eof, we will be able to decrypt the final block because of padding.
        while dec_len == 0 && !self.eof {
            let eof_buffer = self.fill_buf()?;
            let remaining;
            {
                let mut read_buf = RefReadBuffer::new(&self.buffer);
                self.dec.decrypt(&mut read_buf, &mut write_buf, self.eof)
                    .map_err(|e| Error::new(ErrorKind::Other, format!("decryption error: {:?}", e)))?;
                let mut dec = write_buf.take_read_buffer();
                let dec = dec.take_remaining();
                dec_len = dec.len();
                remaining = read_buf.remaining();
            }
            // keep remaining bytes
            let len = self.buffer.len();
            self.buffer.drain(..(len - remaining));
            // append newly read bytes
            self.buffer.extend(eof_buffer);
        }
        Ok(dec_len)
    }

}

impl<D: BlockEncryptor, R: Read> Read for AesReader<D, R> {
    /// Reads encrypted data from the underlying reader, decrypts it and writes the result into the
    /// passed buffer.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read = self.read_decrypt(buf)?;
        Ok(read)
    }
}

#[cfg(test)]
use crypto::aessafe::{AesSafe128Encryptor};

#[cfg(test)]
use std::io::Cursor;

#[cfg(test)]
fn encrypt(data: &[u8]) -> Vec<u8> {
    let key = [0u8; 16];
    let block_enc = AesSafe128Encryptor::new(&key);
    let mut enc = Vec::new();
    {
        let mut aes = AesWriter::new(&mut enc, block_enc).unwrap();
        aes.write_all(&data).unwrap();
    }
    enc
}

#[cfg(test)]
fn decrypt<R: Read>(data: R) -> Vec<u8> {
    let key = [0u8; 16];
    let block_dec = AesSafe128Encryptor::new(&key);
    let mut dec = Vec::new();
    let mut aes = AesReader::new(data, block_dec).unwrap();
    aes.read_to_end(&mut dec).unwrap();
    dec
}

#[cfg(test)]
struct UnalignedReader<'a> {
    buf: &'a [u8],
    block_size: usize,
    written: usize,
}

#[cfg(test)]
impl<'a> UnalignedReader<'a> {
    fn new(buf: &'a [u8], block_size: usize) -> UnalignedReader<'a> {
        UnalignedReader { buf, block_size, written: 0 }
    }
}

#[cfg(test)]
impl<'a> Read for UnalignedReader<'a> {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize> {
        let until = std::cmp::min(self.written + self.block_size, self.buf.len());
        let written = buf.write(&self.buf[self.written..until]).unwrap();
        self.written += written;
        Ok(written)
    }
}

#[test]
fn enc_unaligned() {
    let orig = [0u8; 16];
    let key = [0u8; 16];
    let block_enc = AesSafe128Encryptor::new(&key);
    let mut enc = Vec::new();
    {
        let mut aes = AesWriter::new(&mut enc, block_enc).unwrap();
        for chunk in orig.chunks(3) {
            aes.write_all(&chunk).unwrap();
        }
    }
    assert_eq!(enc.len(), 32);
    let dec = decrypt(Cursor::new(&enc));
    assert_eq!(dec, &orig);
}

#[test]
fn enc_dec_single() {
    let orig = [0u8; 15];
    let enc = encrypt(&orig);
    assert_eq!(enc.len(), 31);
    let dec = decrypt(Cursor::new(&enc));
    assert_eq!(dec, &orig);
}

#[test]
fn enc_dec_single_full() {
    let orig = [0u8; 16];
    let enc = encrypt(&orig);
    assert_eq!(enc.len(), 32);
    let dec = decrypt(Cursor::new(&enc));
    assert_eq!(dec, &orig);
}

#[test]
fn dec_unaligned() {
    let orig = [0u8; 16];
    let enc = encrypt(&orig);
    let dec = decrypt(UnalignedReader::new(&enc, 3));
    assert_eq!(dec, &orig);
}

#[test]
fn dec_block_aligned() {
    let orig = [0u8; 48];
    let enc = encrypt(&orig);
    let dec = decrypt(UnalignedReader::new(&enc, 16));
    assert_eq!(dec, &orig[..]);
}

#[test]
fn dec_read_unaligned() {
    let orig = [0u8; 16];
    let enc = encrypt(&orig);

    let key = [0u8; 16];
    let block_dec = AesSafe128Encryptor::new(&key);
    let mut dec: Vec<u8> = Vec::new();
    let mut aes = AesReader::new(Cursor::new(&enc), block_dec).unwrap();
    loop {
        let mut buf = [0u8; 3];
        let read = aes.read(&mut buf).unwrap();
        dec.extend(&buf[..read]);
        if read == 0 { break; }
    }
    assert_eq!(dec, &orig);
}
