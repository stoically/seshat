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
use std::cmp;
use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom, Write};
use std::ops::Neg;

use crypto::blockmodes::CtrMode;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::mac::{Mac, MacResult};
use crypto::symmetriccipher::{BlockEncryptor, Decryptor, Encryptor};
use rand::{thread_rng, Rng};

const BUFFER_SIZE: usize = 8192;

/// Wraps a [`Write`](https://doc.rust-lang.org/std/io/trait.Write.html) implementation with CBC
/// based on given [`BlockEncryptor`][be]
///
/// [be]: https://docs.rs/rust-crypto/0.2.36/crypto/symmetriccipher/trait.BlockEncryptor.html
///
pub struct AesWriter<E: BlockEncryptor, M: Mac, W: Write> {
    /// Writer to write encrypted data to
    writer: W,
    /// Encryptor to encrypt data with
    enc: CtrMode<E>,
    mac: M,
}

impl<E: BlockEncryptor, M: Mac, W: Write> AesWriter<E, M, W> {
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
    pub fn new(mut writer: W, enc: E, mac: M) -> Result<AesWriter<E, M, W>> {
        let mut iv = vec![0u8; enc.block_size()];
        let mut rng = thread_rng();

        rng.try_fill(&mut iv[..])
            .map_err(|e| Error::new(ErrorKind::Other, format!("error generating iv: {:?}", e)))?;
        writer.write_all(&iv)?;
        Ok(AesWriter {
            writer,
            enc: CtrMode::new(enc, iv),
            mac,
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
            let res = self
                .enc
                .encrypt(&mut read_buf, &mut write_buf, eof)
                .map_err(|e| Error::new(ErrorKind::Other, format!("encryption error: {:?}", e)))?;
            let mut enc = write_buf.take_read_buffer();
            let enc = enc.take_remaining();
            self.writer.write_all(enc)?;
            self.mac.input(enc);
            match res {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow if eof => {
                    panic!("read_buf underflow during encryption with eof")
                }
                BufferResult::BufferOverflow => {}
            }
        }
        assert_eq!(read_buf.remaining(), 0);
        Ok(buf.len())
    }
}

impl<E: BlockEncryptor, M: Mac, W: Write> Write for AesWriter<E, M, W> {
    /// Encrypts the passed buffer and writes the result to the underlying writer.
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let written = self.encrypt_write(buf, false)?;
        Ok(written)
    }

    /// Flush this output stream, ensuring that all intermediately buffered contents reach their destination.
    /// [Read more](https://doc.rust-lang.org/nightly/std/io/trait.Write.html#tymethod.flush)
    fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}

impl<E: BlockEncryptor, M: Mac, W: Write> Drop for AesWriter<E, M, W> {
    /// Drops this AesWriter trying to finish encryption and to write everything to the underlying writer.
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let mac_result = self.mac.result();
            self.writer.write_all(mac_result.code()).unwrap();
            self.flush().unwrap();
        } else {
            let mac_result = self.mac.result();
            let _ = self.writer.write_all(mac_result.code());
            let _ = self.flush();
        }
    }
}

/// Wraps a [`Read`](https://doc.rust-lang.org/std/io/trait.Read.html) implementation with CTR
/// based on given [`CtrMode`][ct]
///
/// [ct]: https://docs.rs/rust-crypto/0.2.36/crypto/blockmodes/struct.CtrMode.html
pub struct AesReader<D: BlockEncryptor, R: Read + Seek> {
    /// Reader to read encrypted data from
    reader: R,
    /// Decryptor to decrypt data with
    dec: CtrMode<D>,
    /// Buffer used to store blob needed to find out if we reached eof
    buffer: Vec<u8>,
    /// Indicates wheather eof of the underlying buffer was reached
    eof: bool,
    /// Total length of the reader
    length: u64,
    /// Length of the MAC.
    mac_length: usize,
}

impl<D: BlockEncryptor, R: Read + Seek> AesReader<D, R> {
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
    pub fn new<M: Mac>(mut reader: R, dec: D, mut mac: M) -> Result<AesReader<D, R>> {
        let iv_length = dec.block_size();
        let mac_length = mac.output_bytes();

        let mut iv = vec![0u8; iv_length];
        let mut expected_mac = vec![0u8; mac_length];

        reader.read_exact(&mut iv)?;
        let end = reader.seek(SeekFrom::End(0))?;

        // TODO make the numeric conversion safe.
        if end < (dec.block_size() + mac_length) as u64 {
            return Err(Error::new(
                ErrorKind::Other,
                "File doesn't contain a valid IV or MAC",
            ));
        }

        // TODO make the numeric conversion safe.
        let seek_back = (mac_length as i64).neg();
        reader.seek(SeekFrom::End(seek_back))?;
        reader.read_exact(&mut expected_mac)?;
        let expected_mac = MacResult::new_from_owned(expected_mac);

        // TODO make the numeric conversion safe.
        reader.seek(SeekFrom::Start(iv_length as u64))?;

        let mut eof = false;

        while !eof {
            let (buffer, end_of_file) =
                AesReader::<D, R>::read_until_mac(&mut reader, end, mac.output_bytes())?;
            eof = end_of_file;
            mac.input(&buffer);
        }

        if mac.result() != expected_mac {
            return Err(Error::new(ErrorKind::Other, "Invalid MAC"));
        }

        // TODO make the numeric conversion safe.
        reader.seek(SeekFrom::Start(iv_length as u64))?;

        Ok(AesReader {
            reader,
            dec: CtrMode::new(dec, iv),
            buffer: Vec::new(),
            eof: false,
            length: end,
            mac_length,
        })
    }

    fn read_until_mac(
        reader: &mut R,
        total_length: u64,
        mac_length: usize,
    ) -> Result<(Vec<u8>, bool)> {
        let mut buffer = vec![0u8; BUFFER_SIZE];
        let read = reader.read(&mut buffer)?;

        // TODO make the numeric conversion safe.
        let current_pos = reader.seek(SeekFrom::Current(0))?;
        let mac_start = total_length - mac_length as u64;
        let read_mac_bytes = cmp::max(current_pos - mac_start, 0);
        let eof = current_pos >= mac_start;

        buffer.truncate(read - read_mac_bytes as usize);

        Ok((buffer, eof))
    }

    /// Reads at max BUFFER_SIZE bytes, handles potential eof and returns the buffer as Vec<u8>
    fn fill_buf(&mut self) -> Result<Vec<u8>> {
        let (buffer, eof) =
            AesReader::<D, R>::read_until_mac(&mut self.reader, self.length, self.mac_length)?;
        self.eof = eof;
        Ok(buffer)
    }

    /// Reads and decrypts data from the underlying stream and writes it into the passed buffer.
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
            res = self
                .dec
                .decrypt(&mut read_buf, &mut write_buf, self.eof)
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
                self.dec
                    .decrypt(&mut read_buf, &mut write_buf, self.eof)
                    .map_err(|e| {
                        Error::new(ErrorKind::Other, format!("decryption error: {:?}", e))
                    })?;
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

impl<D: BlockEncryptor, R: Read + Seek> Read for AesReader<D, R> {
    /// Reads encrypted data from the underlying reader, decrypts it and writes the result into the
    /// passed buffer.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read = self.read_decrypt(buf)?;
        Ok(read)
    }
}

#[cfg(test)]
use crypto::aessafe::AesSafe128Encryptor;

#[cfg(test)]
use crypto::hmac::Hmac;

#[cfg(test)]
use crypto::sha2::Sha256;

#[cfg(test)]
use std::io::Cursor;

#[cfg(test)]
fn encrypt(data: &[u8]) -> Vec<u8> {
    let key = [0u8; 16];
    let hmac_key = [0u8; 16];

    let mac = Hmac::new(Sha256::new(), &hmac_key);
    let block_enc = AesSafe128Encryptor::new(&key);
    let mut enc = Vec::new();
    {
        let mut aes = AesWriter::new(&mut enc, block_enc, mac).unwrap();
        aes.write_all(&data).unwrap();
    }
    enc
}

#[cfg(test)]
fn decrypt<R: Read + Seek>(data: R) -> Vec<u8> {
    let key = [0u8; 16];
    let block_dec = AesSafe128Encryptor::new(&key);
    let mut dec = Vec::new();
    let hmac = Hmac::new(Sha256::new(), &key);
    let mut aes = AesReader::new(data, block_dec, hmac).unwrap();
    aes.read_to_end(&mut dec).unwrap();
    dec
}

#[test]
fn enc_unaligned() {
    let orig = [0u8; 16];
    let key = [0u8; 16];
    let hmac_key = [0u8; 16];

    let mac = Hmac::new(Sha256::new(), &hmac_key);
    let block_enc = AesSafe128Encryptor::new(&key);
    let mut enc = Vec::new();
    {
        let mut aes = AesWriter::new(&mut enc, block_enc, mac).unwrap();
        for chunk in orig.chunks(3) {
            aes.write_all(&chunk).unwrap();
        }
    }
    let dec = decrypt(Cursor::new(&enc));
    assert_eq!(dec, &orig);
}

#[test]
fn enc_dec_single() {
    let orig = [0u8; 15];
    let enc = encrypt(&orig);
    let dec = decrypt(Cursor::new(&enc));
    assert_eq!(dec, &orig);
}

#[test]
fn enc_dec_single_full() {
    let orig = [0u8; 16];
    let enc = encrypt(&orig);
    let dec = decrypt(Cursor::new(&enc));
    assert_eq!(dec, &orig);
}

#[test]
fn dec_read_unaligned() {
    let orig = [0u8; 16];
    let enc = encrypt(&orig);

    let key = [0u8; 16];
    let block_dec = AesSafe128Encryptor::new(&key);
    let mut dec: Vec<u8> = Vec::new();
    let hmac = Hmac::new(Sha256::new(), &key);
    let mut aes = AesReader::new(Cursor::new(&enc), block_dec, hmac).unwrap();
    loop {
        let mut buf = [0u8; 3];
        let read = aes.read(&mut buf).unwrap();
        dec.extend(&buf[..read]);
        if read == 0 {
            break;
        }
    }
    assert_eq!(dec, &orig);
}
