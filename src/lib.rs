// https://en.wikipedia.org/wiki/ZIP_(file_format)

use std::io::Write;
use std::io::Read;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Result;
use std::path::Path;
use std::fs::File;
use std::os::unix::ffi::OsStringExt;
use chrono::NaiveDateTime;
use chrono::DateTime;
use chrono::offset::Utc;
use chrono::Datelike;
use chrono::Timelike;
use crc::Crc;
use miniz_oxide::deflate::core::CompressorOxide;
use miniz_oxide::deflate::stream::deflate;
use miniz_oxide::MZFlush;
use miniz_oxide::MZStatus;
use miniz_oxide::DataFormat;

const CRC32: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);

#[derive(Debug, Clone, Default)]
struct DataDescriptor {
    crc: u32,
    compressed_size: u32,
    uncompressed_size: u32,
}

impl DataDescriptor {
    fn write<W: Write>(&self, handle: &mut W, with_signature: bool) -> Result<usize> {
        let mut written = 0;
        if with_signature {
            handle.write_all(b"PK\x07\x08")?; // data descriptor signature
            written += 4;
        }
        handle.write_all(&self.crc.to_le_bytes())?;
        written += 4;
        handle.write_all(&self.compressed_size.to_le_bytes())?;
        written += 4;
        handle.write_all(&self.uncompressed_size.to_le_bytes())?;
        written += 4;
        Ok(written)
    }
}

#[derive(Debug, Clone)]
struct FileHeader {
    name: Vec<u8>,
    last_modified: NaiveDateTime,
    data_descriptor: Option<DataDescriptor>,
    file_header_start: u32,
    compression: CompressionMode,
}

impl FileHeader {
    fn write<W: Write>(&self, handle: &mut W, is_central: bool) -> Result<usize> {
        let mut written = 0;
        if is_central {
            handle.write_all(b"PK\x01\x02")?; // Central directory file header signature
            written += 4;
        } else {
            handle.write_all(b"PK\x03\x04")?; // Local file header signature
            written += 4;
        }
        if is_central {
            handle.write_all(&10u16.to_le_bytes())?; // Version made by => 1.0
            written += 2;
        }
        handle.write_all(&10u16.to_le_bytes())?; // Version needed to extract (minimum) => 1.0
        written += 2;
        if self.data_descriptor.is_some() {
            handle.write_all(&0b0000_0000u16.to_le_bytes())?; // General purpose bit flag
            written += 2;
        } else {
            handle.write_all(&0b0000_1000u16.to_le_bytes())?; // General purpose bit flag => enable data descriptors
            written += 2;
        }
        let compression_num: u16 = match self.compression {
            CompressionMode::Store => 0,
            CompressionMode::Deflate(_) => 8,
        };
        handle.write_all(&compression_num.to_le_bytes())?; // Compression method
        written += 2;
        let timepart = ((self.last_modified.second() as u16) >> 1) | ((self.last_modified.minute() as u16) << 5) | ((self.last_modified.hour() as u16) << 11);
        let datepart = (self.last_modified.day() as u16) | ((self.last_modified.month() as u16) << 5) | ((self.last_modified.year() as u16 - 1980) << 9);
        handle.write_all(&timepart.to_le_bytes())?; // File last modification time
        written += 2;
        handle.write_all(&datepart.to_le_bytes())?; // File last modification date
        written += 2;
        written += self.data_descriptor.clone().unwrap_or_default().write(handle, false)?;
        handle.write_all(&(self.name.len() as u16).to_le_bytes())?; // File name length
        written += 2;
        handle.write_all(&0u16.to_le_bytes())?; // Extra field length
        written += 2;
        if is_central {
            handle.write_all(&0u16.to_le_bytes())?; // File comment length
            written += 2;
            handle.write_all(&0u16.to_le_bytes())?; // Disk number where file starts
            written += 2;
            handle.write_all(&0u16.to_le_bytes())?; // Internal file attributes
            written += 2;
            handle.write_all(&0u32.to_le_bytes())?; // External file attributes
            written += 4;
            handle.write_all(&self.file_header_start.to_le_bytes())?; // Relative offset of local file header
            written += 4;
        }
        handle.write_all(&self.name)?; // File name
        written += self.name.len();
        Ok(written)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CompressionMode {
    Store,
    Deflate(u8),
}

pub struct Archive<W: Write> {
    buf: [u8; 4096],
    compressed_buf: [u8; 4096],
    files: Vec<FileHeader>,
    written: usize,
    inner: W,
}

impl<W: Write> Archive<W> {
    pub fn new(inner: W) -> Archive<W> {
        Archive {
            buf: [0; 4096],
            compressed_buf: [0; 4096],
            files: Vec::new(),
            written: 0,
            inner,
        }
    }

    fn write_data_deflate<R: Read>(&mut self, content: &mut R, level: u8) -> Result<DataDescriptor> {
        let mut compressor = CompressorOxide::default();
        compressor.set_format_and_level(DataFormat::Raw, level);
        let mut digest = CRC32.digest();
        let mut uncompressed_size = 0u32;
        let mut compressed_size = 0u32;
        while let Ok(len) = content.read(&mut self.buf) {
            if len == 0 { break; }
            digest.update(&self.buf[..len]);
            uncompressed_size += len as u32;

            let mut in_buf = &self.buf[..len];
            loop {
                let res = deflate(&mut compressor, in_buf, &mut self.compressed_buf, MZFlush::None);
                match res.status {
                    Ok(MZStatus::Ok) => (),
                    Ok(status) => return Err(Error::new(ErrorKind::Other, format!("deflate unexpected status: {:?}", status))),
                    Err(status) => return Err(Error::new(ErrorKind::Other, format!("deflate error: {:?}", status))),
                }

                compressed_size += res.bytes_written as u32;
                self.inner.write_all(&self.compressed_buf[..res.bytes_written])?;
                self.written += res.bytes_written;
                in_buf = &in_buf[res.bytes_consumed..];
                if in_buf.len() == 0 { break; }
            }
        }

        loop {
            let res = deflate(&mut compressor, &[], &mut self.compressed_buf, MZFlush::Finish);
            let status = match res.status {
                Ok(MZStatus::Ok) => MZStatus::Ok,
                Ok(MZStatus::StreamEnd) => MZStatus::StreamEnd,
                Ok(status) => return Err(Error::new(ErrorKind::Other, format!("deflate unexpected status: {:?}", status))),
                Err(status) => return Err(Error::new(ErrorKind::Other, format!("deflate error: {:?}", status))),
            };
            compressed_size += res.bytes_written as u32;
            self.inner.write_all(&self.compressed_buf[..res.bytes_written])?;
            self.written += res.bytes_written;
            if let MZStatus::StreamEnd = status { break; }
        }

        let crc = digest.finalize();
        Ok(DataDescriptor {
            crc,
            uncompressed_size,
            compressed_size,
        })
    }

    fn write_data_store<R: Read>(&mut self, content: &mut R) -> Result<DataDescriptor> {
        let mut digest = CRC32.digest();
        let mut uncompressed_size = 0u32;
        while let Ok(len) = content.read(&mut self.buf) {
            if len == 0 { break; }
            digest.update(&self.buf[..len]);
            uncompressed_size += len as u32;
            self.inner.write_all(&self.buf[..len])?;
            self.written += len;
        }
        let crc = digest.finalize();
        Ok(DataDescriptor {
            crc,
            uncompressed_size,
            compressed_size: uncompressed_size,
        })
    }

    pub fn add_file<R: Read>(&mut self, name: Vec<u8>, last_modified: NaiveDateTime, compression: CompressionMode, content: &mut R) -> Result<()> {
        let mut file = FileHeader {
            name,
            last_modified,
            data_descriptor: None,
            file_header_start: self.written as u32,
            compression,
        };
        self.written += file.write(&mut self.inner, false)?;

        let dd = match compression {
            CompressionMode::Store => self.write_data_store(content)?,
            CompressionMode::Deflate(level) => self.write_data_deflate(content, level)?,
        };

        self.written += dd.write(&mut self.inner, true)?;
        file.data_descriptor = Some(dd);

        self.files.push(file);

        Ok(())
    }

    pub fn add_dir_all<R: AsRef<Path>, S: AsRef<Path>>(&mut self, path: R, src_path: S, compression: CompressionMode) -> Result<()> {
        let mut stack = vec![(src_path.as_ref().to_path_buf(), None)];
        while let Some((src, modified_if_file)) = stack.pop() {
            let dest = path.as_ref().join(src.strip_prefix(&src_path).unwrap());
            match modified_if_file {
                None => {
                    for entry in std::fs::read_dir(&src)? {
                        let entry = entry?;
                        let file_type = entry.file_type()?;
                        if !file_type.is_symlink() {
                            let modified_if_file = match file_type.is_dir() {
                                true => None,
                                false => Some(DateTime::<Utc>::from(entry.metadata()?.modified()?).naive_local())
                            };
                            stack.push((entry.path(), modified_if_file));
                        }
                    }
                },
                Some(modified) => {
                    self.add_file(dest.into_os_string().into_vec(), modified, compression, &mut File::open(src)?)?;
                },
            }
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<W> {
        let central_directory_start = self.written;
        for file in &self.files {
            self.written += file.write(&mut self.inner, true)?;
        }
        let central_directory_size = self.written - central_directory_start;

        self.inner.write_all(b"PK\x05\x06")?; // End of central directory signature
        self.inner.write_all(&0u16.to_le_bytes())?; // Number of this disk
        self.inner.write_all(&0u16.to_le_bytes())?; // Disk where central directory starts
        self.inner.write_all(&(self.files.len() as u16).to_le_bytes())?; // Number of central directory records on this disk
        self.inner.write_all(&(self.files.len() as u16).to_le_bytes())?; // Total number of central directory records
        self.inner.write_all(&(central_directory_size as u32).to_le_bytes())?; // Size of central directory
        self.inner.write_all(&(central_directory_start as u32).to_le_bytes())?; // Offset of start of central directory
        self.inner.write_all(&0u16.to_le_bytes())?; // Comment length

        Ok(self.inner)
    }
}
