//! A minimal read-only tar writer and reader.
//!
//! The image-volume variant of a policy artifact is a data filesystem, not a
//! container image: it holds the module and its metadata and nothing else.
//! This module writes and reads the `ustar` archives that carry it, and it
//! deliberately refuses everything that is not a plain regular file - no
//! directories, no links, no device nodes, no executable bits.
//!
//! The archives are uncompressed on purpose: the layer media type is the
//! uncompressed tar type, so no decompressor is needed to validate them.

use std::fmt;

/// The size of a tar block.
const BLOCK: usize = 512;

/// The size of the name field of a tar header.
const NAME_FIELD: usize = 100;

/// One file in a tar archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarEntry {
    /// The path of the file inside the archive.
    pub path: String,
    /// The file mode.
    pub mode: u32,
    /// The contents of the file.
    pub data: Vec<u8>,
}

/// Why an archive could not be written or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TarError {
    /// A path does not fit into the tar name field.
    PathTooLong(String),
    /// The archive ends in the middle of an entry.
    Truncated,
    /// A header field could not be read.
    InvalidHeader(String),
    /// A header checksum does not match its contents.
    ChecksumMismatch,
    /// The archive holds something other than a regular file.
    UnsupportedEntryType(String),
}

impl fmt::Display for TarError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TarError::PathTooLong(path) => write!(formatter, "the path {path} is too long"),
            TarError::Truncated => write!(formatter, "the archive is truncated"),
            TarError::InvalidHeader(reason) => write!(formatter, "invalid tar header: {reason}"),
            TarError::ChecksumMismatch => {
                write!(formatter, "the tar header checksum does not match")
            }
            TarError::UnsupportedEntryType(kind) => {
                write!(formatter, "unsupported tar entry type {kind}")
            }
        }
    }
}

impl std::error::Error for TarError {}

/// Write a tar archive holding the given files.
pub fn write_entries(entries: &[TarEntry]) -> Result<Vec<u8>, TarError> {
    let mut archive = Vec::new();

    for entry in entries {
        archive.extend_from_slice(&header(entry)?);
        archive.extend_from_slice(&entry.data);
        let padding = (BLOCK - entry.data.len() % BLOCK) % BLOCK;
        archive.extend(std::iter::repeat_n(0u8, padding));
    }

    // Two zero blocks terminate the archive.
    archive.extend(std::iter::repeat_n(0u8, BLOCK * 2));
    Ok(archive)
}

/// Read a tar archive.
///
/// Only regular files are returned. Anything else is an error, so an archive
/// that smuggles in a directory, a link or an executable cannot pass as a
/// policy data filesystem.
pub fn read_entries(bytes: &[u8]) -> Result<Vec<TarEntry>, TarError> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset + BLOCK <= bytes.len() {
        let block = &bytes[offset..offset + BLOCK];
        if block.iter().all(|byte| *byte == 0) {
            break;
        }

        let path = read_string(&block[0..NAME_FIELD])?;
        let mode = read_octal(&block[100..108])? as u32;
        let size = read_octal(&block[124..136])? as usize;
        let checksum = read_octal(&block[148..156])?;
        let type_flag = block[156];

        verify_checksum(block, checksum)?;

        if type_flag != b'0' {
            return Err(TarError::UnsupportedEntryType(
                String::from_utf8_lossy(&[type_flag]).to_string(),
            ));
        }

        offset += BLOCK;
        if offset + size > bytes.len() {
            return Err(TarError::Truncated);
        }
        let data = bytes[offset..offset + size].to_vec();
        offset += size;
        offset += (BLOCK - size % BLOCK) % BLOCK;

        entries.push(TarEntry { path, mode, data });
    }

    Ok(entries)
}

/// Build the header block of one entry.
fn header(entry: &TarEntry) -> Result<[u8; BLOCK], TarError> {
    let mut block = [0u8; BLOCK];

    let name = entry.path.as_bytes();
    if name.len() > NAME_FIELD {
        return Err(TarError::PathTooLong(entry.path.clone()));
    }
    block[..name.len()].copy_from_slice(name);

    write_octal(&mut block[100..108], u64::from(entry.mode), 7);
    write_octal(&mut block[108..116], 0, 7);
    write_octal(&mut block[116..124], 0, 7);
    write_octal(&mut block[124..136], entry.data.len() as u64, 11);
    write_octal(&mut block[136..148], 0, 11);
    block[148..156].fill(b' ');
    block[156] = b'0';
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    write_octal(&mut block[329..337], 0, 7);
    write_octal(&mut block[337..345], 0, 7);

    let checksum: u32 = block.iter().map(|byte| u32::from(*byte)).sum();
    let text = format!("{checksum:06o}");
    block[148..154].copy_from_slice(text.as_bytes());
    block[154] = 0;
    block[155] = b' ';

    Ok(block)
}

/// Write an octal number into a fixed size field.
fn write_octal(field: &mut [u8], value: u64, digits: usize) {
    let text = format!("{value:0digits$o}");
    let bytes = text.as_bytes();
    let length = bytes.len().min(field.len() - 1);
    field[..length].copy_from_slice(&bytes[bytes.len() - length..]);
    field[field.len() - 1] = 0;
}

/// Read an octal number from a fixed size field.
fn read_octal(field: &[u8]) -> Result<u64, TarError> {
    let text: String = field
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as char)
        .collect();
    let text = text.trim();
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8)
        .map_err(|error| TarError::InvalidHeader(format!("invalid octal field: {error}")))
}

/// Read a NUL terminated string from a fixed size field.
fn read_string(field: &[u8]) -> Result<String, TarError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    String::from_utf8(field[..end].to_vec())
        .map_err(|error| TarError::InvalidHeader(format!("invalid text field: {error}")))
}

/// Verify the checksum of a header block.
fn verify_checksum(block: &[u8], recorded: u64) -> Result<(), TarError> {
    let mut sum: u32 = 0;
    for (index, byte) in block.iter().enumerate() {
        if (148..156).contains(&index) {
            sum += u32::from(b' ');
        } else {
            sum += u32::from(*byte);
        }
    }
    if u64::from(sum) == recorded {
        Ok(())
    } else {
        Err(TarError::ChecksumMismatch)
    }
}
