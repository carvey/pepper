use super::prelude::*;
use std::str::{from_utf8, Utf8Error};

/*
 * type reference:
 * WORD = u16
 * DWORD = u32
 */
pub const WORD_SZ: usize = 2;
pub const DWORD_SZ: usize = 4;
pub const DWORDLONG_SZ: usize = 8;

#[derive(Debug, PartialEq)]
pub enum PeFormat {
    PE32,  // 32 bit
    PE32P, // PE32+ -> 64 bit
}

#[derive(Debug, PartialEq)]
pub enum ArchDependentSized {
    PE32(u32),
    PE32P(u64),
}

impl ArchDependentSized {
    pub fn new(raw: &[u8], offset: &mut usize, magic: &PeFormat) -> Self {
        match magic {
            PeFormat::PE32 => {
                let dword = read_dword(raw, offset);
                Self::PE32(dword)
            }
            PeFormat::PE32P => {
                let dwordlong = read_dwordlong(raw, offset);
                Self::PE32P(dwordlong)
            }
        }
    }
}

impl PeFormat {
    pub fn from_u16(raw: u16) -> Result<Self, ParsingError> {
        match raw {
            267 => Ok(Self::PE32),
            523 => Ok(Self::PE32P),
            _ => Err(ParsingError::Malformed {
                reason: "failed to parse 2 byte architecture from optional header".to_string(),
            }),
        }
    }
}

// TODO: These read functions should be returning Result / Option instead of just u8

pub fn read_byte(raw: &[u8], offset: &mut usize) -> u8 {
    let slice = &raw[*offset..*offset + 1];
    let val = match slice.try_into() {
        Ok(bytes) => u8::from_le_bytes(bytes),
        Err(_) => unimplemented!(),
    };

    *offset += 1;
    val
}

pub fn read_word(raw: &[u8], offset: &mut usize) -> u16 {
    let slice = &raw[*offset..*offset + WORD_SZ];
    let val = match slice.try_into() {
        Ok(bytes) => u16::from_le_bytes(bytes),
        Err(_) => unimplemented!(),
    };

    *offset += WORD_SZ;
    val
}

pub fn read_dword(raw: &[u8], offset: &mut usize) -> u32 {
    let slice = &raw[*offset..*offset + DWORD_SZ];
    let val = match slice.try_into() {
        Ok(bytes) => u32::from_le_bytes(bytes),
        Err(_) => unimplemented!(),
    };

    *offset += DWORD_SZ;
    val
}

pub fn read_dwordlong(raw: &[u8], offset: &mut usize) -> u64 {
    let slice = &raw[*offset..*offset + DWORDLONG_SZ];
    let val = match slice.try_into() {
        Ok(bytes) => u64::from_le_bytes(bytes),
        Err(_) => unimplemented!(),
    };

    *offset += DWORDLONG_SZ;
    val
}

pub fn read_utf8(raw: &[u8], offset: &mut usize, len: usize) -> Result<String, Utf8Error> {
    let str = from_utf8(&raw[*offset..*offset + len])?.to_string();
    *offset += len;
    Ok(str)
}
