use super::prelude::*;
use std::str::from_utf8;

/*
DOS MZ Header:
+00 WORD    e_magic Magic Number MZ ($5A4D)
+02 WORD    e_cblp Bytes on last page of file
+04 WORD    e_cp Pages in file
+06	WORD	e_crlc	Relocations
+08	WORD	e_cparhdr	Size of header in paragraphs
+0A  (10)	WORD	e_minalloc	Minimum extra paragraphs needed
+0C  (12)	WORD	e_maxalloc	Maximum extra paragraphs needed
+0E  (14)	WORD	e_ss	Initial (relative) SS value
+10  (16)	WORD	e_sp	Initial SP value
+12  (18)	WORD	e_csum	Checksum
+14  (20)	WORD	e_ip	Initial IP value
+16  (22)	WORD	e_cs	Initial (relative) CS value
+18  (24)	WORD	e_lfarlc	File address of relocation table
+1A  (26)	WORD	e_ovno	Overlay number
+1C  (28)	Array[4] of WORD	e_res	Reserved words
+24  (36)	WORD	e_oemid	OEM identifier (for e_oeminfo)
+26  (28)	WORD	e_oeminfo	OEM information; e_oemid specific
+28  (40)	Array[10] of WORD	e_res2	Reserved words
+3C  (60)	DWORD	e_lfanew	File address of new exe header
 */
pub struct DosHeader {
    pub e_magic: String,
    pub e_lfanew: u32,
}

impl DosHeader {
    pub fn new(raw: &[u8]) -> Result<Self, ParsingError> {
        let e_magic = from_utf8(&raw[0..2])
            .expect("UTF8 error parsing DOS magic")
            .to_string();

        let offset = 0x3c;
        let lfa_bytes = &raw[offset..offset + 4];
        let bytes = match lfa_bytes.try_into() {
            Ok(arr) => u32::from_le_bytes(arr),
            Err(e) => panic!(),
        };
        Ok(Self {
            e_magic,
            e_lfanew: bytes,
        })
    }
}
