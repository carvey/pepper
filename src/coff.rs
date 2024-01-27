use super::prelude::*;
use chrono::DateTime;

/*
PE Header:
+00 DWORD Signature ($00004550)
+04	WORD	Machine
+06	WORD	Number of Sections
+08	DWORD	TimeDateStamp
+0C  (12)	DWORD	PointerToSymbolTable
+10  (16)	DWORD	NumberOfSymbols
+14  (20)	WORD	SizeOfOptionalHeader
+16  (22)	WORD	Characteristics
 */
#[derive(Debug)]
pub struct CoffHeader {
    pub signature: String, // u32 before utf8 conversion
    pub machine: u16,
    pub num_sections: u16,
    pub timestamp: String,
    pub symbol_table: u32, // u32 storing pointer for now, but should be parsed SymbolTable
    pub num_symbols: u32,
    pub size_optional_header: u16,
}

impl CoffHeader {
    pub fn new(raw: &[u8]) -> Result<Self, ParsingError> {
        let mut offset = 0;

        let signature =
            read_utf8(&raw, &mut offset, DWORD_SZ).expect("Failed to read PE signature");
        let machine = {
            let raw: &[u8] = &raw;
            let offset: &mut usize = &mut offset;
            let slice = &raw[*offset..*offset + WORD_SZ];
            let val = match slice.try_into() {
                Ok(bytes) => u16::from_le_bytes(bytes),
                Err(e) => panic!(),
            };

            *offset += WORD_SZ;
            val
        };
        let num_sections = read_word(&raw, &mut offset);
        let timestamp = read_dword(&raw, &mut offset);
        let dt = DateTime::from_timestamp(timestamp as i64, 0)
            .expect("failed to parse PE timestamp")
            .to_string();

        let symbol_table = read_dword(&raw, &mut offset);
        let num_symbols = read_dword(&raw, &mut offset);
        let size_optional_header = read_word(&raw, &mut offset);

        Ok(Self {
            signature,
            machine,
            num_sections,
            timestamp: dt,
            symbol_table,
            num_symbols,
            size_optional_header,
        })
    }
}

impl std::fmt::Display for CoffHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "\nCOFF Header\n---------------------")?;
        writeln!(f, "Signature: {}", self.signature)?;
        writeln!(f, "Machine: {}", self.machine)?;
        writeln!(f, "Num. Sections: {}", self.num_sections)?;
        writeln!(f, "Timestamp: {}", self.timestamp)?;
        writeln!(f, "Symbol Table: {}", self.symbol_table)?;
        writeln!(f, "Num. Symbols: {}", self.num_symbols)?;
        writeln!(f, "Size of Optional Header: {}", self.size_optional_header)
    }
}
