use super::prelude::*;
use std::{fmt, path::Path};

#[derive(Debug)]
pub struct Pe {
    //raw: Vec<u8>,
    path: &'static Path,
    pub dos_header: DosHeader,
    pub coff_header: CoffHeader,
    pub optional_header: OptionalHeader,
    pub section_table: SectionTable,
}

impl Pe {
    pub fn new(path_str: &'static str) -> Result<Self, ParsingError> {
        let path = Path::new(path_str);
        let raw = std::fs::read(path).expect("failed to read file");

        let dos_header = DosHeader::new(&raw).expect("failed to parse DOS header");

        let coff_header_offset = dos_header.e_lfanew as usize;
        let coff_header =
            CoffHeader::new(&raw[coff_header_offset..]).expect("failed to parse coff header");

        // optional header starts 24 bytes after coff_header
        let optional_header_offset = coff_header_offset + 24;
        let optional_header = OptionalHeader::new(&raw[optional_header_offset..])
            .expect("failed to parse optional header");

        // will eventually need to account for scenario where there's no optional header (non image
        // files)
        let section_table_offset =
            optional_header_offset + coff_header.size_optional_header as usize;
        let num_sections = coff_header.num_sections as usize;
        let section_table = SectionTable::new(&raw[section_table_offset..], num_sections)
            .expect("failed to parse section table");

        Ok(Self {
            //raw,
            path,
            dos_header,
            coff_header,
            optional_header,
            section_table,
        })
    }
}

// now that I'm not storing the raw bytes on the Pe struct, I don't need to finishing doing all this manually.
// will keep for now though. This output is much more pleasant to read
impl fmt::Display for Pe {
    // This trait requires `fmt` with this exact signature.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "\nPE File: {:?}\n==========================================",
            self.path
        )?;
        write!(f, "{}", self.dos_header)?;
        write!(f, "{}", self.coff_header)
    }
}
