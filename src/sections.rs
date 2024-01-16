use super::prelude::*;

pub struct SectionTable {
    pub section_headers: Vec<SectionHeader>,
}

impl SectionTable {
    pub fn new(raw: &[u8], num_sections: usize) -> Result<Self, Box<dyn std::error::Error>> {
        let mut offset: usize = 0; // optional header starts
        let mut section_headers = Vec::with_capacity(num_sections);
        for _ in 0..section_headers.len() {
            let section_header = SectionHeader::new(raw, &mut offset);
            section_headers.push(section_header);
        }

        Ok(Self { section_headers })
    }
}

pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_raw_data: u32,
    pub pointer_raw_data: u32,
    pub pointer_relocations: u32,
    pub pointer_line_numbers: u32,
    pub number_relocations: u16,
    pub number_line_numbers: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    pub fn new(raw: &[u8], offset: &mut usize) -> Self {
        let name =
            read_utf8(raw, offset, DWORDLONG_SZ).expect("failed to parse section header name");
        let virtual_size = read_dword(raw, offset);
        let virtual_address = read_dword(raw, offset);
        let size_raw_data = read_dword(raw, offset);
        let pointer_raw_data = read_dword(raw, offset);
        let pointer_relocations = read_dword(raw, offset);
        let pointer_line_numbers = read_dword(raw, offset);
        let number_relocations = read_word(raw, offset);
        let number_line_numbers = read_word(raw, offset);
        let characteristics = read_dword(raw, offset);

        Self {
            name,
            virtual_size,
            virtual_address,
            size_raw_data,
            pointer_raw_data,
            pointer_relocations,
            pointer_line_numbers,
            number_relocations,
            number_line_numbers,
            characteristics,
        }
    }
}
