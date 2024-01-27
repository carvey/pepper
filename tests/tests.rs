use pepper;

#[cfg(test)]
mod tests {
    use pepper::utils::{ArchDependentSized, PeFormat};

    use super::pepper::pe::Pe;

    #[test]
    fn test_dos_header() {
        let pe = Pe::new("tests/test.exe").unwrap();
        assert_eq!(pe.dos_header.e_magic, "MZ".to_string())
    }

    #[test]
    fn test_coff_machine() {
        let pe = Pe::new("tests/test.exe").unwrap();
        assert_eq!(pe.coff_header.machine, 0x8664)
    }

    #[test]
    fn test_coff_size_optional_header() {
        let pe = Pe::new("tests/test.exe").unwrap();
        assert_eq!(pe.coff_header.size_optional_header, 0xf0)
    }

    #[test]
    fn test_optional_header_magic() {
        let pe = Pe::new("tests/test.exe").unwrap();
        assert_eq!(pe.optional_header.magic, PeFormat::PE32P)
    }

    #[test]
    fn test_optional_header_base_of_code() {
        let pe = Pe::new("tests/test.exe").unwrap();
        assert_eq!(pe.optional_header.base_of_code, 0x1000)
    }

    // base_of_data should only be defined on 32bit binaries
    // test binary is 64 bit (PE32P)
    #[test]
    fn test_optional_header_base_of_data() {
        let pe = Pe::new("tests/test.exe").unwrap();
        assert_eq!(pe.optional_header.base_of_data, None)
    }

    #[test]
    fn test_major_subsystem_version() {
        let pe = Pe::new("tests/test.exe").unwrap();
        assert_eq!(pe.optional_header.major_subsystem_version, 5);
    }

    #[test]
    fn test_optional_header_size_heap_reserve() {
        let pe = Pe::new("tests/test.exe").unwrap();
        assert_eq!(
            pe.optional_header.size_heap_reserve,
            ArchDependentSized::PE32P(0x100000)
        );
    }

    #[test]
    fn test_section_headers() {
        let pe = Pe::new("tests/test.exe").unwrap();
        let section_header_names: Vec<&str> = vec![
            ".text", ".data", ".rdata", ".pdata", ".xdata", ".bss", ".idata", ".CRT", ".tls",
            ".reloc", "/4", "/19", "/35", "/51", "/63", "/77", "/89", "/102", "/113", "/124",
        ];
        let test_pe_headers = pe.section_table.section_headers;

        // TODO: umm... ?
        for (correct, parsed) in section_header_names.iter().zip(test_pe_headers) {
            dbg!(correct);
            dbg!(&parsed.name);
            assert_eq!(*correct, parsed.name);
        }
    }
}
