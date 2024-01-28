use crate::prelude::*;

/*
 * Optional Header:
+18  (24)   WORD    Magic
+1A  (26)	BYTE	MajorLinkerVersion
+1B  (27)	BYTE	MinorLinkerVersion
+1C  (28)	DWORD	SizeOfCode
+20  (32)	DWORD	SizeOfInitializedData
+24  (36)	DWORD	SizeOfUnitializedData
+28  (40)	DWORD	AddressOfEntryPoint
+2C  (44)	DWORD	offsetOfCode
+30  (48)	DWORD	offsetOfData
     -NT additional fields-
+34  (52)	DWORD	Imageoffset
+38  (56)	DWORD	SectionAlignment
+3C (60)	DWORD	FileAlignment
+40  (64)	WORD	MajorOperatingSystemVersion
+42  (66)	WORD	MinorOperatingSystemVersion
+44  (68)	WORD	MajorImageVersion
+46  (70)	WORD	MinorImageVersion
+48  (72)	WORD	MajorSubsystemVersion
+4A  (74)	WORD	MinorSubsystemVersion
+4C  (76)	DWORD	Reserved1
+50  (80)	DWORD	SizeOfImage
+54  (84)	DWORD	SizeOfHeaders
+58  (88)	DWORD	CheckSum
+5C  (92)	WORD	Subsystem
+5E  (94)	WORD	DllCharacteristics
+60  (96)	DWORD	SizeOfStackReserve
+64  (100)	DWORD	SizeOfStackCommit
+68  (104)	DWORD	SizeOFHeapReserve
+6C  (108)	DWORD	SizeOfHeapCommit
+70  (112)	DWORD	LoaderFlags
+74  (116)	DWORD	NumberOfRvaAndSizes
+78  (120)	DWORD	ExportDirectory VA
+7C  (124)	DWORD	ExportDirectory Size
+80  (128)	DWORD	ImportDirectory VA
+84  (132)	DWORD	ImportDirectory Size
+88  (136)	DWORD	ResourceDirectory VA
+8C  (140)	DWORD	ResourceDirectory Size
+90  (144)	DWORD	ExceptionDirectory VA
+94  (148)	DWORD	ExceptionDirectory Size
+98  (152)	DWORD	SecurityDirectory VA
+9C  (156)	DWORD	SecurityDirectory Size
+A0  (160)	DWORD	offsetRelocationTable VA
+A4  (164)	DWORD	offsetRelocationTable Size
+A8  (168)	DWORD	DebugDirectory VA
+AC  (172)	DWORD	DebugDirectory Size
+B0  (176)	DWORD	ArchitectureSpecificData VA
+B4  (180)	DWORD	ArchitectureSpecificData Size
+B8  (184)	DWORD	RVAofGP VA
+BC  (188)	DWORD	RVAofGP Size
+C0  (192)	DWORD	TLSDirectory VA
+C4  (196)	DWORD	TLSDirectory Size
+C8  (200)	DWORD	LoadConfigurationDirectory VA
+CC  (204)	DWORD	LoadConfigurationDirectory Size
+D0  (208)	DWORD	BoundImportDirectoryinheaders VA
+D4  (212)	DWORD	BoundImportDirectoryinheaders Size
+D8  (216)	DWORD	ImportAddressTable VA
+DC  (220)	DWORD	ImportAddressTable Size
+E0  (224)	DWORD	DelayLoadImportDescriptors VA
+E4  (228)	DWORD	DelayLoadImportDescriptors Size
+E8  (232)	DWORD	COMRuntimedescriptor VA
+EC  (236)	DWORD	COMRuntimedescriptor Size
+F0  (240)	DWORD	0
+F4  (244)	DWORD	0
 */
#[derive(Debug)]
pub struct OptionalHeader {
    // standard fields
    pub magic: PeFormat,
    pub major_linked_version: u8,
    pub minor_linked_version: u8,
    pub size_of_code: u32,
    pub size_initialized_data: u32,
    pub size_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: Option<u32>,
    // windows specifc fields
    pub image_offset: ArchDependentSized,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub reserved1: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_stack_reserve: ArchDependentSized,
    pub size_stack_commit: ArchDependentSized,
    pub size_heap_reserve: ArchDependentSized,
    pub size_heap_commit: ArchDependentSized,
    pub loader_flags: u32,
    pub num_rva_and_sizes: u32,
    //pub export_dir_va: u32,
    //pub export_dir_size: u32,
    //pub import_dir_va: u32,
    //pub import_dir_size: u32,
    //pub security_dir_va: u32,
    //pub security_dir_size: u32,
    //pub offset_relocation_table_va: u32,
    //pub offset_relocation_table_size: u32,
    //pub arch_specific_data_va: u32,
    //pub arch_specific_data_size: u32,
    //pub rva_gp_va: u32,
    //pub rva_gp_size: u32,
    //pub tls_dir_va: u32,
    //pub tls_dir_size: u32,
    pub data_directories: DataDirectories,
}

impl OptionalHeader {
    pub fn new(raw: &[u8]) -> Result<Self, ParsingError> {
        let mut offset: usize = 0; // optional header starts
        let magic: PeFormat = match read_word(&raw, &mut offset) {
            0x10b => PeFormat::PE32,
            0x20b => PeFormat::PE32P,
            _ => {
                return Err(ParsingError::Malformed {
                    reason: "failed to parse optional header PE format".to_string(),
                })
            }
        };
        let major_linked_version = read_byte(&raw, &mut offset);
        let minor_linked_version = read_byte(&raw, &mut offset);
        let size_of_code = read_dword(&raw, &mut offset);
        let size_initialized_data = read_dword(&raw, &mut offset);
        let size_uninitialized_data = read_dword(&raw, &mut offset);
        let address_of_entry_point = read_dword(&raw, &mut offset);
        let base_of_code = read_dword(&raw, &mut offset);

        let base_of_data: Option<u32> = match magic {
            PeFormat::PE32 => Some(read_dword(&raw, &mut offset)),
            _ => None,
        };

        let image_offset = ArchDependentSized::new(&raw, &mut offset, &magic);
        let section_alignment = read_dword(&raw, &mut offset);
        let file_alignment = read_dword(&raw, &mut offset);
        let major_operating_system_version = read_word(&raw, &mut offset);
        let minor_operating_system_version = read_word(&raw, &mut offset);
        let major_image_version = read_word(&raw, &mut offset);
        let minor_image_version = read_word(&raw, &mut offset);
        let major_subsystem_version = read_word(&raw, &mut offset);
        let minor_subsystem_version = read_word(&raw, &mut offset);
        let reserved1 = read_dword(&raw, &mut offset);
        let size_of_image = read_dword(&raw, &mut offset);
        let size_of_headers = read_dword(&raw, &mut offset);
        let checksum = read_dword(&raw, &mut offset);
        let subsystem = read_word(&raw, &mut offset);
        let dll_characteristics = read_word(&raw, &mut offset);
        let size_stack_reserve = ArchDependentSized::new(&raw, &mut offset, &magic);
        let size_stack_commit = ArchDependentSized::new(&raw, &mut offset, &magic);
        let size_heap_reserve = ArchDependentSized::new(&raw, &mut offset, &magic);
        let size_heap_commit = ArchDependentSized::new(&raw, &mut offset, &magic);
        let loader_flags = read_dword(&raw, &mut offset);
        let num_rva_and_sizes = read_dword(&raw, &mut offset);

        // time to parse data directories
        let data_directories: DataDirectories = DataDirectories::new(raw, &mut offset);

        Ok(Self {
            magic,
            major_linked_version,
            minor_linked_version,
            size_of_code,
            size_initialized_data,
            size_uninitialized_data,
            address_of_entry_point,
            base_of_code,
            base_of_data,
            image_offset,
            section_alignment,
            file_alignment,
            major_operating_system_version,
            minor_operating_system_version,
            major_image_version,
            minor_image_version,
            major_subsystem_version,
            minor_subsystem_version,
            reserved1,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            size_stack_reserve,
            size_stack_commit,
            size_heap_reserve,
            size_heap_commit,
            loader_flags,
            num_rva_and_sizes,
            //export_dir_va,
            //export_dir_size,
            //import_dir_va,
            //import_dir_size,
            //security_dir_va,
            //security_dir_size,
            //offset_relocation_table_va,
            //offset_relocation_table_size,
            //arch_specific_data_va,
            //arch_specific_data_size,
            //rva_gp_va,
            //rva_gp_size,
            //tls_dir_va,
            //tls_dir_size,
            data_directories,
        })
    }
}

#[derive(Debug)]
pub struct DataDirectories {
    pub export_table: ImageDataDirectory,
    pub import_table: ImageDataDirectory,
    pub resource_table: ImageDataDirectory,
    pub exception_table: ImageDataDirectory,
    pub certificate_table: ImageDataDirectory,
    pub offset_relocation_table: ImageDataDirectory,
    pub debug_table: ImageDataDirectory,
    pub architecture: ImageDataDirectory,
    pub global_ptr: ImageDataDirectory,
    pub tls_table: ImageDataDirectory,
    pub load_config_table: ImageDataDirectory,
    pub bound_import_table: ImageDataDirectory,
    pub import_address_table: ImageDataDirectory,
    pub delay_import_descriptor: ImageDataDirectory,
    pub clr_runtime_header: ImageDataDirectory,
}

impl DataDirectories {
    fn new(raw: &[u8], offset: &mut usize) -> Self {
        let export_table = ImageDataDirectory::new(raw, offset);
        let import_table = ImageDataDirectory::new(raw, offset);
        let resource_table = ImageDataDirectory::new(raw, offset);
        let exception_table = ImageDataDirectory::new(raw, offset);
        let certificate_table = ImageDataDirectory::new(raw, offset);
        let offset_relocation_table = ImageDataDirectory::new(raw, offset);
        let debug_table = ImageDataDirectory::new(raw, offset);
        let architecture = ImageDataDirectory::new(raw, offset);
        let global_ptr = ImageDataDirectory::new(raw, offset);
        let tls_table = ImageDataDirectory::new(raw, offset);
        let load_config_table = ImageDataDirectory::new(raw, offset);
        let bound_import_table = ImageDataDirectory::new(raw, offset);
        let import_address_table = ImageDataDirectory::new(raw, offset);
        let delay_import_descriptor = ImageDataDirectory::new(raw, offset);
        let clr_runtime_header = ImageDataDirectory::new(raw, offset);

        Self {
            export_table,
            import_table,
            resource_table,
            exception_table,
            certificate_table,
            offset_relocation_table,
            debug_table,
            architecture,
            global_ptr,
            tls_table,
            load_config_table,
            bound_import_table,
            import_address_table,
            delay_import_descriptor,
            clr_runtime_header,
        }
    }
}

#[derive(Debug)]
pub struct ImageDataDirectory {
    pub virtual_addr: u32,
    pub size: u32,
}

impl ImageDataDirectory {
    fn new(raw: &[u8], offset: &mut usize) -> Self {
        let virtual_addr = read_dword(raw, offset);
        let size = read_dword(raw, offset);
        Self { virtual_addr, size }
    }
}
