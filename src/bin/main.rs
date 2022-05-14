// - extern crates
#[macro_use] extern crate serde;

// - STD
use std::fs::{File};

use std::process::exit;
use std::io::{Seek, Read, SeekFrom};

use std::collections::HashMap;

// - modules
mod lib;

// - internal
use lib::*;
use lib::constants::*;
use zff::{
    Result,
    constants::*,
    header::version1::{MainHeader as MainHeaderV1, SegmentHeader as SegmentHeaderV1, ChunkHeader as ChunkHeaderV1},
    footer::version1::{SegmentFooter as SegmentFooterV1},
    header::version2::{MainHeader as MainHeaderV2, SegmentHeader as SegmentHeaderV2, ObjectHeader, FileHeader, HashHeader as HashHeaderV2},
    footer::version2::{SegmentFooter as SegmentFooterV2, MainFooter, ObjectFooterPhysical, ObjectFooterLogical, FileFooter},
    ValueDecoder,
    HeaderCoding,
    ZffErrorKind,
};

// - external
use clap::{Parser, ArgEnum};

#[derive(Parser)]
#[clap(about, version, author)]
struct Cli {

    /// The input files. This should be your zff image files. You can use this Option multiple times.
    #[clap(short='i', long="inputfiles", multiple_values=true)]
    inputfiles: Vec<String>,

    /// The output format.
    #[clap(short='f', long="output-format", arg_enum, default_value="toml")]
    output_format: OutputFormat,

    /// Verbose mode to show each chunk information.
    #[clap(short='v', long="verbose")]
    verbose: bool,

    ///TODO: Implement
    /// The password, if the file has an encrypted main header
    #[clap(short='p', long="decryption-password")]
    decryption_password: Option<String>,

    ///TODO: Implement
    /// The path to the file which contains the public key.
    #[clap(short='k', long="publickey-file")]
    publickey_file: Option<String>,

    ///TODO: Implement
    /// Checks the integrity of the imaged data by calculating/comparing the used hash values.
    #[clap(short='c', long="integrity-check")]
    check_integrity: bool,
}

#[derive(ArgEnum, Clone)]
enum OutputFormat {
    Toml,
    Json,
    JsonPretty
}

enum HeaderType {
    MainHeaderV1(Box<MainHeaderV1>),
    MainHeaderV2(MainHeaderV2),
    SegmentHeaderV1(SegmentHeaderV1),
    SegmentHeaderV2(SegmentHeaderV2),
}

fn main() {
    let args = Cli::parse();
    let mut files = HashMap::new(); //<file number of .zXX file, std::file::File>
    let mut file_numbers = Vec::new(); //zff file numbers
    let mut segments_map = HashMap::new(); // <segment number, file number of .zXX file>
    let mut file_number = 0; // file number of .zXX file
    let mut logical_object_footer_map = HashMap::new(); // <unique identifier, <object number, logical object footer>>
    for inputfile in &args.inputfiles {
        match File::open(&inputfile) {
            Ok(file) => {
                files.insert(file_number, file);
                file_numbers.push(file_number);
                file_number +=1;
            },
            Err(err_msg) => {
                eprintln!("{ERROR_OPEN_INPUT_FILE}{err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        }
    };

    let mut information: HashMap<i64, Vec<Information>> = HashMap::new();

    for file_number in file_numbers {
        // - unwrap should be safe here, because we have filled the map and the vector above with the correct file numbers.
        let file = files.get_mut(&file_number).unwrap();
        let header_type = match get_header(file, &args) {
            Ok(ht) => ht,
            Err(err_msg) => {
                eprintln!("{ERROR_FILE_READ}{err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        };
        match header_type {
            HeaderType::MainHeaderV1(main_header) => {
                let unique_identifier = main_header.unique_identifier();

                let first_segment_header = match SegmentHeaderV1::decode_directly(file) {
                    Ok(header) => header,
                    Err(e) => {
                        eprintln!("{ERROR_DECODE_SEGMENT_HEADER}1\n{e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                };
                let segment_information = match get_segment_information_v1(&args, file, first_segment_header) {
                    Ok(seg_info) => seg_info,
                    Err(e) => {
                        eprintln!("{ERROR_GET_SEGMENT_INFORMATION_V1}{e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                };

                let compression_information = CompressionInformation {
                    algorithm: CompressionAlgorithmInformation::from(main_header.compression_header().algorithm()),
                    level: *main_header.compression_header().level(),
                    threshold: main_header.compression_header().threshold(),
                };
                let main_information = MainInformationV1 {
                    chunk_size: main_header.chunk_size() as u64,
                    signature_flag: main_header.has_signature(),
                    segment_size: main_header.segment_size(),
                    number_of_segments: main_header.number_of_segments(),
                    length_of_data: main_header.length_of_data(),
                    compression_information,
                    segment_information,
                };

                match information.get_mut(&unique_identifier) {
                    Some(data) => data.push(Information::MainInformationV1(main_information)),
                    None => { 
                        information.insert(unique_identifier, Vec::new());
                        information.get_mut(&unique_identifier).unwrap().push(Information::MainInformationV1(main_information));
                    },
                };
            },
            HeaderType::SegmentHeaderV1(segment_header) => {
                let unique_identifier = segment_header.unique_identifier();
                let segment_information = match get_segment_information_v1(&args, file, segment_header) {
                    Ok(seg_info) => seg_info,
                    Err(e) => {
                        eprintln!("{ERROR_GET_SEGMENT_INFORMATION_V1}{e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                };
                match information.get_mut(&unique_identifier) {
                    Some(data) => data.push(Information::SegmentInformation(segment_information)),
                    None => { 
                        information.insert(unique_identifier, Vec::new());
                        information.get_mut(&unique_identifier).unwrap().push(Information::SegmentInformation(segment_information));
                    },
                };
            }
            HeaderType::MainHeaderV2(main_header) => {
                let unique_identifier = main_header.unique_identifier();
                // First segment
                let first_segment_header = match SegmentHeaderV2::decode_directly(file) {
                    Ok(header) => header,
                    Err(e) => {
                        eprintln!("{ERROR_DECODE_SEGMENT_HEADER}2\n{e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                };
                segments_map.insert(first_segment_header.segment_number(), file_number);
                let segment_information = match get_segment_information_v2(&args, file, first_segment_header, &mut information, &mut logical_object_footer_map) {
                    Ok(seg_info) => seg_info,
                    Err(e) => {
                        eprintln!("{ERROR_GET_SEGMENT_INFORMATION_V2}{e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                };
                // - MainHeader
                let main_information = MainHeaderInformationV2 {
                    chunk_size: main_header.chunk_size() as u64,
                    segment_size: main_header.segment_size(),
                    segment_information,
                };
                match information.get_mut(&unique_identifier) {
                    Some(data) => data.push(Information::MainHeaderInformationV2(main_information)),
                    None => { 
                        information.insert(unique_identifier, Vec::new());
                        information.get_mut(&unique_identifier).unwrap().push(Information::MainHeaderInformationV2(main_information));
                    },
                };
                // - MainFooter
                if let Ok(main_footer) = get_main_footer(file) {
                    let main_footer_information = MainFooterInformation {
                        number_of_segments: main_footer.number_of_segments(),
                        description_notes: main_footer.description_notes().map(|s| s.to_string()),
                    };
                    match information.get_mut(&unique_identifier) {
                        Some(data) => data.push(Information::MainFooterInformation(main_footer_information)),
                        None => { 
                            information.insert(unique_identifier, Vec::new());
                            information.get_mut(&unique_identifier).unwrap().push(Information::MainFooterInformation(main_footer_information));
                        },
                    };
                }
            }
            HeaderType::SegmentHeaderV2(segment_header) => {
                let unique_identifier = segment_header.unique_identifier();
                segments_map.insert(segment_header.segment_number(), file_number);
                let segment_information = match get_segment_information_v2(&args, file, segment_header, &mut information, &mut logical_object_footer_map) {
                    Ok(seg_info) => seg_info,
                    Err(e) => {
                        eprintln!("{ERROR_GET_SEGMENT_INFORMATION_V2}{e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                };

                if let Ok(main_footer) = get_main_footer(file) {
                    let main_footer_information = MainFooterInformation {
                        number_of_segments: main_footer.number_of_segments(),
                        description_notes: main_footer.description_notes().map(|s| s.to_string()),
                    };
                    match information.get_mut(&unique_identifier) {
                        Some(data) => data.push(Information::MainFooterInformation(main_footer_information)),
                        None => { 
                            information.insert(unique_identifier, Vec::new());
                            information.get_mut(&unique_identifier).unwrap().push(Information::MainFooterInformation(main_footer_information));
                        },
                    };
                }
                match information.get_mut(&unique_identifier) {
                    Some(data) => data.push(Information::SegmentInformation(segment_information)),
                    None => { 
                        information.insert(unique_identifier, Vec::new());
                        information.get_mut(&unique_identifier).unwrap().push(Information::SegmentInformation(segment_information));
                    },
                };
            }
        }
    }
    for (unique_identifier, inner_logical_object_footer_map) in &logical_object_footer_map {
       for (object_number, logical_object_footer) in inner_logical_object_footer_map {
        let mut object_footer_information_logical = ObjectFooterInformationLogical {
            object_number: *object_number,
            file_header_map: HashMap::new(),
            file_footer_map: HashMap::new(),
        };
        for (file_number, segment_number) in logical_object_footer.file_header_segment_numbers() {
             //TODO: Error handling if verbose mode=on - or logging to STDERR?
            if let Some(offset) = logical_object_footer.file_header_offsets().get(file_number) {
                //TODO: Error handling if verbose mode=on? - or logging to STDERR?
                if let Some(zff_file_number) = segments_map.get(segment_number) {
                    //TODO: Error handling if verbose mode=on? - or logging to STDERR? with match and continue?
                    if let Some(file) = files.get_mut(zff_file_number) {
                        //TODO: Error handling if verbose mode=on? - or logging to STDERR? with match and continue?
                        if let Ok(file_header_information) = get_file_header_information(file, *offset) {
                            object_footer_information_logical.file_header_map.insert(*file_number, file_header_information);
                        }
                            
                    }
                }
            }
        }

        for (file_number, segment_number) in logical_object_footer.file_footer_segment_numbers() {
             //TODO: Error handling if verbose mode=on - or logging to STDERR?
            if let Some(offset) = logical_object_footer.file_footer_offsets().get(file_number) {
                //TODO: Error handling if verbose mode=on? - or logging to STDERR?
                if let Some(zff_file_number) = segments_map.get(segment_number) {
                    //TODO: Error handling if verbose mode=on? - or logging to STDERR? with match and continue?
                    if let Some(file) = files.get_mut(zff_file_number) {
                        //TODO: Error handling if verbose mode=on? - or logging to STDERR? with match and continue?
                        if let Ok(file_footer_information) = get_file_footer_information(file, *offset) {
                            object_footer_information_logical.file_footer_map.insert(*file_number, file_footer_information);
                        }
                            
                    }
                }
            }
        }            match information.get_mut(unique_identifier) {
                Some(data) => data.push(Information::ObjectFooterInformationLogical(object_footer_information_logical)),
                None => { 
                    information.insert(*unique_identifier, Vec::new());
                    information.get_mut(unique_identifier).unwrap().push(Information::ObjectFooterInformationLogical(object_footer_information_logical));
                },
            }; 
        }
    }

    match args.output_format {
        OutputFormat::Toml => {
            let mut stringified_hashmap = HashMap::new();
            for (unique_identifier, value) in information.drain() {
                stringified_hashmap.insert(unique_identifier.to_string(), value);
            }
            match toml::Value::try_from(&stringified_hashmap) {
                Ok(value) => {
                    println!("{}", value);
                    exit(EXIT_STATUS_SUCCESS);
                },
                Err(e) => {
                    eprintln!("{ERROR_SERIALIZE_TOML}{e}");
                    exit(EXIT_STATUS_ERROR);
                }
            };
        },
    
        OutputFormat::Json => match serde_json::to_string(&information) {
            Ok(value) => {
                println!("{}", value);
                exit(EXIT_STATUS_SUCCESS);
            },
            Err(e) => {
                eprintln!("{ERROR_SERIALIZE_JSON}{e}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        OutputFormat::JsonPretty => match serde_json::to_string_pretty(&information) {
            Ok(value) => {
                println!("{}", value);
                exit(EXIT_STATUS_SUCCESS);
            },
            Err(e) => {
                eprintln!("{ERROR_SERIALIZE_JSON}{e}");
                exit(EXIT_STATUS_ERROR);
            }
        },
    }
}

fn get_main_footer(file: &mut File) -> Result<MainFooter> {
    file.seek(SeekFrom::End(-8))?;
    let footer_offset = u64::decode_directly(file)?;
    file.seek(SeekFrom::Start(footer_offset))?;
    let main_footer = MainFooter::decode_directly(file)?;
    Ok(main_footer)
}

fn get_object_header_information(file: &mut File, offset: u64) -> Result<ObjectHeaderInformation> {
    file.seek(SeekFrom::Start(offset))?;
    let object_header = ObjectHeader::decode_directly(file)?;
    let compression_information = CompressionInformation {
        algorithm: CompressionAlgorithmInformation::from(object_header.compression_header().algorithm()),
        level: *object_header.compression_header().level(),
        threshold: object_header.compression_header().threshold(),
    };
    let description_header_information = DescriptionHeaderInformation {
        information: object_header.description_header().identifier_map().clone(),
    };
    let object_header_information = ObjectHeaderInformation {
        object_number: object_header.object_number(),
        compression_information,
        signature_flag: object_header.signature_flag().clone(),
        object_type: object_header.object_type(),
        description_header: description_header_information,
    };
    Ok(object_header_information)
}

fn get_object_footer_information_physical(file: &mut File, offset: u64, object_number: u64) -> Result<ObjectFooterInformationPhysical> {
    file.seek(SeekFrom::Start(offset))?;
    let object_footer_physical = ObjectFooterPhysical::decode_directly(file)?;
    let hash_information = hash_information_v2(object_footer_physical.hash_header());
    let get_object_footer_information_physical = ObjectFooterInformationPhysical {
        object_number,
        acquisition_start: object_footer_physical.acquisition_start(),
        acquisition_end: object_footer_physical.acquisition_end(),
        length_of_data: object_footer_physical.length_of_data(),
        number_of_chunks: object_footer_physical.number_of_chunks(),
        hash_information
    };

    Ok(get_object_footer_information_physical)
}

fn set_object_footer_information_logical(
    unique_identifier: i64,
    logical_object_footer_map: &mut HashMap<i64, HashMap<u64, ObjectFooterLogical>>, // <unique identifier, <object number, object footer>
    file: &mut File,
    offset: u64,
    object_number: u64) -> Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    let object_footer_logical = ObjectFooterLogical::decode_directly(file)?;
    match logical_object_footer_map.get_mut(&unique_identifier) {
        Some(inner_map) => { inner_map.insert(object_number, object_footer_logical); },
        None => {
            logical_object_footer_map.insert(unique_identifier, HashMap::new());
            logical_object_footer_map.get_mut(&unique_identifier).unwrap().insert(object_number, object_footer_logical);
        },
    }
    Ok(())
}

fn get_file_header_information(file: &mut File, offset: u64) -> Result<FileHeaderInformation> {
    file.seek(SeekFrom::Start(offset))?;
    let file_header = FileHeader::decode_directly(file)?;
    Ok(FileHeaderInformation {
        file_type: file_header.file_type(),
        filename: file_header.filename().to_string(),
        parent_file_number: file_header.parent_file_number(),
        atime: file_header.atime(),
        mtime: file_header.mtime(),
        ctime: file_header.ctime(),
        btime: file_header.btime(),
        metadata_extended_information: file_header.metadata_ext().clone(),
    })
}
fn get_file_footer_information(file: &mut File, offset: u64) -> Result<FileFooterInformation> {
    file.seek(SeekFrom::Start(offset))?;
    let file_footer = FileFooter::decode_directly(file)?;
    Ok(FileFooterInformation{
        acquisition_start: file_footer.acquisition_start(),
        acquisition_end: file_footer.acquisition_end(),
        hash_information: hash_information_v2(file_footer.hash_header()),
        number_of_chunks: file_footer.number_of_chunks(),
        length_of_data: file_footer.length_of_data()
    })
}

fn hash_information_v2(hash_header: &HashHeaderV2) -> Vec<HashInformation> {
    let mut hash_information_vec = Vec::new();
    for hash_value in hash_header.hash_values() {
        hash_information_vec.push(HashInformation{
            hash_type: hash_value.hash_type().clone(),
            hash: hash_value.hash().to_vec(),
            ed25519_signature: hash_value.ed25519_signature()
        })
    }
    hash_information_vec
}

fn get_segment_information_v2(
    args: &Cli,
    file: &mut File,
    segment_header: SegmentHeaderV2,
    global_information_map: &mut HashMap<i64, Vec<Information>>,
    logical_object_footer_map: &mut HashMap<i64, HashMap<u64, ObjectFooterLogical>> //<unique identifier, <object number, logical footer>>
    ) -> Result<SegmentInformation> {
    match get_main_footer(file) {
        Ok(_) => {
            file.seek(SeekFrom::End(-8))?;
            let footer_offset = u64::decode_directly(file)?;
            file.seek(SeekFrom::Start(footer_offset))?;
            file.seek(SeekFrom::Current(-8))?
        },
        Err(_) => file.seek(SeekFrom::End(-8))?,
    };
    let footer_offset = u64::decode_directly(file)?;
    file.seek(SeekFrom::Start(footer_offset))?;
    let segment_footer = SegmentFooterV2::decode_directly(file)?;
    let mut segment_information = SegmentInformation {
        segment_number: segment_header.segment_number(),
        length_of_segment: segment_footer.length_of_segment(),
        chunk_information: Vec::new()
    };
    if args.verbose {
        for offset in segment_footer.chunk_offsets().values() {
            file.seek(SeekFrom::Start(*offset))?;
            let chunk_header = ChunkHeaderV1::decode_directly(file)?;

            let chunk_information = ChunkInformation {
                chunk_number: chunk_header.chunk_number(),
                chunk_size: *chunk_header.chunk_size(),
                crc32: chunk_header.crc32(),
                error_flag: chunk_header.error_flag(),
                compression_flag: chunk_header.compression_flag(),
                ed25519_signature: *chunk_header.signature(),
            };

            segment_information.chunk_information.push(chunk_information);
        }
    }
    let unique_identifier = segment_header.unique_identifier();
    // - ObjectHeader
    for (object_number, offset) in segment_footer.object_header_offsets() {
        match get_object_header_information(file, *offset) {
            Ok(object_header_information) => {
                match global_information_map.get_mut(&unique_identifier) {
                    Some(data) => data.push(Information::ObjectHeaderInformation(object_header_information)),
                    None => { 
                        global_information_map.insert(unique_identifier, Vec::new());
                        global_information_map.get_mut(&unique_identifier).unwrap().push(Information::ObjectHeaderInformation(object_header_information));
                    },
                };
            },
            Err(e) => match e.get_kind() {
                ZffErrorKind::HeaderDecodeEncryptedHeader => eprintln!("Warning: object header of object {object_number} is encrypted and not readable."),
                _ => eprintln!("Error: get_object_header_information: {e}"),
            }
        }
    }
    // - ObjectFooter
    for (object_number, offset) in segment_footer.object_footer_offsets() {
        match get_object_footer_information_physical(file, *offset, *object_number) {
            Ok(object_footer_information) => {
                match global_information_map.get_mut(&unique_identifier) {
                    Some(data) => data.push(Information::ObjectFooterInformationPhysical(object_footer_information)),
                    None => { 
                        global_information_map.insert(unique_identifier, Vec::new());
                        global_information_map.get_mut(&unique_identifier).unwrap().push(Information::ObjectFooterInformationPhysical(object_footer_information));
                    },
                };
            },
            Err(_) => match set_object_footer_information_logical(unique_identifier, logical_object_footer_map, file, *offset, *object_number) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!("Error: set_object_footer_information_logical: {e}");
                }
            }
        }
    }
    
    Ok(segment_information)
}

fn get_segment_information_v1(args: &Cli, file: &mut File, segment_header: SegmentHeaderV1) -> Result<SegmentInformation> {
    let mut segment_information = SegmentInformation {
        segment_number: segment_header.segment_number(),
        length_of_segment: segment_header.length_of_segment(),
        chunk_information: Vec::new()
    };
    if args.verbose {
        file.seek(SeekFrom::Start(segment_header.footer_offset()))?;
        let segment_footer = SegmentFooterV1::decode_directly(file)?;
        for offset in segment_footer.chunk_offsets() {
            file.seek(SeekFrom::Start(*offset))?;
            let chunk_header = ChunkHeaderV1::decode_directly(file)?;

            let chunk_information = ChunkInformation {
                chunk_number: chunk_header.chunk_number(),
                chunk_size: *chunk_header.chunk_size(),
                crc32: chunk_header.crc32(),
                error_flag: chunk_header.error_flag(),
                compression_flag: chunk_header.compression_flag(),
                ed25519_signature: *chunk_header.signature(),
            };

            segment_information.chunk_information.push(chunk_information);
        }
    }
    Ok(segment_information)
}

fn get_header(inputfile: &mut File,  args: &Cli) -> Result<HeaderType> {
    //read header signature and version
    let mut header_signature = [0u8; HEADER_SIGNATURE_LENGTH];
    let mut header_length = [0u8; HEADER_LENGTH_LENGTH];
    let mut header_version = [0u8; HEADER_VERSION_LENGTH];
    inputfile.read_exact(&mut header_signature)?;
    inputfile.read_exact(&mut header_length)?;
    inputfile.read_exact(&mut header_version)?;
    inputfile.rewind()?;

    if u32::from_be_bytes(header_signature) == HEADER_IDENTIFIER_MAIN_HEADER {
        main_header(inputfile, u8::from_be_bytes(header_version))
    } else if u32::from_be_bytes(header_signature) == HEADER_IDENTIFIER_ENCRYPTED_MAIN_HEADER {
        match &args.decryption_password {
            None => {
                eprintln!("{ERROR_DECRYPTION_PASSWORD_NEEDED}");
                exit(EXIT_STATUS_ERROR);
            },
            Some(decryption_password) => encrypted_main_header(inputfile, u8::from_be_bytes(header_version), decryption_password),
        }
    } else if u32::from_be_bytes(header_signature) == HEADER_IDENTIFIER_SEGMENT_HEADER {
        segment_header(inputfile, u8::from_be_bytes(header_version))
    } else {
        eprintln!("{ERROR_UNKNOWN_HEADER}");
        exit(EXIT_STATUS_ERROR);
    }
}

fn main_header(inputfile: &mut File, header_version: u8) -> Result<HeaderType> {
    match header_version {
        1 => match MainHeaderV1::decode_directly(inputfile) {
            Ok(main_header) => Ok(HeaderType::MainHeaderV1(Box::new(main_header))),
            Err(err_msg) => {
                eprintln!("{ERROR_PARSE_MAIN_HEADER}{err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        2 => match MainHeaderV2::decode_directly(inputfile) {
            Ok(main_header) => Ok(HeaderType::MainHeaderV2(main_header)),
            Err(err_msg) => {
                eprintln!("{ERROR_PARSE_MAIN_HEADER} {err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        version => {
            eprintln!("{ERROR_UNSUPPORTED_ZFF_MAIN_HEADER_VERSION}{version}");
            exit(EXIT_STATUS_ERROR);
        },
    }
}

fn encrypted_main_header<P: AsRef<[u8]>>(inputfile: &mut File, header_version: u8, decryption_password: P) -> Result<HeaderType> {
    match header_version {
        1 => {
            match MainHeaderV1::decode_encrypted_header_with_password(inputfile, decryption_password) {
                Ok(main_header) => Ok(HeaderType::MainHeaderV1(Box::new(main_header))),
                Err(err) => {
                    match err.get_kind() {
                        ZffErrorKind::PKCS5CryptoError => println!("{ERROR_PARSE_ENCRYPTED_MAIN_HEADER}{ERROR_WRONG_PASSWORD}"),
                        _ => println!("{ERROR_PARSE_ENCRYPTED_MAIN_HEADER}{err}"),
                    };
                    exit(EXIT_STATUS_ERROR);
                }
            }
        },
        2 => match MainHeaderV2::decode_directly(inputfile) {
            Ok(main_header) => Ok(HeaderType::MainHeaderV2(main_header)),
            Err(err_msg) => {
                eprintln!("{ERROR_PARSE_MAIN_HEADER} {err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        version => {
            eprintln!("{ERROR_UNSUPPORTED_ZFF_MAIN_HEADER_VERSION}{version}");
            exit(EXIT_STATUS_ERROR);
        },
    }
}

fn segment_header(inputfile: &mut File, header_version: u8) -> Result<HeaderType> {
    match header_version {
        1 => match SegmentHeaderV1::decode_directly(inputfile) {
            Ok(segment_header) => Ok(HeaderType::SegmentHeaderV1(segment_header)),
            Err(err_msg) => {
                eprintln!("{ERROR_PARSE_SEGMENT_HEADER}{err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        2 => match SegmentHeaderV2::decode_directly(inputfile) {
            Ok(segment_header) => Ok(HeaderType::SegmentHeaderV2(segment_header)),
            Err(err_msg) => {
                eprintln!("{ERROR_PARSE_SEGMENT_HEADER}{err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        version => {
            eprintln!("{ERROR_UNSUPPORTED_ZFF_SEGMENT_HEADER_VERSION}{version}");
            exit(EXIT_STATUS_ERROR);
        }
    }
}