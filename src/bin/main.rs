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
    header::version2::{MainHeader as MainHeaderV2, SegmentHeader as SegmentHeaderV2, ObjectHeader, FileHeader, HashHeader as HashHeaderV2, EncryptionHeader as EncryptionHeaderV2},
    footer::version2::{SegmentFooter as SegmentFooterV2, MainFooter, ObjectFooterPhysical, ObjectFooterLogical, FileFooter},
    ValueDecoder,
    HeaderCoding,
    ZffErrorKind,
    ZffReader,
    Object,
    Hash,
    Signature,
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

    /// The password(s), if the file(s) are encrypted. You can use this option multiple times to enter different passwords for different objects.
    #[clap(short='p', long="decryption-passwords", multiple_values=true)]
    decryption_passwords: Vec<String>,

    /// The public sign key to verify the appropriate signatures.
    #[clap(short='k', long="pub-key")]
    public_key: Option<String>,

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
    if args.check_integrity {
        match check_integrity(&args) {
            Ok(_) => exit(EXIT_STATUS_SUCCESS),
            Err(e) => {
                eprintln!("{ERROR_TRYING_CALCULATE_HASHES_}{e}");
                exit(EXIT_STATUS_ERROR);
            }
        }
    }

    if let Some(ref public_key) = args.public_key {
         match check_signatures(&args, public_key) {
            Ok(_) => exit(EXIT_STATUS_SUCCESS),
            Err(e) => {
                eprintln!("{ERROR_TRYING_VERIFY_SIGNATURES_}{e}");
                exit(EXIT_STATUS_ERROR);
            }
         }
    }

    if !args.check_integrity && args.public_key.is_none() {
        analyze(&args);
    }
}

fn gen_password_per_object_map(args: &Cli) -> Result<HashMap<u64, String>> {
    let mut files = Vec::new();
    for path in &args.inputfiles {
     let f = File::open(&path)?;
        files.push(f);
    };

    let temp_zffreader = ZffReader::new(files, HashMap::new())?;

    //check encryption and try to decrypt
    let mut passwords_per_object = HashMap::new();

    for object_number in temp_zffreader.undecryptable_objects() {
        let mut decryption_state = false;
        'inner:  for password in &args.decryption_passwords {
            let mut temp_pw_map = HashMap::new();
            temp_pw_map.insert(*object_number, password.to_string());

            let mut files = Vec::new();
            for path in &args.inputfiles {
                let f = File::open(&path)?;
                files.push(f);
            };
            let inner_temp_zffreader = match ZffReader::new(files, temp_pw_map) {
                Ok(zffreader) => zffreader,
                Err(e) => match e.get_kind() {
                    ZffErrorKind::PKCS5CryptoError => continue,
                    _ => return Err(e)
                },
            };
            if !inner_temp_zffreader.undecryptable_objects().contains(object_number) {
                passwords_per_object.insert(*object_number, password.to_string());
                decryption_state = true;
                break 'inner;
            }
        }
        if !decryption_state {
            eprintln!("{ERROR_DECRYPT_OBJECT_}{object_number} ({HINT_BAD_PASSWORD}).");
            exit(EXIT_STATUS_ERROR);
        }
    }

    Ok(passwords_per_object)
}

fn check_signatures(args: &Cli, public_key: &str) -> Result<()> {
    let mut files = Vec::new();
    for path in &args.inputfiles {
        let f = File::open(&path)?;
        files.push(f);
    };

    let mut zffreader = ZffReader::new(files, gen_password_per_object_map(args)?)?;

    let object_numbers = zffreader.object_numbers();

    let public_key = match base64::decode(public_key)?.try_into() {
        Ok(key) => key,
        Err(_) => {
            eprintln!("{ERROR_UNEXPECTED_PUBKEY_LENGTH}{} {SER_BYTES}", base64::decode(public_key)?.len());
            exit(EXIT_STATUS_ERROR);
        }
    };

    for object_number in object_numbers {
        let object = zffreader.object(object_number).unwrap().clone();
        if object.header().has_per_chunk_signatures() {
            println!("{M_VERIFING_PER_CHUNK_SIGS_OBJ_}{object_number} ...");

            match object {
                Object::Physical(_) => {
                    zffreader.set_reader_physical_object(object_number)?;
                },
                Object::Logical(_) => {
                    zffreader.set_reader_logical_object_file(object_number, 1)?;
                }
            }

            match zffreader.verify_chunk_signatures(public_key) {
                Err(e) => match e.get_kind() {
                    ZffErrorKind::NoSignatureFoundAtChunk => eprintln!("{ERROR_PER_CHUNK_SIGS_NO_SIGS_FOUND}"),
                    _ => return Err(e)
                },
                Ok(corrupt_chunks) => {
                    if corrupt_chunks.is_empty() {
                        println!("{M_ALL_SIGS_VALID}");
                    } else {
                        println!("{M_INVALID_SIGS_FOR_CHUNKS_}");
                        for chunk_no in corrupt_chunks {
                            print!("{} ", chunk_no);
                        }
                        println!(); 
                    }
                }
            }
        }

        if object.header().has_hash_signatures() {
            println!("{M_VERIFING_HASH_SIGS_OBJ_}{object_number} ...");

            match object {
                Object::Physical(ref obj_info) => {
                    for hash_value in obj_info.footer().hash_header().hash_values() {
                        let hash_type = hash_value.hash_type();
                        let hash = hash_value.hash();
                        let signature = match hash_value.ed25519_signature() {
                            Some(sig) => sig,
                            None => {
                                eprintln!("{M_NO_SIGS_FOUND_FOR_}{hash_type}.");
                                continue;
                            }
                        };
                        if Signature::verify(public_key, hash, signature)? {
                            println!("{M_VALID_SIG_FOR_}{hash_type}.");
                        } else {
                            println!("{M_INVALID_SIG_FOR_}{hash_type}.");
                        }
                    }
                    if obj_info.footer().hash_header().hash_values().is_empty() {
                        println!("{M_NO_HASHES_CALCULATED_IN_OBJ}");
                    }
                },
                Object::Logical(ref obj_info) => {
                    for (filenumber, file) in obj_info.files() {
                        let mut invalid_sig_found = false;
                        let mut hashes_calculated = false;
                        for hash_value in file.footer().hash_header().hash_values() {
                            hashes_calculated = true;
                            let hash = hash_value.hash();
                            let signature = match hash_value.ed25519_signature() {
                                Some(sig) => sig,
                                None => {
                                    eprintln!("{M_NO_SIGS_FOR_HASHES_OF_FILE_}{filenumber}");
                                    continue;
                                }
                            };
                            if !Signature::verify(public_key, hash, signature)? {
                                println!("{M_INVALID_HASH_SIG_OF_FILE_}{filenumber}.");
                                invalid_sig_found = true;
                            }
                        }
                        if !hashes_calculated {
                            println!("{M_NO_HASHES_CALCULATED_IN_OBJ}");
                        } else if !invalid_sig_found {
                            println!("{M_ALL_SIGS_VALID}");
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

//TODO: implement multi threading for this function
fn check_integrity(args: &Cli) -> Result<()> {
    let mut files = Vec::new();
    for path in &args.inputfiles {
        let f = File::open(&path)?;
        files.push(f);
    };

    let mut zffreader = ZffReader::new(files, gen_password_per_object_map(args)?)?;

    let object_numbers = zffreader.object_numbers();

    for object_number in object_numbers {
        println!("{M_CALCULATING_COMPARING_HASH_VALUES_OBJ_}{object_number} ...");
        let object = zffreader.object(object_number).unwrap().clone();
        match object {
            Object::Physical(ref obj_info) => {
                let hash_types = obj_info.footer().hash_header().hash_values().iter().map(|x| x.hash_type());
                let mut hasher_map = HashMap::new();
                for h_type in hash_types {
                    let hasher = Hash::new_hasher(h_type);
                    hasher_map.insert(h_type.clone(), hasher);
                };
                if hasher_map.is_empty() {
                    println!("{M_NO_HASH_VALUES_FOR_OBJ_}{object_number}!");
                    continue;
                };
                zffreader.set_reader_physical_object(object.object_number())?;
                
                let mut eof = false;

                loop {
                    let mut buf = vec![0u8; BUFFER_DEFAULT_SIZE];
                    let mut read_bytes = 0;

                    while read_bytes < BUFFER_DEFAULT_SIZE {
                        let r = zffreader.read(&mut buf[read_bytes..])?;
                        if r == 0 {
                            eof = true;
                            break;
                        }
                        read_bytes += r;
                    }
                    let buf = if read_bytes == BUFFER_DEFAULT_SIZE {
                        buf
                    } else {
                        buf[..read_bytes].to_vec()
                    };

                    for hasher in hasher_map.values_mut() {
                        hasher.update(&buf);
                    }
                    if eof {
                        break;
                    }
                }

                for (hash_type, hasher) in hasher_map.clone() {
                    let hash1 = hasher.finalize();
                    let hash2 = obj_info.footer().hash_header().hash_values().iter().find(|x| x.hash_type() == &hash_type).unwrap().hash();
                    if &hash1.to_vec() == hash2 {
                        println!("{M_SUCCESSFUL_INTEGRITY_CHECK_HASH_}({hash_type})");
                    } else {
                        println!("{M_FAILED_INTEGRITY_CHECK_HASH_}({hash_type})");
                    }
                }
            },

            Object::Logical(ref obj_info) => {
                let mut hash_conflict = false;

                for (current_filenumber, current_file) in obj_info.files() {
                    let hash_types = current_file.footer().hash_header().hash_values().iter().map(|x| x.hash_type());
                    let mut hasher_map = HashMap::new();
                    for h_type in hash_types {
                        let hasher = Hash::new_hasher(h_type);
                        hasher_map.insert(h_type.clone(), hasher);
                    };
                    
                    if hasher_map.is_empty() {
                        let filename = current_file.header().filename();
                        println!("{M_NO_HASH_FOR_FILE_}{current_filenumber}: {filename}");
                        continue;
                    };

                    zffreader.set_reader_logical_object_file(object.object_number(), *current_filenumber)?;

                    let mut eof = false;

                    loop {
                        let mut buf = vec![0u8; BUFFER_DEFAULT_SIZE];
                        let mut read_bytes = 0;

                        while read_bytes < BUFFER_DEFAULT_SIZE {
                            let r = zffreader.read(&mut buf[read_bytes..])?;
                            if r == 0 {
                                eof = true;
                                break;
                            }
                            read_bytes += r;
                        }
                        let buf = if read_bytes == BUFFER_DEFAULT_SIZE {
                            buf
                        } else {
                            buf[..read_bytes].to_vec()
                        };

                        for hasher in hasher_map.values_mut() {
                            hasher.update(&buf);
                        }
                        if eof {
                            break;
                        }
                    }

                    for (hash_type, hasher) in hasher_map.clone() {
                        let hash1 = hasher.finalize();
                        let hash2 = current_file.footer().hash_header().hash_values().iter().find(|x| x.hash_type() == &hash_type).unwrap().hash();
                        if &hash1.to_vec() != hash2 {
                            println!("{M_FAILED_INTEGRITY_CHECK_HASH_}({hash_type})");
                            hash_conflict = true;
                        }
                    }
                }

                if !hash_conflict {
                    println!("{M_SUCCESSFUL_INTEGRITY_CHECK_ALL_FILES}");
                } else {
                    println!("{M_FAILED_INTEGRITY_CHECK_ALL_FILES}");
                }
            }
        }
    }

    Ok(())
}

fn analyze(args: &Cli) {
    
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
                eprintln!("{ERROR_OPEN_INPUT_FILE_}{err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        }
    };

    let mut information: HashMap<i64, Vec<Information>> = HashMap::new();

    for file_number in file_numbers {
        // - unwrap should be safe here, because we have filled the map and the vector above with the correct file numbers.
        let file = files.get_mut(&file_number).unwrap();
        let header_type = match get_header(file, args) {
            Ok(ht) => ht,
            Err(err_msg) => {
                eprintln!("{ERROR_FILE_READ_}{err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        };
        match header_type {
            HeaderType::MainHeaderV1(main_header) => {
                let unique_identifier = main_header.unique_identifier();

                let first_segment_header = match SegmentHeaderV1::decode_directly(file) {
                    Ok(header) => header,
                    Err(e) => {
                        eprintln!("{ERROR_DECODE_SEGMENT_HEADER_}1\n{e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                };
                let segment_information = match get_segment_information_v1(args, file, first_segment_header) {
                    Ok(seg_info) => seg_info,
                    Err(e) => {
                        eprintln!("{ERROR_GET_SEGMENT_INFORMATION_V1_}{e}");
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
                let segment_information = match get_segment_information_v1(args, file, segment_header) {
                    Ok(seg_info) => seg_info,
                    Err(e) => {
                        eprintln!("{ERROR_GET_SEGMENT_INFORMATION_V1_}{e}");
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
                        eprintln!("{ERROR_DECODE_SEGMENT_HEADER_}2\n{e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                };
                segments_map.insert(first_segment_header.segment_number(), file_number);
                let segment_information = match get_segment_information_v2(args, file, first_segment_header, &mut information, &mut logical_object_footer_map) {
                    Ok(seg_info) => seg_info,
                    Err(e) => {
                        eprintln!("{ERROR_GET_SEGMENT_INFORMATION_V2_}{e}");
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
                let segment_information = match get_segment_information_v2(args, file, segment_header, &mut information, &mut logical_object_footer_map) {
                    Ok(seg_info) => seg_info,
                    Err(e) => {
                        eprintln!("{ERROR_GET_SEGMENT_INFORMATION_V2_}{e}");
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
        let (mut decryption_key, mut encryption_header) = (None, None);
        for info in information.get(unique_identifier).unwrap() {
            match info {
                Information::ObjectHeaderInformation(obj_header_info) => if obj_header_info.object_number == *object_number {
                    encryption_header = obj_header_info.encryption_header.as_ref();
                    match encryption_header {
                        Some(encryption_header) => {
                            for password in &args.decryption_passwords {
                                match &encryption_header.decrypt_encryption_key(password) {
                                    Ok(key) => {
                                        decryption_key = Some(key.clone());
                                        break;
                                    },
                                    Err(_) => continue,
                                }
                            }
                        },
                        None => break,
                    }
                },
                _ => continue,
            }
        }
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
                        } else {
                            match &decryption_key {
                                None => eprintln!("Warning: file header of file number {file_number} in object {object_number} is encrypted and not readable."),
                                Some(key) => {
                                    if let Ok(file_header_information) = get_encrypted_file_header_information(file, *offset, key, encryption_header.unwrap()) {
                                        object_footer_information_logical.file_header_map.insert(*file_number, file_header_information);
                                    }
                                }
                            }
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
                    eprintln!("{ERROR_SERIALIZE_TOML_}{e}");
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
                eprintln!("{ERROR_SERIALIZE_JSON_}{e}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        OutputFormat::JsonPretty => match serde_json::to_string_pretty(&information) {
            Ok(value) => {
                println!("{}", value);
                exit(EXIT_STATUS_SUCCESS);
            },
            Err(e) => {
                eprintln!("{ERROR_SERIALIZE_JSON_}{e}");
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
        encryption_header: object_header.encryption_header().cloned(),
    };
    Ok(object_header_information)
}

fn get_encrypted_object_header_information<P: Into<String>>(file: &mut File, offset: u64, decryption_password: P) -> Result<ObjectHeaderInformation> {
    file.seek(SeekFrom::Start(offset))?;
    let object_header = ObjectHeader::decode_encrypted_header_with_password(file, decryption_password.into())?;
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
        encryption_header: object_header.encryption_header().cloned(),
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

fn get_encrypted_file_header_information<K: AsRef<[u8]>>(file: &mut File, offset: u64, key: K, encryption_header: &EncryptionHeaderV2) -> Result<FileHeaderInformation> {
    file.seek(SeekFrom::Start(offset))?;
    let file_header = FileHeader::decode_encrypted_header_with_key(file, key, encryption_header.clone())?;
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
                ZffErrorKind::HeaderDecodeEncryptedHeader => {
                    let mut decrypted = false;
                    for password in &args.decryption_passwords {
                        match get_encrypted_object_header_information(file, *offset, password) {
                            Ok(object_header_information) => {
                                decrypted = true;
                                match global_information_map.get_mut(&unique_identifier) {
                                    Some(data) => data.push(Information::ObjectHeaderInformation(object_header_information)),
                                    None => {
                                        global_information_map.insert(unique_identifier, Vec::new());
                                        global_information_map.get_mut(&unique_identifier).unwrap().push(Information::ObjectHeaderInformation(object_header_information));
                                    },
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    if !decrypted {
                       eprintln!("{M_ENCRYPTED_OBJ_HEADER_IN_OBJ_}{object_number}.") 
                    };
                },
                _ => eprintln!("{ERROR_GET_OBJ_HEADER_INFORMATION_}{e}"),
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
                    eprintln!("{ERROR_SET_OBJ_FOOTER_INFORMATION_}{e}");
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
        if args.decryption_passwords.len() as u64 != 1 {
            eprintln!("{ERROR_DECRYPTION_PASSWORD_NEEDED}");
            exit(EXIT_STATUS_ERROR);
        };
        let decryption_password = &args.decryption_passwords[0]; 
        encrypted_main_header(inputfile, u8::from_be_bytes(header_version), decryption_password)
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
                eprintln!("{ERROR_PARSE_MAIN_HEADER_}{err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        2 => match MainHeaderV2::decode_directly(inputfile) {
            Ok(main_header) => Ok(HeaderType::MainHeaderV2(main_header)),
            Err(err_msg) => {
                eprintln!("{ERROR_PARSE_MAIN_HEADER_} {err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        version => {
            eprintln!("{ERROR_UNSUPPORTED_ZFF_MAIN_HEADER_VERSION_}{version}");
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
                        ZffErrorKind::PKCS5CryptoError => println!("{ERROR_PARSE_ENCRYPTED_MAIN_HEADER_}{ERROR_WRONG_PASSWORD}"),
                        _ => println!("{ERROR_PARSE_ENCRYPTED_MAIN_HEADER_}{err}"),
                    };
                    exit(EXIT_STATUS_ERROR);
                }
            }
        },
        2 => match MainHeaderV2::decode_directly(inputfile) {
            Ok(main_header) => Ok(HeaderType::MainHeaderV2(main_header)),
            Err(err_msg) => {
                eprintln!("{ERROR_PARSE_MAIN_HEADER_} {err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        version => {
            eprintln!("{ERROR_UNSUPPORTED_ZFF_MAIN_HEADER_VERSION_}{version}");
            exit(EXIT_STATUS_ERROR);
        },
    }
}

fn segment_header(inputfile: &mut File, header_version: u8) -> Result<HeaderType> {
    match header_version {
        1 => match SegmentHeaderV1::decode_directly(inputfile) {
            Ok(segment_header) => Ok(HeaderType::SegmentHeaderV1(segment_header)),
            Err(err_msg) => {
                eprintln!("{ERROR_PARSE_SEGMENT_HEADER_}{err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        2 => match SegmentHeaderV2::decode_directly(inputfile) {
            Ok(segment_header) => Ok(HeaderType::SegmentHeaderV2(segment_header)),
            Err(err_msg) => {
                eprintln!("{ERROR_PARSE_SEGMENT_HEADER_}{err_msg}");
                exit(EXIT_STATUS_ERROR);
            }
        },
        version => {
            eprintln!("{ERROR_UNSUPPORTED_ZFF_SEGMENT_HEADER_VERSION_}{version}");
            exit(EXIT_STATUS_ERROR);
        }
    }
}