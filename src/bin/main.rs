// - STD
use std::fs::File;
use std::path::PathBuf;
use std::process::exit;
use std::io::{Seek, SeekFrom, Read};
use std::collections::BTreeMap;

// - modules
mod res;

// - internal
use res::*;
use res::constants::*;
use res::traits::*;


use zff::header::{ChunkDeduplicationMap, ChunkSamebytesMap, ChunkHeaderMap, ChunkMap};
use zff::ZffErrorKind;
use zff::{
    Result,
    helper::get_segment_of_chunk_no,
    header::{SegmentHeader, ObjectHeader, EncryptedObjectHeader, FileHeader, ChunkMaps, EncryptionInformation, HashHeader},
    footer::{SegmentFooter, MainFooter, ObjectFooter, EncryptedObjectFooter, FileFooter},
    HeaderCoding,
    Signature,
};

// - external
use clap::{Parser, ValueEnum};
use log::{LevelFilter, error, warn, debug, info, trace};
use serde::Serialize;
use dialoguer::{theme::ColorfulTheme, Password as PasswordDialog};

#[derive(Parser)]
#[clap(about, version, author)]
struct Cli {

    /// The input files. This should be your zff image files. You can use this Option multiple times.
    #[clap(short='i', long="inputfiles", required=true, value_delimiter = ' ', num_args = 1..)]
    inputfiles: Vec<String>,

    /// The output format.
    #[clap(short='f', long="output-format", value_enum, default_value="toml")]
    output_format: OutputFormat,

    /// Verbose mode to show more information. Can be used multiple times.
    /// Use the option one time to print also the chunk maps  
    /// Use the option two times to print also the chunk maps and logical file information (for each file!)
    /// Use the option three times to print also the chunk maps, the logical file information and the chunk header information (for each chunk!)
    #[arg(short='v', long="verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// The password(s), if the file(s) are encrypted. You can use this option multiple times to enter different passwords for different objects.
    /// If you don't provide a password for an object, you will be asked to enter the password interactively.
    #[clap(short='p', long="decryption-passwords", value_parser = parse_key_val::<String, String>)]
    decryption_passwords: Vec<(String, String)>,

    /// Do not ask interactively for passwords, if objects are encrypted.
    #[clap(short='I', long="ignore-encryption")]
    ignore_encryption: bool,

    //TODO
    /// The public sign key to verify the appropriate signatures.
    #[clap(short='k', long="pub-key")]
    public_key: Option<String>,

    /// Checks the integrity of the imaged data by calculating/comparing the used hash values.
    #[clap(short='c', long="integrity-check")]
    check_integrity: bool,

    /// The Loglevel
    #[clap(short='l', long="log-level", value_enum, default_value="info")]
    log_level: LogLevel,
}

#[derive(ValueEnum, Clone, PartialEq)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace
}

#[derive(ValueEnum, Clone)]
enum OutputFormat {
    Toml,
    Json,
    JsonPretty
}

fn main() {
    let args = Cli::parse();
    
    // setup logging
    let log_level = match args.log_level {
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::Trace => LevelFilter::Trace,
    };
    env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(log_level)
        .init();

    let inputfiles: Vec<PathBuf> = args.inputfiles.iter().map(|x| concat_prefix_path(INPUTFILES_PATH_PREFIX ,x)).collect();
    debug!("Concatenated inputfiles to: {:?}", inputfiles);

    let mut container_info = match read_segments(&inputfiles, &args) {
        Ok(container_info) => container_info,
        Err(e) => {
            error!("An error occurred while trying to read the appropriate zff file(s).");
            debug!("{e}");
            exit(EXIT_STATUS_ERROR);
        }
    };
    if args.verbose < 1 {
        container_info.segments.iter_mut().for_each(|(_, segment)| {
            segment.chunkmaps = None;
        });
    }
    print_serialized_data(&args, container_info);


    exit(EXIT_STATUS_SUCCESS);
}

fn print_serialized_data<D: Serialize + std::fmt::Debug>(args: &Cli, data: D) {
    match args.output_format {
        OutputFormat::Toml => {
            match toml::to_string(&data) {
                Ok(toml) => println!("{toml}"),
                Err(e) => {
                    error!("An error occurred while trying to serialize data: {e}");
                    debug!("{:?}", data);
                }
            }
        }
        OutputFormat::Json => {
            match serde_json::to_string(&data) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    error!("An error occurred while trying to serialize data: {e}");
                    debug!("{:?}", data);
                }
            }
        }
        OutputFormat::JsonPretty => {
            match serde_json::to_string_pretty(&data) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    error!("An error occurred while trying to serialize data: {e}");
                    debug!("{:?}", data);
                }
            }
        }
    }
}

fn read_segments(inputfiles: &Vec<PathBuf>, args: &Cli) -> Result<ContainerInfo> {
    let mut segments = BTreeMap::new();
    let mut main_footer = None;
    let mut reader = BTreeMap::new();

    for inputfile in inputfiles {
        debug!("Reading segment {}", inputfile.display());
        let mut file = File::open(inputfile)?;
        let segment_header = match SegmentHeader::decode_directly(&mut file) {
            Ok(header) => header,
            Err(e) => {
                error!("Could not read segment header from {}.", inputfile.display());
                debug!("An error occurred while trying to read the segment header of {}: {e}", inputfile.display());
                exit(EXIT_STATUS_ERROR);
            },
        };
        let segment_footer = match try_find_footer(&mut file)? {
            Footer::MainAndSegment((main, segment)) => {
                main_footer = Some(main);
                segment
            },
            Footer::Segment(segment_footer) => segment_footer,
        };
        let seg_no = segment_header.segment_number;

        // add chunkmaps to segment info
        let mut chunkmaps = ChunkMaps::default();
        // chunk header table 
        let mut header_map = BTreeMap::new();
        for (_, offset) in &segment_footer.chunk_header_map_table {
            file.seek(SeekFrom::Start(*offset))?;
            let mut chunk_header_map = match ChunkHeaderMap::decode_directly(&mut file) {
                Ok(map) => map,
                Err(e) => {
                    error!("Could not read chunk header map from {}.", inputfile.display());
                    debug!("An error occurred while trying to read the chunk offset map of {}: {e}", inputfile.display());
                    exit(EXIT_STATUS_ERROR);
                }
            };
            header_map.extend(chunk_header_map.flush());
        }
        chunkmaps.header_map = ChunkHeaderMap::with_data(header_map);

        // chunk same bytes table 
        let mut same_bytes_map = BTreeMap::new();
        for (_, offset) in &segment_footer.chunk_samebytes_map_table {
            file.seek(SeekFrom::Start(*offset))?;
            let mut chunk_same_bytes_map = match ChunkSamebytesMap::decode_directly(&mut file) {
                Ok(map) => map,
                Err(e) => {
                    error!("Could not read chunk same bytes map from {}.", inputfile.display());
                    debug!("An error occurred while trying to read the chunk same bytes map of {}: {e}", inputfile.display());
                    exit(EXIT_STATUS_ERROR);
                }
            };
            same_bytes_map.extend(chunk_same_bytes_map.flush());
        }
        chunkmaps.same_bytes_map = ChunkSamebytesMap::with_data(same_bytes_map);

        // chunk deduplication table
        let mut dedup_map = BTreeMap::new();
        for (_, offset) in &segment_footer.chunk_dedup_map_table {
            file.seek(SeekFrom::Start(*offset))?;
            let mut chunk_dedup_map = match ChunkDeduplicationMap::decode_directly(&mut file) {
                Ok(map) => map,
                Err(e) => {
                    error!("Could not read chunk deduplication map from {}.", inputfile.display());
                    debug!("An error occurred while trying to read the chunk deduplication map of {}: {e}", inputfile.display());
                    exit(EXIT_STATUS_ERROR);
                }
            };
            dedup_map.extend(chunk_dedup_map.flush());
        }

        let seg_info = SegmentInfo {
            header: segment_header,
            footer: segment_footer,
            chunkmaps: Some(chunkmaps),
        };

        reader.insert(seg_no, file);
        segments.insert(seg_no, seg_info);
    }

    let (mut objects, encrypted_objects) = read_objects(args, &mut segments, &mut reader)?;

    // add file_info to object info, if verbose mode is set at least two times or the integrity check or signature verification should be performed.
    if args.verbose >= 2 || args.check_integrity || args.public_key.is_some() {
        for object_info in objects.values_mut() {
            let encryption_information = EncryptionInformation::try_from(&object_info.header).ok();
            read_files(object_info, &mut reader, encryption_information)?;
        }
    }

    if main_footer.is_none() {
        warn!("No main footer found in given segments.");
    }

    let container_info = ContainerInfo {
        main_footer,
        segments,
        objects,
        encrypted_objects,
    };

    let mut check_mode = false;

    if args.check_integrity {
        integrity_check(&container_info, &mut reader);
        check_mode = true;
    }

    if args.public_key.is_some() {
        let public_key = args.public_key.as_ref().unwrap();
        verify_signature(&container_info, public_key);
        check_mode = true;
    }

    if check_mode {
        exit(EXIT_STATUS_SUCCESS);
    }

    Ok(container_info)
}

fn read_objects<R: Read + Seek>(
    args: &Cli,
    segments: &mut BTreeMap<u64, SegmentInfo>,
    reader: &mut BTreeMap<u64, R>
    ) -> Result<(BTreeMap<u64, ObjectInfo>, BTreeMap<u64, EncryptedObjectInfo>)> {

    debug!("Reading objects from segments.");

    let mut object_header_map = BTreeMap::new();
    let mut object_footer_map = BTreeMap::new();
    let mut objects = BTreeMap::new();

    let mut encrypted_object_header = BTreeMap::new();
    let mut encrypted_object_footer = BTreeMap::new();
    let mut encrypted_objects = BTreeMap::new();

    for (seg_no, seg_info) in segments {
        let seg_reader = match reader.get_mut(seg_no) {
            Some(reader) => reader,
            None => unreachable!()
        };

        for (object_no, object_header_offset) in &seg_info.footer.object_header_offsets {
            seg_reader.seek(SeekFrom::Start(*object_header_offset))?;
            match ObjectHeader::decode_directly(seg_reader) {
                Ok(obj_header) => {  object_header_map.insert(object_no, obj_header); },
                Err(e) => match e.kind() {
                    ZffErrorKind::EncryptionError => {
                        debug!("Object header of object {object_no} is encrypted.");

                        seg_reader.seek(SeekFrom::Start(*object_header_offset))?;
                        let mut enc_obj_header = match EncryptedObjectHeader::decode_directly(seg_reader) {
                            Ok(obj_header) => obj_header,
                            Err(e) => {
                                error!("Could not read object header of object {object_no} from segment {seg_no}.");
                                debug!("An error occurred while trying to read the object header of object {object_no} from segment {seg_no}: {e}");
                                exit(EXIT_STATUS_ERROR);
                            }
                        };
                        if let Some(decryption_password) = try_get_password(args, *object_no) {
                            match enc_obj_header.decrypt_with_password(decryption_password) {
                                Ok(header) => { object_header_map.insert(object_no, header); },
                                _ => { encrypted_object_header.insert(*object_no, enc_obj_header); },
                            };
                        } else {
                            encrypted_object_header.insert(*object_no, enc_obj_header);
                        }
                    },
                    _ => {
                        error!("Could not read object header of object {object_no} from segment {seg_no}.");
                        debug!("An error occurred while trying to read the object header of object {object_no} from segment {seg_no}: {e}");
                        exit(EXIT_STATUS_ERROR);
                    },
                }
            };
        }

        for (object_no, object_footer_offset) in &seg_info.footer.object_footer_offsets {
            seg_reader.seek(SeekFrom::Start(*object_footer_offset))?;
            match ObjectFooter::decode_directly(seg_reader) {
                Ok(obj_footer) => { object_footer_map.insert(object_no, obj_footer); },
                Err(e) => match e.kind() {
                    ZffErrorKind::EncryptionError => {
                        seg_reader.seek(SeekFrom::Start(*object_footer_offset))?;
                        let enc_obj_footer = match EncryptedObjectFooter::decode_directly(seg_reader) {
                            Ok(obj_footer) => obj_footer,
                            Err(e) => {
                                error!("Could not read object footer of object {object_no} from segment {seg_no}.");
                                debug!("An error occurred while trying to read the object footer of object {object_no} from segment {seg_no}: {e}");
                                exit(EXIT_STATUS_ERROR);
                            }
                        };
                        if let Some(decrypted_header) = object_header_map.get(object_no) {
                            // unwrap should safe here, because we checked if a decrypted object header is present.
                            let decryption_key = decrypted_header.encryption_header.as_ref().unwrap().get_encryption_key_ref().unwrap();
                            let encryption_algorithm = &decrypted_header.encryption_header.as_ref().unwrap().algorithm;
                            match enc_obj_footer.decrypt(decryption_key, encryption_algorithm) {
                                Ok(footer) => { object_footer_map.insert(object_no, footer); },
                                _ => { encrypted_object_footer.insert(*object_no, enc_obj_footer); },
                            };
                        } else {
                            encrypted_object_footer.insert(*object_no, enc_obj_footer);
                        }
                    },
                    _ => {
                        error!("Could not read object footer of object {object_no} from segment {seg_no}.");
                        debug!("An error occurred while trying to read the object footer of object {object_no} from segment {seg_no}: {e}");
                        exit(EXIT_STATUS_ERROR);
                    },
                }
            };
        }
    }

    for (object_no, enc_obj_header) in encrypted_object_header {
        let enc_obj_footer = match encrypted_object_footer.remove(&object_no) {
            Some(footer) => footer,
            None => {
                error!("No (encrypted) object footer present for object {object_no}");
                exit(EXIT_STATUS_ERROR); 
            }
        };
        let enc_obj_info = EncryptedObjectInfo {
            header: enc_obj_header,
            footer: enc_obj_footer,
        };
        encrypted_objects.insert(object_no, enc_obj_info);
    }

    for (object_no, obj_header) in &object_header_map {
        let obj_footer = match object_footer_map.get(object_no) {
            Some(footer) => footer,
            None => {
                error!("No object footer present for object {object_no}");
                exit(EXIT_STATUS_ERROR);
            }
        };
        let obj_info = ObjectInfo {
            header: obj_header.clone(),
            footer: obj_footer.clone(),
            files: None,
        };
        objects.insert(**object_no, obj_info);
    }

    // check if there is a object footer present, but the appropriate object header is not.
    for object_no in object_footer_map.keys() {
        match object_header_map.get(object_no) {
            Some(_) => (),
            None => {
                error!("No object header present for object {object_no}");
                exit(EXIT_STATUS_ERROR);
            }
        };
    }

    Ok((objects, encrypted_objects))
}

fn read_files<R: Read + Seek>(
    object: &mut ObjectInfo,
    reader: &mut BTreeMap<u64, R>,
    optional_encryption_information: Option<EncryptionInformation>,
    ) -> Result<()> {
    
    let mut files = BTreeMap::new();

    let logical_object_footer = match &object.footer {
        ObjectFooter::Logical(logical) => logical,
        _ => return Ok(())
    };

    for (filenumber, header_segment_no) in &logical_object_footer.file_header_segment_numbers {
        let header_offset = match logical_object_footer.file_header_offsets.get(filenumber) {
            Some(offset) => offset,
            None => {
                warn!("Offset for file header of file no {filenumber} not present. Malformed Segment?");
                continue;
            }
        };
        let (footer_segment_no, footer_offset) = match logical_object_footer.file_footer_segment_numbers.get(filenumber) {
            Some(seg_no) => match logical_object_footer.file_footer_offsets.get(filenumber) {
                Some(offset) => (seg_no, offset),
                None =>  {
                    warn!("Offset for file footer of file no {filenumber} not present. Malformed Segment?");
                    continue;
                }
            },
            None => {
                warn!("Segment number for file footer of file no {filenumber} not present. Malformed Object footer or missing segment?");
                continue;
            }
        };

        let file_header = match reader.get_mut(header_segment_no) {
            Some(reader) => {
                reader.seek(SeekFrom::Start(*header_offset))?;
                if let Some(enc_info) = &optional_encryption_information {
                    FileHeader::decode_encrypted_header_with_key(
                        reader, 
                        enc_info)?
                } else {
                    FileHeader::decode_directly(reader)?
                }
            },
            None =>  {
                warn!("Missing segment {header_segment_no}. File header of file no {filenumber} could not be found.");
                continue;
            }
        };

        let file_footer = match reader.get_mut(footer_segment_no) {
            Some(reader) => {
                reader.seek(SeekFrom::Start(*footer_offset))?;
                if let Some(enc_info) = &optional_encryption_information {
                    FileFooter::decode_encrypted_footer_with_key(
                        reader, 
                        enc_info)?
                } else {
                    FileFooter::decode_directly(reader)?
                }
            },
            None =>  {
                warn!("Missing segment {header_segment_no}. File footer of file no {filenumber} could not be found.");
                continue;
            }
        };

        let file_info = FileInfo {
            header: file_header,
            footer: file_footer,
        };

        files.insert(*filenumber, file_info);
    }

    object.files = Some(files);

    Ok(())
}

// function to verify the signature of each hash (if an signature is present) by using the appropriate public key.
fn verify_signature(container_info: &ContainerInfo, public_key: &str) {
    for object_info in container_info.objects.values() {
        match object_info.footer {
            ObjectFooter::Physical(ref footer) => {
                info!("Verifying signature of object {}.", object_info.header.object_number);
                check_hash_header(&footer.hash_header, public_key);
            },
            ObjectFooter::Logical(_) => {
                info!("Verifying signature of object {}.", object_info.header.object_number);
                let files = match &object_info.files {
                    Some(files) => files,
                    None => unreachable!()
                };
                for file_info in files.values() {
                    check_hash_header(&file_info.footer.hash_header, public_key);
                }
            },
            ObjectFooter::Virtual(_) => {
                debug!("Virtual objects are not supported for signature verification.");
                continue;
            },
        }
    }
}

fn check_hash_header(hash_header: &HashHeader, public_key: &str) {
    for hash_value in &hash_header.hashes {
        let hash = hash_value.hash();
        let hash_type = hash_value.hash_type();
        let signature = match hash_value.ed25519_signature() {
            Some(signature) => signature,
            None => {
                warn!("No signature found for {hash_type} hash.");
                continue;
            }
        };
        match Signature::verify_with_base64_key(public_key, hash, signature) {
            Ok(true) => info!("Signature of {hash_type} hash is valid."),
            Ok(false) => warn!("Signature of {hash_type} hash is invalid."),
            Err(e) => {
                error!("An error occurred while trying to verify the signature of {hash_type} hash.");
                debug!("{e}");
                exit(EXIT_STATUS_ERROR);
            }
        }
    }
}

// function to check the integrity of each chunk by comparing the appropriate xxhash values.
fn integrity_check<R: Read + Seek>(container_info: &ContainerInfo, reader: &mut BTreeMap<u64, R>) {
    todo!()
}

// returns a BTreeMap with all chunk numbers of the container (and the appropriate offset), to see, if a chunk is missing or is available without a corresponding
// object.
fn get_all_chunk_numbers(container_info: &ContainerInfo) -> BTreeMap<u64, (u64, u64)> {
    let mut all_chunk_numbers = BTreeMap::new();
    let main_footer = match &container_info.main_footer {
        Some(footer) => footer,
        None => {
            error!("No main footer found in given segments, integrity check not possible.");
            exit(EXIT_STATUS_ERROR);
        
        },
    };
    let last_chunk_number = *main_footer.chunk_header_maps.keys().max().unwrap_or(&0);
    for chunk_no in 1..=last_chunk_number {
        let segment = match get_segment_of_chunk_no(chunk_no, &main_footer.chunk_header_maps) {
            Some(segment_no) => match container_info.segments.get(&segment_no) {
                Some(segment_info) => segment_info,
                None => {
                    error!("Segment {segment_no} not found in given segments, integrity check not possible.");
                    exit(EXIT_STATUS_ERROR);
                }
            },
            None => {
                error!("Segment for chunk {chunk_no} not found in given segments, integrity check not possible.");
                exit(EXIT_STATUS_ERROR);
            },
        };
        // unwrap is safe here while the option is just used to handle the serialisation of the chunkmaps
        let offset = match segment.chunkmaps.as_ref().unwrap().header_map.chunkmap().get(&chunk_no) {
            Some(header) => header.offset,
            None => {
                error!("Chunk {chunk_no} not found in chunkmaps of segment {}, integrity check not possible.", segment.header.segment_number);
                exit(EXIT_STATUS_ERROR);
            },
        };
        all_chunk_numbers.insert(chunk_no, (segment.header.segment_number, offset));
    }
    all_chunk_numbers
}

fn try_get_password(args: &Cli, object_no: u64) -> Option<String> {
    match args.decryption_passwords.get(object_no.to_string()) {
        Some(pw) => Some(pw.clone()),
        None => {
            if args.ignore_encryption {
                None
            } else {
                enter_password_dialog(object_no)
            }
        },
    }
}

fn enter_password_dialog(obj_no: u64) -> Option<String> {
    match PasswordDialog::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Enter the password for object {obj_no}"))
        .interact() {
            Ok(pw) => Some(pw),
            Err(_) => None
        }
}