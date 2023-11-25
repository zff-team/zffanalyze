// - STD
use std::fs::{File};
use std::path::PathBuf;
use std::process::exit;
use std::io::{Seek, SeekFrom, Read};
use std::collections::BTreeMap;

// - modules
mod res;

// - internal
use res::*;
use res::constants::*;


use zff::{
    Result,
    header::{SegmentHeader, ObjectHeader, EncryptedObjectHeader, FileHeader,},
    footer::{SegmentFooter, MainFooter, ObjectFooter, EncryptedObjectFooter, FileFooter},
    HeaderCoding,
};

// - external
use clap::{Parser, ValueEnum};
use log::{LevelFilter, error, warn, debug};
use serde::{Serialize};

#[derive(Parser)]
#[clap(about, version, author)]
struct Cli {

    /// The input files. This should be your zff image files. You can use this Option multiple times.
    #[clap(short='i', long="inputfiles")]
    inputfiles: Vec<String>,

    /// The output format.
    #[clap(short='f', long="output-format", value_enum, default_value="toml")]
    output_format: OutputFormat,

    /// Verbose mode to show more information. Can be used multiple times.
    #[arg(short='v', long="verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    //TODO
    /// The password(s), if the file(s) are encrypted. You can use this option multiple times to enter different passwords for different objects.
    #[clap(short='p', long="decryption-passwords", value_parser = parse_key_val::<String, String>)]
    decryption_passwords: Vec<(String, String)>,

    //TODO
    /// The public sign key to verify the appropriate signatures.
    #[clap(short='k', long="pub-key")]
    public_key: Option<String>,

    //TODO
    /// Checks the integrity of the imaged data by calculating/comparing the used hash values.
    #[clap(short='c', long="integrity-check")]
    check_integrity: bool,

    /// The Loglevel
    #[clap(short='l', long="log-level", value_enum, default_value="info")]
    log_level: LogLevel,
}

#[derive(ValueEnum, Clone, Debug)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
    Off
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
        LogLevel::Error => Some(LevelFilter::Error),
        LogLevel::Warn => Some(LevelFilter::Warn),
        LogLevel::Info => Some(LevelFilter::Info),
        LogLevel::Debug => Some(LevelFilter::Debug),
        LogLevel::Trace => Some(LevelFilter::Trace),
        LogLevel::Off => None,
    };
    if let Some(log_level) = log_level {
       env_logger::builder()
            .format_timestamp_nanos()
            .filter_level(log_level)
            .init(); 
    };

    let inputfiles: Vec<PathBuf> = args.inputfiles.iter().map(|x| concat_prefix_path(INPUTFILES_PATH_PREFIX ,x)).collect();
    debug!("Concatenated inputfiles to: {:?}", inputfiles);

    let container_info = match read_segments(&inputfiles, &args) {
        Ok(container_info) => container_info,
        Err(e) => {
            error!("An error occurred while trying to read the appropriate zff file(s).");
            debug!("{e}");
            exit(EXIT_STATUS_ERROR);
        }
    };

    match args.output_format {
        OutputFormat::Toml => {
            match toml::to_string(&container_info) {
                Ok(toml) => println!("{toml}"),
                Err(e) => {
                    error!("An error occurred while trying to serialize the container information: {e}");
                    debug!("{:?}", container_info);
                }
            }
        }
        OutputFormat::Json => {
            match serde_json::to_string(&container_info) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    error!("An error occurred while trying to serialize the container information: {e}");
                    debug!("{:?}", container_info);
                }
            }
        }
        OutputFormat::JsonPretty => {
            match serde_json::to_string_pretty(&container_info) {
                Ok(json) => println!("{json}"),
                Err(e) => {
                    error!("An error occurred while trying to serialize the container information: {e}");
                    debug!("{:?}", container_info);
                }
            }
        }
    }
    exit(EXIT_STATUS_SUCCESS);
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
        let seg_info = SegmentInfo {
            header: segment_header,
            footer: segment_footer
        };
        reader.insert(seg_no, file);
        segments.insert(seg_no, seg_info);
    }

    let mut objects = read_objects(&mut segments, &mut reader)?;

    // add file_info to object info, if verbose mode is set at least one time.
    if args.verbose >= 1 {
        for object_info in objects.values_mut() {
            read_files(object_info, &mut reader)?;
        }
    }

    if main_footer.is_none() {
        warn!("No main footer found in given segments.");
    }

    Ok(ContainerInfo {
        main_footer: main_footer,
        segments: segments,
        objects: objects,
    })
}

fn read_objects<R: Read + Seek>(
    segments: &mut BTreeMap<u64, SegmentInfo>,
    reader: &mut BTreeMap<u64, R>
    ) -> Result<BTreeMap<u64, ObjectInfo>> {

    let mut object_header_map = BTreeMap::new();
    let mut object_footer_map = BTreeMap::new();
    let mut objects = BTreeMap::new();

    for (seg_no, seg_info) in segments {
        let seg_reader = match reader.get_mut(&seg_no) {
            Some(reader) => reader,
            None => unreachable!()
        };

        // TODO: Handle encrypted objects
        for (object_no, object_header_offset) in &seg_info.footer.object_header_offsets {
            seg_reader.seek(SeekFrom::Start(*object_header_offset))?;
            let obj_header = ObjectHeader::decode_directly(seg_reader)?;
            object_header_map.insert(object_no, obj_header);
        }

        for (object_no, object_footer_offset) in &seg_info.footer.object_footer_offsets {
            seg_reader.seek(SeekFrom::Start(*object_footer_offset))?;
            let obj_footer = ObjectFooter::decode_directly(seg_reader)?;
            object_footer_map.insert(object_no, obj_footer);
        }
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

    Ok(objects)
}

fn read_files<R: Read + Seek>(
    object: &mut ObjectInfo,
    reader: &mut BTreeMap<u64, R>,
    ) -> Result<()> {
    
    let mut files = BTreeMap::new();

    let logical_object_footer = match &object.footer {
        ObjectFooter::Logical(logical) => logical,
        _ => return Ok(())
    };

    // TODO: Handle encrypted files
    for (filenumber, header_segment_no) in &logical_object_footer.file_header_segment_numbers {
        let header_offset = match logical_object_footer.file_header_offsets.get(&filenumber) {
            Some(offset) => offset,
            None => {
                warn!("Offset for file header of file no {filenumber} not present. Malformed Segment?");
                continue;
            }
        };
        let (footer_segment_no, footer_offset) = match logical_object_footer.file_footer_segment_numbers.get(&filenumber) {
            Some(seg_no) => match logical_object_footer.file_footer_offsets.get(&filenumber) {
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

        let file_header = match reader.get_mut(&header_segment_no) {
            Some(reader) => {
                reader.seek(SeekFrom::Start(*header_offset))?;
                FileHeader::decode_directly(reader)?
            },
            None =>  {
                warn!("Missing segment {header_segment_no}. File header of file no {filenumber} could not be found.");
                continue;
            }
        };

        let file_footer = match reader.get_mut(&footer_segment_no) {
            Some(reader) => {
                reader.seek(SeekFrom::Start(*footer_offset))?;
                FileFooter::decode_directly(reader)?
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