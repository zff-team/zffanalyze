// - STD
use std::collections::HashMap;

// - external
use hex::ToHex;
use serde::ser::{Serialize, Serializer, SerializeStruct};
use time::{OffsetDateTime, format_description};

pub mod constants;
pub mod traits;

// - internal
use zff::{
	HashType,
	header::version2::{ObjectType, FileType},
	CompressionAlgorithm,
};
use crate::constants::*;
use traits::*;

pub enum Information {
    MainInformationV1(MainInformationV1),
    SegmentInformation(SegmentInformation),
    MainHeaderInformationV2(MainHeaderInformationV2),
    MainFooterInformation(MainFooterInformation),
    ObjectHeaderInformation(ObjectHeaderInformation),
    ObjectFooterInformationLogical(ObjectFooterInformationLogical),
    ObjectFooterInformationPhysical(ObjectFooterInformationPhysical),
}

impl Serialize for Information {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Information", 6)?;
        match self {
            Information::MainInformationV1(main) => state.serialize_field("Main", &main)?,
            Information::SegmentInformation(seg) => state.serialize_field("Segment", &seg)?,
            Information::MainHeaderInformationV2(main) => state.serialize_field("Main", &main)?,
            Information::MainFooterInformation(main) => state.serialize_field("Main", &main)?,
            Information::ObjectHeaderInformation(obj_header) => state.serialize_field("ObjectHeader", &obj_header)?,
            Information::ObjectFooterInformationLogical(obj_footer) => state.serialize_field("ObjectFooterLogical", &obj_footer)?,
            Information::ObjectFooterInformationPhysical(obj_footer) => state.serialize_field("ObjectFooterPhysical", &obj_footer)?,
        }
        state.end()
    }
}

#[derive(Serialize)]
pub enum CompressionAlgorithmInformation {
    None,
    Zstd,
    Lz4,
    Unimplemented,
}

impl From<&CompressionAlgorithm> for CompressionAlgorithmInformation {
    fn from(algo: &CompressionAlgorithm) -> Self {
        match algo {
            CompressionAlgorithm::None => CompressionAlgorithmInformation::None,
            CompressionAlgorithm::Zstd => CompressionAlgorithmInformation::Zstd,
            CompressionAlgorithm::Lz4 => CompressionAlgorithmInformation::Lz4,
            _ => {
                eprintln!("{ERROR_UNIMPLEMENTED_COMPRESSION_ALGORITHM}");
                CompressionAlgorithmInformation::Unimplemented
            },           
        }
    
    }
}

#[derive(Serialize)]
pub enum FileTypeInformation {
    File,
    Directory,
    Symlink,
    Hardlink,
    Unimplemented,
}

impl From<&FileType> for FileTypeInformation {
    fn from(file_type: &FileType) -> Self {
        match file_type {
            FileType::File => FileTypeInformation::File,
            FileType::Directory => FileTypeInformation::Directory,
            FileType::Symlink => FileTypeInformation::Symlink,
            FileType::Hardlink => FileTypeInformation::Hardlink,
            _ => {
                eprintln!("{ERROR_UNIMPLEMENTED_FILETYPE}");
                FileTypeInformation::Unimplemented
            }, 
        }
    }
}

#[derive(Serialize)]
pub enum ObjectTypeInformation {
    Physical,
    Logical,
}

impl From<&ObjectType> for ObjectTypeInformation {
    fn from(object_type: &ObjectType) -> Self {
        match object_type {
            ObjectType::Physical => ObjectTypeInformation::Physical,
            ObjectType::Logical => ObjectTypeInformation::Logical,              
        }
    }
}

// - version 1 header
pub struct MainInformationV1 {
    pub chunk_size: u64,
    pub signature_flag: bool,
    pub segment_size: u64,
    pub number_of_segments: u64,
    pub length_of_data: u64,
    pub compression_information: CompressionInformation,
    pub segment_information: SegmentInformation,
    //TODO: add other things.
}

impl Serialize for MainInformationV1 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MainHeaderInformation", 6)?;
        state.serialize_field("chunk size", &format!("{} ({} bytes)", &self.chunk_size.bytes_as_hrb(), &self.chunk_size))?;
        state.serialize_field("signature flag", &self.signature_flag)?;
        state.serialize_field("segment size", &self.segment_size)?;
        state.serialize_field("number of segments", &self.number_of_segments)?;
        state.serialize_field("length of data", &self.length_of_data)?;
        state.serialize_field("compression_information", &self.compression_information)?;
        state.serialize_field("segment information", &self.segment_information)?;
        state.end()
    }
}

pub struct SegmentInformation {
    pub segment_number: u64,
    pub length_of_segment: u64,
    pub chunk_information: Vec<ChunkInformation>,
}

impl Serialize for SegmentInformation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SegmentInformation", 6)?;
        state.serialize_field("segment number", &self.segment_number)?;
        state.serialize_field("length of segment", &format!("{} ({} bytes)", &self.length_of_segment.bytes_as_hrb(), &self.length_of_segment))?;
        for chunk in &self.chunk_information {
        	state.serialize_field("chunk", &chunk)?;
        }
        state.end()
    }
}

// - version 2 header
pub struct MainHeaderInformationV2 {
    pub chunk_size: u64,
    pub segment_size: u64,
    pub segment_information: SegmentInformation,
}

impl Serialize for MainHeaderInformationV2 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MainHeaderInformation", 6)?;
        state.serialize_field("chunk size", &format!("{} ({} bytes)", &self.chunk_size.bytes_as_hrb(), &self.chunk_size))?;
        state.serialize_field("segment size", &format!("{} ({} bytes)", &self.segment_size.bytes_as_hrb(), &self.segment_size))?;
        state.serialize_field("segment information", &self.segment_information)?;
        state.end()
    }
}

#[derive(Serialize)]
pub struct MainFooterInformation {
    pub number_of_segments: u64,
    pub description_notes: Option<String>,
}

pub struct ObjectHeaderInformation {
    pub object_number: u64,
    //TODO: add other parts like encryption header.
    pub compression_information: CompressionInformation,
    //signature_flag: u8, TODO
    //TODO: description header
    pub object_type: ObjectType,
}

impl Serialize for ObjectHeaderInformation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ObjectHeaderInformation", 6)?;
        state.serialize_field("object number", &self.object_number)?;
        state.serialize_field("compression_information", &self.compression_information)?;
        state.serialize_field("object type", &ObjectTypeInformation::from(&self.object_type))?;
        state.end()
    }
}

pub struct ObjectFooterInformationPhysical {
    pub object_number: u64,
    pub acquisition_start: u64,
    pub acquisition_end: u64,
    pub length_of_data: u64,
    pub number_of_chunks: u64,
    pub hash_information: Vec<HashInformation>,   
}

impl Serialize for ObjectFooterInformationPhysical {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
    	//unwrap should be safe here, because the format string was tested.
    	let format = format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second] UTC").unwrap();

        let mut state = serializer.serialize_struct("ObjectFooterInformationPhysical", 6)?;

    	//acquisition start
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.acquisition_start as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field("acquisition_start", &formatted_dt)?;
    		} else {
    			state.serialize_field("acquisition_start", &self.acquisition_start)?;
    		}
    	} else {
    		state.serialize_field("acquisition_start", &self.acquisition_start)?;
    	};

    	//acquisition end
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.acquisition_end as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field("acquisition_end", &formatted_dt)?;
    		} else {
    			state.serialize_field("acquisition_end", &self.acquisition_end)?;
    		}
    	} else {
    		state.serialize_field("acquisition_end", &self.acquisition_end)?;
    	};

        state.serialize_field("object number", &self.object_number)?;
        state.serialize_field("length of data", &format!("{} ({} bytes)", &self.length_of_data.bytes_as_hrb(), &self.length_of_data))?;
        state.serialize_field("number of chunks", &self.number_of_chunks)?;
        for hash_info in &self.hash_information {
        	state.serialize_field("hash information", &hash_info)?;
        };
        state.end()
    }
}


pub struct ObjectFooterInformationLogical {
    pub object_number: u64,
    pub file_header_map: HashMap<u64, FileHeaderInformation>, //<file number, FileHeader>
    pub file_footer_map: HashMap<u64, FileFooterInformation> //<file number, FileFooter>
}

impl Serialize for ObjectFooterInformationLogical {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ObjectFooterInformationLogical", 6)?;
        state.serialize_field("object number", &self.object_number)?;
        let mut stringified_file_header_map = HashMap::new();
        for (file_number, file_header) in &self.file_header_map {
            stringified_file_header_map.insert(file_number.to_string(), file_header);
        };
        let mut stringified_file_footer_map = HashMap::new();
        for (file_number, file_footer) in &self.file_footer_map {
            stringified_file_footer_map.insert(file_number.to_string(), file_footer);
        };

        state.serialize_field("file header", &stringified_file_header_map)?;
        state.serialize_field("file footer", &stringified_file_footer_map)?;

        state.end()
    }
}

pub struct FileHeaderInformation {
    pub file_type: FileType,
    pub filename: String,
    pub parent_file_number: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub btime: u64,
    pub metadata_extended_information: HashMap<String, String>
}

impl Serialize for FileHeaderInformation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
    	//unwrap should be safe here, because the format string was tested.
    	let format = format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second] UTC").unwrap();

        let mut state = serializer.serialize_struct("FileHeaderInformation", 6)?;

        state.serialize_field("file type", &FileTypeInformation::from(&self.file_type))?;
		state.serialize_field("filename", &self.filename)?;
		state.serialize_field("parent file number", &self.parent_file_number)?;

    	//atime
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.atime as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field("atime", &formatted_dt)?;
    		} else {
    			state.serialize_field("atime", &self.atime)?;
    		}
    	} else {
    		state.serialize_field("atime", &self.atime)?;
    	};

    	//mtime
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.mtime as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field("mtime", &formatted_dt)?;
    		} else {
    			state.serialize_field("mtime", &self.mtime)?;
    		}
    	} else {
    		state.serialize_field("mtime", &self.mtime)?;
    	};

    	//ctime
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.ctime as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field("ctime", &formatted_dt)?;
    		} else {
    			state.serialize_field("ctime", &self.ctime)?;
    		}
    	} else {
    		state.serialize_field("ctime", &self.ctime)?;
    	};

    	//btime
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.btime as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field("btime", &formatted_dt)?;
    		} else {
    			state.serialize_field("btime", &self.btime)?;
    		}
    	} else {
    		state.serialize_field("btime", &self.btime)?;
    	};

    	state.serialize_field("metadata extended information", &self.metadata_extended_information)?;

        state.end()
    }
}

#[derive(Debug)]
pub struct FileFooterInformation {
    pub acquisition_start: u64,
    pub acquisition_end: u64,
    pub hash_information: Vec<HashInformation>,
    pub number_of_chunks: u64,
    pub length_of_data: u64,
}

impl Serialize for FileFooterInformation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
    	//unwrap should be safe here, because the format string was tested.
    	let format = format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second] UTC").unwrap();

        let mut state = serializer.serialize_struct("FileFooterInformation", 6)?;

    	//acquisition start
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.acquisition_start as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field("acquisition_start", &formatted_dt)?;
    		} else {
    			state.serialize_field("acquisition_start", &self.acquisition_start)?;
    		}
    	} else {
    		state.serialize_field("acquisition_start", &self.acquisition_start)?;
    	};

    	//acquisition end
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.acquisition_end as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field("acquisition_end", &formatted_dt)?;
    		} else {
    			state.serialize_field("acquisition_end", &self.acquisition_end)?;
    		}
    	} else {
    		state.serialize_field("acquisition_end", &self.acquisition_end)?;
    	};
        state.serialize_field("length of data", &format!("{} ({} bytes)", &self.length_of_data.bytes_as_hrb(), &self.length_of_data))?;
        state.serialize_field("number of chunks", &self.number_of_chunks)?;
        for hash_info in &self.hash_information {
        	state.serialize_field("hash information", &hash_info)?;
        };
        state.end()
    }
}

#[derive(Serialize)]
pub struct CompressionInformation {
    pub algorithm: CompressionAlgorithmInformation,
    pub level: u8,
    pub threshold: f32
}

#[derive(Debug)]
pub struct HashInformation {
    pub hash_type: HashType,
    pub hash: Vec<u8>,
    pub ed25519_signature: Option<[u8; 64]>
}

impl Serialize for HashInformation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HashInformation", 3)?;
        state.serialize_field("hash type", &self.hash_type.to_string())?;
        state.serialize_field("hash", &self.hash.encode_hex::<String>())?;
        if let Some(signature) = &self.ed25519_signature {
        	state.serialize_field("signature", &base64::encode(signature))?;
        }
        state.end()
    }
}

pub struct ChunkInformation {
    pub chunk_number: u64,
    pub chunk_size: u64,
    pub crc32: u32,
    pub error_flag: bool,
    pub compression_flag: bool,
    pub ed25519_signature: Option<[u8; 64]>
}

impl Serialize for ChunkInformation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ChunkInformation", 6)?;
        state.serialize_field("chunk number", &self.chunk_number)?;
        state.serialize_field("chunk size", &format!("{} ({} bytes)", &self.chunk_size.bytes_as_hrb(), &self.chunk_size))?;
        state.serialize_field("crc32", &self.crc32.to_string().encode_hex::<String>())?;
        state.serialize_field("error flag", &self.error_flag)?;
        state.serialize_field("compression flag", &self.compression_flag)?;
        if let Some(signature) = &self.ed25519_signature {
        	state.serialize_field("signature", &base64::encode(signature))?;
        }
        state.end()
    }
}