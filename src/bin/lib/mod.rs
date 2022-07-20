// - STD
use std::path::PathBuf;
use std::str::FromStr;
use std::collections::HashMap;

// - internal
use zff::{ZffError, ZffErrorKind, SignatureFlag};

// - external
use hex::ToHex;
use serde::ser::{Serialize, Serializer, SerializeStruct};
use time::{OffsetDateTime, format_description};

pub mod constants;
pub mod traits;

// - internal
use zff::{
	HashType,
	header::version2::{ObjectType, FileType, EncryptionHeader, PBEHeader, KDFParameters},
	CompressionAlgorithm,
    KDFScheme,
    PBEScheme,
    EncryptionAlgorithm,
};
use crate::constants::*;
use traits::*;

pub fn concat_prefix_path<P: Into<String>>(prefix: P, path: &PathBuf) -> PathBuf {
    let mut new_path = PathBuf::from(prefix.into());
    new_path.push(path);
    new_path
}

fn string_to_str(s: String) -> &'static str {
  Box::leak(s.into_boxed_str())
}

pub enum PredefinedDescriptionHeaderInformationKeys {
    CaseNumber,
    EvidenceNumber,
    ExaminerName,
    Notes,
}

impl FromStr for PredefinedDescriptionHeaderInformationKeys {
    type Err = ZffError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cn" => Ok(PredefinedDescriptionHeaderInformationKeys::CaseNumber),
            "ev" => Ok(PredefinedDescriptionHeaderInformationKeys::EvidenceNumber),
            "ex" => Ok(PredefinedDescriptionHeaderInformationKeys::ExaminerName),
            "no" => Ok(PredefinedDescriptionHeaderInformationKeys::Notes),
            _ => Err(ZffError::new(ZffErrorKind::Custom, s)),
        }
    }
}


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
        let mut state = serializer.serialize_struct(SER_INFORMATION, 6)?;
        match self {
            Information::MainInformationV1(main) => state.serialize_field(SER_MAIN, &main)?,
            Information::SegmentInformation(seg) => state.serialize_field(SER_SEGMENT, &seg)?,
            Information::MainHeaderInformationV2(main) => state.serialize_field(SER_MAIN, &main)?,
            Information::MainFooterInformation(main) => state.serialize_field(SER_MAIN, &main)?,
            Information::ObjectHeaderInformation(obj_header) => {
                let key = string_to_str(format!("{SER_OBJECT_HEADER}_{}", obj_header.object_number));
                state.serialize_field(key, &obj_header)?
            },
            Information::ObjectFooterInformationLogical(obj_footer) => {
                let key = string_to_str(format!("{SER_OBJECT_FOOTER}_{}", obj_footer.object_number));
                state.serialize_field(key, &obj_footer)?
            },
            Information::ObjectFooterInformationPhysical(obj_footer) => {
                let key = string_to_str(format!("{SER_OBJECT_FOOTER}_{}", obj_footer.object_number));
                state.serialize_field(key, &obj_footer)?
            },
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
        let mut state = serializer.serialize_struct(SER_INFORMATION, 7)?;
        state.serialize_field(SER_CHUNK_SIZE, &format!("{} ({} {SER_BYTES})", &self.chunk_size.bytes_as_hrb(), &self.chunk_size))?;
        state.serialize_field(SER_SIGNATURE_FLAG, &self.signature_flag)?;
        state.serialize_field(SER_SEGMENT_SIZE, &self.segment_size)?;
        state.serialize_field(SER_NUMBER_OF_SEGMENTS, &self.number_of_segments)?;
        state.serialize_field(SER_LENGTH_OF_DATA, &self.length_of_data)?;
        state.serialize_field(SER_COMPRESSION_INFORMATION, &self.compression_information)?;
        state.serialize_field(SER_SEGMENT_INFORMATION, &self.segment_information)?;
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
        let mut state = serializer.serialize_struct(SER_INFORMATION, 6)?;
        state.serialize_field(SER_SEGMENT_NUMBER, &self.segment_number)?;
        state.serialize_field(SER_LENGTH_OF_SEGMENT, &format!("{} ({} {SER_BYTES})", &self.length_of_segment.bytes_as_hrb(), &self.length_of_segment))?;
        for chunk in &self.chunk_information {
        	state.serialize_field(SER_CHUNK, &chunk)?;
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
        let mut state = serializer.serialize_struct(SER_INFORMATION, 6)?;
        state.serialize_field(SER_CHUNK_SIZE, &format!("{} ({} {SER_BYTES})", &self.chunk_size.bytes_as_hrb(), &self.chunk_size))?;
        state.serialize_field(SER_SEGMENT_SIZE, &format!("{} ({} {SER_BYTES})", &self.segment_size.bytes_as_hrb(), &self.segment_size))?;
        state.serialize_field(SER_SEGMENT_INFORMATION, &self.segment_information)?;
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
    pub signature_flag: SignatureFlag,
    pub description_header: DescriptionHeaderInformation,
    pub object_type: ObjectType,
    pub encryption_header: Option<EncryptionHeader>,
}

impl Serialize for ObjectHeaderInformation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        
        let mut state = serializer.serialize_struct(SER_INFORMATION, 6)?;
        state.serialize_field(SER_OBJECT_NUMBER, &self.object_number)?;
        state.serialize_field(SER_COMPRESSION_INFORMATION, &self.compression_information)?;
        state.serialize_field(SER_OBJECT_TYPE, &ObjectTypeInformation::from(&self.object_type))?;
        
        let description_header_information = {
            let mut new_map = HashMap::new();
            for (key, value) in &self.description_header.information {
                match PredefinedDescriptionHeaderInformationKeys::from_str(key) {
                    Err(_) => { new_map.insert(key.to_string(), value); },
                    Ok(key) => match key {
                        PredefinedDescriptionHeaderInformationKeys::CaseNumber => { new_map.insert(String::from(SER_CASE_NUMBER), value); },
                        PredefinedDescriptionHeaderInformationKeys::EvidenceNumber => { new_map.insert(String::from(SER_EVIDENCE_NUMBER), value); },
                        PredefinedDescriptionHeaderInformationKeys::ExaminerName => { new_map.insert(String::from(SER_EXAMINER_NAME), value); },
                        PredefinedDescriptionHeaderInformationKeys::Notes => { new_map.insert(String::from(SER_NOTES), value); },
                    },
                }
            }
            new_map
        };
        state.serialize_field(SER_DESCRIPTION_INFORMATION, &description_header_information)?;
        state.serialize_field(SER_SIGNATURE_FLAG, &self.signature_flag.to_string())?;

        if let Some(encryption_header) = &self.encryption_header {
            state.serialize_field(SER_ENCRYPTION_INFORMATION, &EncryptionHeaderInformation::from(encryption_header))?;
        }

        state.end()
    }
}

pub struct EncryptionHeaderInformation {
    pub pbe_header: PBEHeader,
    pub encryption_algorithm: EncryptionAlgorithm,
}

impl Serialize for EncryptionHeaderInformation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        
        let mut state = serializer.serialize_struct(SER_INFORMATION, 2)?;
        state.serialize_field(SER_PBE_HEADER, &PBEHeaderInformation::from(&self.pbe_header))?;
        match self.encryption_algorithm {
            EncryptionAlgorithm::AES128GCMSIV => state.serialize_field(SER_ENCRYPTION_ALGORITHM, ENC_ALGO_AES128GCMSIV)?,
            EncryptionAlgorithm::AES256GCMSIV => state.serialize_field(SER_ENCRYPTION_ALGORITHM, ENC_ALGO_AES256GCMSIV)?,
            _ => state.serialize_field(SER_ENCRYPTION_ALGORITHM, ENC_ALGO_UNKNOWN)?,
        }

        state.end()
    }
}

impl From<EncryptionHeader> for EncryptionHeaderInformation {
    fn from(header: EncryptionHeader) -> EncryptionHeaderInformation {
        EncryptionHeaderInformation {
            pbe_header: header.pbe_header().clone(),
            encryption_algorithm: header.algorithm().clone(),
        }
    }
}

impl From<&EncryptionHeader> for EncryptionHeaderInformation {
    fn from(header: &EncryptionHeader) -> EncryptionHeaderInformation {
        EncryptionHeaderInformation {
            pbe_header: header.pbe_header().clone(),
            encryption_algorithm: header.algorithm().clone(),
        }
    }
}

pub struct PBEHeaderInformation {
    pub kdf_scheme: KDFScheme,
    pub encryption_scheme: PBEScheme,
    pub kdf_parameters: KDFParameters,
    pub pbencryption_nonce: [u8; 16],
}

impl Serialize for PBEHeaderInformation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        
        let mut state = serializer.serialize_struct(SER_INFORMATION, 4)?;
        let kdf_scheme = match self.kdf_scheme {
            KDFScheme::PBKDF2SHA256 => ENC_ALGO_PBKDF2_SHA256,
            KDFScheme::Scrypt => ENC_ALGO_SCRYPT,
            _ => ENC_ALGO_UNKNOWN
        };
        state.serialize_field(SER_KDF_SCHEME, &kdf_scheme)?;

        state.end()
    }
}

impl From<PBEHeader> for PBEHeaderInformation {
    fn from(header: PBEHeader) -> PBEHeaderInformation {
        PBEHeaderInformation {
            kdf_scheme: header.kdf_scheme().clone(),
            encryption_scheme: header.encryption_scheme().clone(),
            kdf_parameters: header.kdf_parameters().clone(),
            pbencryption_nonce: *header.nonce()
        }
    }
}

impl From<&PBEHeader> for PBEHeaderInformation {
    fn from(header: &PBEHeader) -> PBEHeaderInformation {
        PBEHeaderInformation {
            kdf_scheme: header.kdf_scheme().clone(),
            encryption_scheme: header.encryption_scheme().clone(),
            kdf_parameters: header.kdf_parameters().clone(),
            pbencryption_nonce: *header.nonce()
        }
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
    	let format = format_description::parse(DEFAULT_DATE_FORMAT).unwrap();

        let mut state = serializer.serialize_struct(SER_INFORMATION, 6)?;

    	//acquisition start
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.acquisition_start as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field(SER_ACQUISITION_START, &formatted_dt)?;
    		} else {
    			state.serialize_field(SER_ACQUISITION_START, &self.acquisition_start)?;
    		}
    	} else {
    		state.serialize_field(SER_ACQUISITION_START, &self.acquisition_start)?;
    	};

    	//acquisition end
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.acquisition_end as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field(SER_ACQUISITION_END, &formatted_dt)?;
    		} else {
    			state.serialize_field(SER_ACQUISITION_END, &self.acquisition_end)?;
    		}
    	} else {
    		state.serialize_field(SER_ACQUISITION_END, &self.acquisition_end)?;
    	};

        state.serialize_field(SER_OBJECT_NUMBER, &self.object_number)?;
        state.serialize_field(SER_LENGTH_OF_DATA, &format!("{} ({} {SER_BYTES})", &self.length_of_data.bytes_as_hrb(), &self.length_of_data))?;
        state.serialize_field(SER_NUMBER_OF_CHUNKS, &self.number_of_chunks)?;
        for hash_info in &self.hash_information {
        	state.serialize_field(SER_HASH_INFORMATION, &hash_info)?;
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
        let mut state = serializer.serialize_struct(SER_INFORMATION, 6)?;
        state.serialize_field(SER_OBJECT_NUMBER, &self.object_number)?;
        let mut stringified_file_header_map = HashMap::new();
        for (file_number, file_header) in &self.file_header_map {
            stringified_file_header_map.insert(file_number.to_string(), file_header);
        };
        let mut stringified_file_footer_map = HashMap::new();
        for (file_number, file_footer) in &self.file_footer_map {
            stringified_file_footer_map.insert(file_number.to_string(), file_footer);
        };

        state.serialize_field(SER_FILE_HEADER, &stringified_file_header_map)?;
        state.serialize_field(SER_FILE_FOOTER, &stringified_file_footer_map)?;

        state.end()
    }
}

pub struct DescriptionHeaderInformation {
    pub information: HashMap<String, String>,
}

impl Serialize for DescriptionHeaderInformation {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(SER_INFORMATION, 6)?;
        for (key, value) in &self.information {
            let key = string_to_str(key.to_string());
            state.serialize_field(key, &value)?;
        }

        state.end()
    }
}

#[derive(Debug)]
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
    	let format = format_description::parse(DEFAULT_DATE_FORMAT).unwrap();

        let mut state = serializer.serialize_struct(SER_INFORMATION, 6)?;

        state.serialize_field(SER_FILETYPE, &FileTypeInformation::from(&self.file_type))?;
		state.serialize_field(SER_FILENAME, &self.filename)?;
		state.serialize_field(SER_PARENTFILENUMBER, &self.parent_file_number)?;

    	//atime
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.atime as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field(SER_TIME_ATIME, &formatted_dt)?;
    		} else {
    			state.serialize_field(SER_TIME_ATIME, &self.atime)?;
    		}
    	} else {
    		state.serialize_field(SER_TIME_ATIME, &self.atime)?;
    	};

    	//mtime
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.mtime as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field(SER_TIME_MTIME, &formatted_dt)?;
    		} else {
    			state.serialize_field(SER_TIME_MTIME, &self.mtime)?;
    		}
    	} else {
    		state.serialize_field(SER_TIME_MTIME, &self.mtime)?;
    	};

    	//ctime
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.ctime as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field(SER_TIME_CTIME, &formatted_dt)?;
    		} else {
    			state.serialize_field(SER_TIME_CTIME, &self.ctime)?;
    		}
    	} else {
    		state.serialize_field(SER_TIME_CTIME, &self.ctime)?;
    	};

    	//btime
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.btime as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field(SER_TIME_BTIME, &formatted_dt)?;
    		} else {
    			state.serialize_field(SER_TIME_BTIME, &self.btime)?;
    		}
    	} else {
    		state.serialize_field(SER_TIME_BTIME, &self.btime)?;
    	};

    	state.serialize_field(SER_METADATA_EXTENDED_INFORMATION, &self.metadata_extended_information)?;

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
    	let format = format_description::parse(DEFAULT_DATE_FORMAT).unwrap();

        let mut state = serializer.serialize_struct(SER_INFORMATION, 6)?;

    	//acquisition start
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.acquisition_start as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field(SER_ACQUISITION_START, &formatted_dt)?;
    		} else {
    			state.serialize_field(SER_ACQUISITION_START, &self.acquisition_start)?;
    		}
    	} else {
    		state.serialize_field(SER_ACQUISITION_START, &self.acquisition_start)?;
    	};

    	//acquisition end
    	if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.acquisition_end as i64) {
    		if let Ok(formatted_dt) = dt.format(&format) {
    			state.serialize_field(SER_ACQUISITION_END, &formatted_dt)?;
    		} else {
    			state.serialize_field(SER_ACQUISITION_END, &self.acquisition_end)?;
    		}
    	} else {
    		state.serialize_field(SER_ACQUISITION_END, &self.acquisition_end)?;
    	};
        state.serialize_field(SER_LENGTH_OF_DATA, &format!("{} ({} bytes)", &self.length_of_data.bytes_as_hrb(), &self.length_of_data))?;
        state.serialize_field(SER_NUMBER_OF_CHUNKS, &self.number_of_chunks)?;
        for hash_info in &self.hash_information {
        	state.serialize_field(SER_HASH_INFORMATION, &hash_info)?;
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
        let mut state = serializer.serialize_struct(SER_INFORMATION, 3)?;
        state.serialize_field(SER_HASH_TYPE, &self.hash_type.to_string())?;
        state.serialize_field(SER_HASH, &self.hash.encode_hex::<String>())?;
        if let Some(signature) = &self.ed25519_signature {
        	state.serialize_field(SER_SIGNATURE, &base64::encode(signature))?;
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
        let mut state = serializer.serialize_struct(SER_INFORMATION, 6)?;
        state.serialize_field(SER_CHUNK_NUMBER, &self.chunk_number)?;
        state.serialize_field(SER_CHUNK_SIZE, &format!("{} ({}  {SER_BYTES})", &self.chunk_size.bytes_as_hrb(), &self.chunk_size))?;
        state.serialize_field(SER_CRC32, &self.crc32.to_string().encode_hex::<String>())?;
        state.serialize_field(SER_ERROR_FLAG, &self.error_flag)?;
        state.serialize_field(SER_COMPRESSION_FLAG, &self.compression_flag)?;
        if let Some(signature) = &self.ed25519_signature {
        	state.serialize_field(SER_SIGNATURE, &base64::encode(signature))?;
        }
        state.end()
    }
}