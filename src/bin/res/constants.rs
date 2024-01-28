// External
pub(crate) const INPUTFILES_PATH_PREFIX: &str = "/";

// Error messages
pub(crate) const ERROR_CANONICALIZE_INPUT_FILE_: &str = "An error occurred while trying to canonicalize following inputfile: ";
pub(crate) const ERROR_STRIPPING_PREFIX_INPUT_FILE_: &str = "An error occurred while trying to stripping the path-prefix of following inputfile: ";

// Exit status codes
pub(crate) const EXIT_STATUS_ERROR: i32 = 1;
pub(crate) const EXIT_STATUS_SUCCESS: i32 = 0;

// default values
pub(crate) const DEFAULT_DATE_FORMAT: &str = "[year]-[month]-[day] [hour]:[minute]:[second] UTC";

// Other
#[cfg(target_family = "unix")]
pub(crate) const UNIX_BASE: &str = "/";


// Serialized struct names
pub(crate) const SER_STRUCT_CONTAINER_INFO: &str = "container_info";
pub(crate) const SER_STRUCT_OBJECT_INFO: &str = "object_info";
pub(crate) const SER_FIELD_ENCRYPTED_OBJECT_INFOS: &str = "encrypted_object";
pub(crate) const SER_STRUCT_SEGMENT_INFO: &str = "segment_info";
pub(crate) const SER_STRUCT_FILE_INFO: &str = "file_info";


// Serializer field names
pub(crate) const SER_FIELD_OBJECT_NUMBER: &str = "object_number";
pub(crate) const SER_FIELD_OBJECT_FLAGS: &str = "object_flags";
pub(crate) const SER_FIELD_ENCRYPTION_HEADER: &str = "encryption_header";
pub(crate) const SER_FIELD_CHUNK_SIZE: &str = "chunk_size";
pub(crate) const SER_FIELD_COMPRESSION_HEADER: &str = "compression_header";
pub(crate) const SER_FIELD_DESCRIPTION_HEADER: &str = "description_header";
pub(crate) const SER_FIELD_OBJECT_TYPE: &str = "object_type";
pub(crate) const SER_FIELD_ACQUISITION_START: &str = "acquisition_start";
pub(crate) const SER_FIELD_ACQUISITION_END: &str = "acquisition_end";
pub(crate) const SER_FIELD_SIZE_OF_DATA: &str = "size_of_data";
pub(crate) const SER_FIELD_FIRST_CHUNK_NUMBER: &str = "first_chunk_number";
pub(crate) const SER_FIELD_NUMBER_OF_CHUNKS: &str = "total_number_of_chunks";
pub(crate) const SER_FIELD_HASH_HEADER: &str = "hash_header";
pub(crate) const SER_FIELD_NUMBER_OF_FILES: &str = "total_number_of_files";
pub(crate) const SER_FIELD_CREATION_DATE: &str = "creation_date";
pub(crate) const SER_FIELD_PASSIVE_OBJECTS: &str = "passive_objects";
pub(crate) const SER_FIELD_SEGMENT_INFOS: &str = "segment";
pub(crate) const SER_FIELD_OBJECT_INFOS: &str = "object";
pub(crate) const SER_FIELD_UNIQUE_IDENTIFIER: &str = "unique_identifier";
pub(crate) const SER_FIELD_SEGMENT_NUMBER: &str = "segment_number";
pub(crate) const SER_FIELD_CHUNKMAP_SIZE: &str = "target_chunkmap_size";
pub(crate) const SER_FIELD_LENGTH_OF_SEGMENT: &str = "length_of_segment";
pub(crate) const SER_NUMBER_OF_CHUNKMAPS: &str = "number_of_chunkmaps";
pub(crate) const SER_FIELD_CHUNKMAP: &str = "chunkmap";
pub(crate) const SER_FIELD_NUMBER_OF_SEGMENTS: &str = "total_number_of_segments";
pub(crate) const SER_FIELD_DESCRIPTION_NOTE: &str = "description_note";
pub(crate) const SER_FIELD_FILE: &str = "file";
pub(crate) const SER_FIELD_FILE_NUMBER: &str = "file_number";
pub(crate) const SER_FIELD_FILE_TYPE: &str = "file_type";
pub(crate) const SER_FIELD_FILE_NAME: &str = "file_name";
pub(crate) const SER_FIELD_PARENT_FILE_NUMBER: &str = "parent_file_number";
pub(crate) const SER_FIELD_EXTENDED_METADATA: &str = "extended_metadata";

// Description header keys
pub(crate) const DESCRIPTION_KEY_CASE_NUMBER: &str = "case_number";
pub(crate) const DESCRIPTION_KEY_EXAMINER_NAME: &str = "examiner_name";
pub(crate) const DESCRIPTION_KEY_EVIDENCE_NUMBER: &str = "evidence_number";
pub(crate) const DESCRIPTION_KEY_NOTES: &str = "notes";
pub(crate) const DESCRIPTION_KEY_TOOL_NAME: &str = "tool_name";
pub(crate) const DESCRIPTION_KEY_TOOL_VERSION: &str = "tool_version";

pub(crate) const ENCODING_KEY_TOOL_NAME: &str = "tn";
pub(crate) const ENCODING_KEY_TOOL_VERSION: &str = "tv";