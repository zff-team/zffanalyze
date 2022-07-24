// External
pub(crate) const INPUTFILES_PATH_PREFIX: &str = "";

// Error messages
pub(crate) const ERROR_OPEN_INPUT_FILE_: &str = "An error occurred while trying to open the input file: ";
pub(crate) const ERROR_FILE_READ_: &str = "An error occurred while trying to read the input file: ";
pub(crate) const ERROR_UNKNOWN_HEADER: &str = "Could not read header of this file. This file is not a well formatted zff file.";

pub(crate) const ERROR_SERIALIZE_TOML_: &str = "An error occurred while trying to serialize the decoded information to toml format: ";
pub(crate) const ERROR_SERIALIZE_JSON_: &str = "An error occurred while trying to serialize the decoded information to json format: ";

pub(crate) const ERROR_PARSE_MAIN_HEADER_: &str = "An error occurred while trying to parse the main header: ";
pub(crate) const ERROR_PARSE_ENCRYPTED_MAIN_HEADER_: &str = "An error occurred while trying to parse the (encrypted) main header: ";
pub(crate) const ERROR_PARSE_SEGMENT_HEADER_: &str = "An error occurred while trying to parse the segment header: ";
pub(crate) const ERROR_WRONG_PASSWORD: &str = "Incorrect password";
pub(crate) const ERROR_UNSUPPORTED_ZFF_MAIN_HEADER_VERSION_: &str = "Unsupported main header version: found header version ";
pub(crate) const ERROR_UNSUPPORTED_ZFF_SEGMENT_HEADER_VERSION_: &str = "Unsupported segment header version: found header version ";
pub(crate) const ERROR_DECRYPTION_PASSWORD_NEEDED: &str = "Password is needed to decrypt the header";
pub(crate) const ERROR_DECODE_SEGMENT_HEADER_: &str = "Error while trying to decode segment header: ";
pub(crate) const ERROR_GET_SEGMENT_INFORMATION_V1_: &str = "Error while trying to parse segment information for zff segment v1: ";
pub(crate) const ERROR_GET_SEGMENT_INFORMATION_V2_: &str = "Error while trying to parse segment information for zff segment v2: ";
pub(crate) const ERROR_UNIMPLEMENTED_COMPRESSION_ALGORITHM: &str = "An error occurred while trying to interpret the compression algorithm. The used algorithm is currently not supported by zffanalyze.";
pub(crate) const ERROR_UNIMPLEMENTED_FILETYPE: &str = "An error occurred while trying to interpret the file type. The used file type is currently not supported by zffanalyze.";
pub(crate) const ERROR_TRYING_CALCULATE_HASHES_: &str = "An error occurred, while trying to calculate hash values: ";
pub(crate) const ERROR_TRYING_VERIFY_SIGNATURES_: &str = "An error occurred, while trying to check the signatures: ";
pub(crate) const ERROR_DECRYPT_OBJECT_: &str = "Could not decrypt object ";
pub(crate) const ERROR_UNEXPECTED_PUBKEY_LENGTH: &str = "public_key has an unexpected length: ";
pub(crate) const ERROR_PER_CHUNK_SIGS_NO_SIGS_FOUND: &str = "Could not verify per chunk signatures: no signatures found.";
pub(crate) const ERROR_GET_OBJ_HEADER_INFORMATION_: &str = "Error: get_object_header_information: ";
pub(crate) const ERROR_SET_OBJ_FOOTER_INFORMATION_: &str = "Error: set_object_footer_information_logical: ";
pub(crate) const ERROR_CANONICALIZE_INPUT_FILE_: &str = "An error occurred while trying to canonicalize following inputfile: ";
pub(crate) const ERROR_STRIPPING_PREFIX_INPUT_FILE_: &str = "An error occurred while trying to stripping the path-prefix of following inputfile: ";

// Other messages
pub(crate) const HINT_BAD_PASSWORD: &str = "bad or missing password(s)?";
pub(crate) const M_VERIFING_PER_CHUNK_SIGS_OBJ_: &str = "Verifing per chunk signatures for object ";
pub(crate) const M_VERIFING_HASH_SIGS_OBJ_: &str = "Verifing hash signatures for object ";

pub(crate) const M_ALL_SIGS_VALID: &str = "    ... all signatures are valid.";
pub(crate) const M_INVALID_SIGS_FOR_CHUNKS_: &str = "    ... invalid signatures found for following chunks:";

pub(crate) const M_NO_SIGS_FOUND_FOR_: &str ="    ... no signatures found for ";
pub(crate) const M_VALID_SIG_FOR_: &str = "    ... valid signature for ";
pub(crate) const M_INVALID_SIG_FOR_: &str = "    ... invalid signature (or wrong public key?) for ";
pub(crate) const M_NO_HASHES_CALCULATED_IN_OBJ: &str = "    ... no hashes calculated in this object.";
pub(crate) const M_NO_SIGS_FOR_HASHES_OF_FILE_: &str = "    ... no hash signatures found for file ";
pub(crate) const M_INVALID_HASH_SIG_OF_FILE_: &str = "    ... invalid hash signature for file ";
pub(crate) const M_CALCULATING_COMPARING_HASH_VALUES_OBJ_: &str = "Calculating and comparing hash values for object ";
pub(crate) const M_NO_HASH_VALUES_FOR_OBJ_: &str = "  ... no calculated hash values available for object "; 
pub(crate) const M_SUCCESSFUL_INTEGRITY_CHECK_HASH_: &str = "    ... done. Hash value-based integrity check successful. Hash value is correct. ";
pub(crate) const M_FAILED_INTEGRITY_CHECK_HASH_: &str = "    ... failed. Hash value-based integrity check failed: incorrect hash value. ";
pub(crate) const M_NO_HASH_FOR_FILE_: &str = "  ... no calculated hash values available for file no ";
pub(crate) const M_SUCCESSFUL_INTEGRITY_CHECK_ALL_FILES: &str = "    ... done. Hash value-based integrity checks of all object files successful. Hash values are correct.";
pub(crate) const M_FAILED_INTEGRITY_CHECK_ALL_FILES: &str = "    ... failed. Hash value-based integrity checks of some object files failed: incorrect hash value(s).";
pub(crate) const M_ENCRYPTED_OBJ_HEADER_IN_OBJ_: &str = "Warning: encrypted and unreadable object header in object ";

// Exit status codes
pub(crate) const EXIT_STATUS_ERROR: i32 = 1;
pub(crate) const EXIT_STATUS_SUCCESS: i32 = 0;

// default values
pub(crate) const BUFFER_DEFAULT_SIZE: usize = 1048576;

pub(crate) const DEFAULT_DATE_FORMAT: &str = "[year]-[month]-[day] [hour]:[minute]:[second] UTC";


// serializer struct/field names
pub(crate) const SER_INFORMATION: &str = "Information";
pub(crate) const SER_MAIN: &str = "Main";
pub(crate) const SER_SEGMENT: &str = "Segment";
pub(crate) const SER_OBJECT_HEADER: &str = "object_header";
pub(crate) const SER_OBJECT_FOOTER: &str = "object_footer";
pub(crate) const SER_CHUNK_SIZE: &str = "chunk_size";
pub(crate) const SER_SIGNATURE_FLAG: &str = "signature_flag";
pub(crate) const SER_SEGMENT_SIZE: &str = "segment_size";
pub(crate) const SER_NUMBER_OF_SEGMENTS: &str = "number_of_segments";
pub(crate) const SER_LENGTH_OF_DATA: &str = "length_of_data";
pub(crate) const SER_COMPRESSION_INFORMATION: &str = "compression_information";
pub(crate) const SER_SEGMENT_INFORMATION: &str = "segment_information";
pub(crate) const SER_BYTES: &str = "bytes";
pub(crate) const SER_SEGMENT_NUMBER: &str = "segment_number";
pub(crate) const SER_LENGTH_OF_SEGMENT: &str = "length_of_segment";
pub(crate) const SER_CHUNK: &str = "chunk";
pub(crate) const SER_OBJECT_NUMBER: &str = "object_number";
pub(crate) const SER_OBJECT_TYPE: &str = "object_type";
pub(crate) const SER_DESCRIPTION_INFORMATION: &str = "description_information";
pub(crate) const SER_ENCRYPTION_INFORMATION: &str = "encryption_information";
pub(crate) const SER_HASH_INFORMATION: &str = "hash_information";
pub(crate) const SER_PBE_HEADER: &str = "pbe_header";
pub(crate) const SER_ENCRYPTION_ALGORITHM: &str = "encryption_algorithm";
pub(crate) const SER_KDF_SCHEME: &str = "kdf_scheme";
pub(crate) const SER_ACQUISITION_START: &str = "acquisition_start";
pub(crate) const SER_ACQUISITION_END: &str = "acquisition_end";
pub(crate) const SER_NUMBER_OF_CHUNKS: &str = "number_of_chunks";
pub(crate) const SER_FILE_HEADER: &str = "fileheader";
pub(crate) const SER_FILE_FOOTER: &str = "filefooter";
pub(crate) const SER_FILETYPE: &str = "filetype";
pub(crate) const SER_FILENAME: &str = "filename";
pub(crate) const SER_PARENTFILENUMBER: &str = "parent_filenumber";
pub(crate) const SER_METADATA_EXTENDED_INFORMATION: &str = "metadata_extended_information";
pub(crate) const SER_HASH_TYPE: &str = "hash_type";
pub(crate) const SER_HASH: &str = "hash";
pub(crate) const SER_SIGNATURE: &str = "signature";
pub(crate) const SER_CHUNK_NUMBER: &str = "chunk_number";
pub(crate) const SER_CRC32: &str = "crc32";
pub(crate) const SER_ERROR_FLAG: &str = "error_flag";
pub(crate) const SER_COMPRESSION_FLAG: &str = "compression_flag";

pub(crate) const SER_TIME_ATIME: &str = "atime";
pub(crate) const SER_TIME_MTIME: &str = "mtime";
pub(crate) const SER_TIME_CTIME: &str = "ctime";
pub(crate) const SER_TIME_BTIME: &str = "btime";


pub(crate) const SER_CASE_NUMBER: &str = "case_number";
pub(crate) const SER_EVIDENCE_NUMBER: &str = "evidence_number";
pub(crate) const SER_EXAMINER_NAME: &str = "examiner_name";
pub(crate) const SER_NOTES: &str = "notes";

// encryption algorithms
pub(crate) const ENC_ALGO_AES256GCMSIV: &str = "AES-256-GCM-SIV";
pub(crate) const ENC_ALGO_AES128GCMSIV: &str = "AES-128-GCM-SIV";

pub(crate) const ENC_ALGO_PBKDF2_SHA256: &str = "pbkdf2/sha256";
pub(crate) const ENC_ALGO_SCRYPT: &str = "scrypt";


pub(crate) const ENC_ALGO_UNKNOWN: &str = "unknown_encryption_algorithm";


// Other
#[cfg(target_family = "unix")]
pub(crate) const UNIX_BASE: &str = "/";