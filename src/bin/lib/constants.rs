// Error messages
pub(crate) const ERROR_OPEN_INPUT_FILE: &str = "An error occurred while trying to open the input file: ";
pub(crate) const ERROR_FILE_READ: &str = "An error occurred while trying to read the input file: ";
pub(crate) const ERROR_UNKNOWN_HEADER: &str = "Could not read header of this file. This file is not a well formatted zff file.";

pub(crate) const ERROR_SERIALIZE_TOML: &str = "An error occurred while trying to serialize the decoded information to toml format: ";
pub(crate) const ERROR_SERIALIZE_JSON: &str = "An error occurred while trying to serialize the decoded information to json format: ";
pub(crate) const ERROR_SERIALIZE_UNKNOWN_SERIALIZER: &str = "Unknown output format.";

pub(crate) const ERROR_PARSE_MAIN_HEADER: &str = "An error occurred while trying to parse the main header: ";
pub(crate) const ERROR_PARSE_ENCRYPTED_MAIN_HEADER: &str = "An error occurred while trying to parse the (encrypted) main header: ";
pub(crate) const ERROR_PARSE_SEGMENT_HEADER: &str = "An error occurred while trying to parse the segment header: ";
pub(crate) const ERROR_WRONG_PASSWORD: &str = "Incorrect password";
pub(crate) const ERROR_UNSUPPORTED_ZFF_MAIN_HEADER_VERSION: &str = "Unsupported main header version: found header version ";
pub(crate) const ERROR_UNSUPPORTED_ZFF_SEGMENT_HEADER_VERSION: &str = "Unsupported segment header version: found header version ";
pub(crate) const ERROR_DECRYPTION_PASSWORD_NEEDED: &str = "Password is needed to decrypt the header";
pub(crate) const ERROR_DECODE_SEGMENT_HEADER: &str = "Error while trying to decode segment header: ";
pub(crate) const ERROR_GET_SEGMENT_INFORMATION_V1: &str = "Error while trying to parse segment information for zff segment v1: ";
pub(crate) const ERROR_GET_SEGMENT_INFORMATION_V2: &str = "Error while trying to parse segment information for zff segment v2: ";

pub(crate) const EXIT_STATUS_ERROR: i32 = 1;
pub(crate) const EXIT_STATUS_SUCCESS: i32 = 0;


// verifier results
pub(crate) const VERIFIER_RESULT_SUCCESS: &'static str = "The data of the image is valid";
pub(crate) const VERIFIER_RESULT_CORRUPTION_FOUND: &'static str = "Corrupted data chunks found. The following chunks (listet by chunk numbers) are NOT valid:";
pub(crate) const VERIFIER_RESULT_ERROR: &'static str = "An error occurred while trying to verify the data: ";