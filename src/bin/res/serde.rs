// - STD
use std::collections::BTreeMap;

// - internal
use crate::res::traits::HumanReadable;
use crate::*;
use zff::constants::{
    ENCODING_KEY_CASE_NUMBER, ENCODING_KEY_EVIDENCE_NUMBER, ENCODING_KEY_EXAMINER_NAME,
    ENCODING_KEY_NOTES, METADATA_ATIME, METADATA_BTIME, METADATA_CTIME, METADATA_MTIME,
};
use zff::header::MetadataExtendedValue;

// - external
use serde::ser::{Serialize, SerializeStruct, Serializer};
use time::{format_description, OffsetDateTime};

#[derive(Serialize, Debug)]
pub(crate) struct EncryptedObjectInfo {
    pub header: EncryptedObjectHeader,
    pub footer: EncryptedObjectFooter,
}

#[derive(Debug)]
pub(crate) struct ObjectInfo {
    pub header: ObjectHeader,
    pub footer: ObjectFooter,
    pub files: Option<BTreeMap<u64, FileInfo>>,
    pub virtual_files: Option<BTreeMap<u64, VirtualFileInfo>>,
}

impl Serialize for ObjectInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        debug!("Serialize object {}", self.header.object_number);
        let footer_value = match self.footer {
            ObjectFooter::Physical(_) => 6,
            _ => 3,
        };
        let mut state = serializer.serialize_struct(
            SER_STRUCT_OBJECT_INFO,
            7 + footer_value
                + usize::from(self.files.is_some())
                + usize::from(self.virtual_files.is_some()),
        )?;
        state.serialize_field(SER_FIELD_OBJECT_NUMBER, &self.header.object_number)?;
        state.serialize_field(SER_FIELD_CHUNK_SIZE, &self.header.chunk_size)?;
        state.serialize_field(SER_FIELD_OBJECT_TYPE, &self.header.object_type)?;
        // check the object footer type and show the appropriate information
        match &self.footer {
            ObjectFooter::Physical(footer) => {
                state.serialize_field(
                    SER_FIELD_ACQUISITION_START,
                    &timestamp_to_datetime_formatted(footer.acquisition_start),
                )?;
                state.serialize_field(
                    SER_FIELD_ACQUISITION_END,
                    &timestamp_to_datetime_formatted(footer.acquisition_end),
                )?;
                state.serialize_field(
                    SER_FIELD_SIZE_OF_DATA,
                    &format!(
                        "{} ({})",
                        footer.length_of_data.bytes_as_hrb(),
                        footer.length_of_data
                    ),
                )?;
                state.serialize_field(SER_FIELD_FIRST_CHUNK_NUMBER, &footer.first_chunk_number)?;
                state.serialize_field(SER_FIELD_NUMBER_OF_CHUNKS, &footer.number_of_chunks)?;
                state.serialize_field(SER_FIELD_HASH_HEADER, &footer.hash_header)?;
            }
            ObjectFooter::Logical(footer) => {
                state.serialize_field(
                    SER_FIELD_ACQUISITION_START,
                    &timestamp_to_datetime_formatted(footer.acquisition_start),
                )?;
                state.serialize_field(
                    SER_FIELD_ACQUISITION_END,
                    &timestamp_to_datetime_formatted(footer.acquisition_end),
                )?;
                state.serialize_field(
                    SER_FIELD_NUMBER_OF_FILES,
                    &footer.file_header_offsets.len(),
                )?;
            }
            ObjectFooter::Virtual(footer) => {
                state.serialize_field(
                    SER_FIELD_CREATION_DATE,
                    &timestamp_to_datetime_formatted(footer.creation_timestamp),
                )?;
                state.serialize_field(
                    SER_FIELD_NUMBER_OF_FILES,
                    &footer.file_header_offsets.len(),
                )?;
                state.serialize_field(SER_FIELD_PASSIVE_OBJECTS, &footer.passive_objects)?;
            }
        }
        // ensure that all table containing elements are at the end of this serialization, see
        // https://github.com/toml-rs/toml-rs/issues/142 for further information.
        state.serialize_field(SER_FIELD_OBJECT_FLAGS, &self.header.flags)?;
        let mut encryption_header = self.header.encryption_header.clone();
        if let Some(header) = &mut encryption_header {
            header.decrypted_encryption_key = None;
        }
        state.serialize_field(SER_FIELD_ENCRYPTION_HEADER, &encryption_header)?;
        state.serialize_field(
            SER_FIELD_COMPRESSION_HEADER,
            &self.header.compression_header,
        )?;
        let mut description_header_map = BTreeMap::new();
        for (key, value) in self.header.description_header.identifier_map() {
            match key.as_str() {
                ENCODING_KEY_CASE_NUMBER => {
                    description_header_map.insert(DESCRIPTION_KEY_CASE_NUMBER.to_string(), value);
                }
                ENCODING_KEY_EXAMINER_NAME => {
                    description_header_map.insert(DESCRIPTION_KEY_EXAMINER_NAME.to_string(), value);
                }
                ENCODING_KEY_EVIDENCE_NUMBER => {
                    description_header_map
                        .insert(DESCRIPTION_KEY_EVIDENCE_NUMBER.to_string(), value);
                }
                ENCODING_KEY_NOTES => {
                    description_header_map.insert(DESCRIPTION_KEY_NOTES.to_string(), value);
                }
                ENCODING_KEY_TOOL_NAME => {
                    description_header_map.insert(DESCRIPTION_KEY_TOOL_NAME.to_string(), value);
                }
                ENCODING_KEY_TOOL_VERSION => {
                    description_header_map.insert(DESCRIPTION_KEY_TOOL_VERSION.to_string(), value);
                }
                _ => {
                    description_header_map.insert(key.to_string(), value);
                }
            }
        }
        state.serialize_field(SER_FIELD_DESCRIPTION_HEADER, &description_header_map)?;
        if let Some(files) = &self.files {
            let converted_map: BTreeMap<String, &FileInfo> = files
                .iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect();
            state.serialize_field(SER_FIELD_FILE, &converted_map)?;
        }

        if let Some(files) = &self.virtual_files {
            let converted: BTreeMap<String, _> =
                files.iter().map(|(n, f)| (n.to_string(), f)).collect();
            state.serialize_field(SER_FIELD_FILE, &converted)?;
        }
        state.end()
    }
}

#[derive(Debug)]
pub(crate) struct VirtualFileInfo {
    pub header: FileHeader,
    pub footer: zff::footer::VirtualFileFooter,
    pub map: Option<zff::footer::VirtualFileMap>,
}

impl Serialize for VirtualFileInfo {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut state =
            serializer.serialize_struct("virtual_file", 2 + usize::from(self.map.is_some()))?;
        state.serialize_field("header", &self.header)?;
        state.serialize_field("footer", &self.footer)?;
        if let Some(map) = &self.map {
            let extents: BTreeMap<String, _> = map
                .extents
                .iter()
                .map(|(n, e)| (n.to_string(), e))
                .collect();
            state.serialize_field("extents", &extents)?;
        }
        state.end()
    }
}

#[derive(Debug)]
pub(crate) struct FileInfo {
    pub header: FileHeader,
    pub footer: FileFooter,
}

impl Serialize for FileInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        debug!("Serialize file {}", self.header.file_number);
        let mut state = serializer.serialize_struct(SER_STRUCT_FILE_INFO, 11)?;
        state.serialize_field(SER_FIELD_FILE_NUMBER, &self.header.file_number)?;
        state.serialize_field(SER_FIELD_FILE_NAME, &self.header.filename)?;
        state.serialize_field(
            SER_FIELD_PARENT_FILE_NUMBER,
            &self.header.parent_file_number,
        )?;
        state.serialize_field(
            SER_FIELD_ACQUISITION_START,
            &timestamp_to_datetime_formatted(self.footer.acquisition_start),
        )?;
        state.serialize_field(
            SER_FIELD_ACQUISITION_END,
            &timestamp_to_datetime_formatted(self.footer.acquisition_end),
        )?;
        state.serialize_field(
            SER_FIELD_FIRST_CHUNK_NUMBER,
            &self.footer.first_chunk_number,
        )?;
        state.serialize_field(SER_FIELD_NUMBER_OF_CHUNKS, &self.footer.number_of_chunks)?;
        state.serialize_field(
            SER_FIELD_SIZE_OF_DATA,
            &format!(
                "{} ({})",
                self.footer.length_of_data.bytes_as_hrb(),
                self.footer.length_of_data
            ),
        )?;
        // ensure that all table containing elements are at the end of this serialization, see
        // https://github.com/toml-rs/toml-rs/issues/142 for further information.
        state.serialize_field(SER_FIELD_FILE_TYPE, &self.header.file_type)?;
        state.serialize_field(SER_FIELD_HASH_HEADER, &self.footer.hash_header)?;
        //state.serialize_field(SER_FIELD_EXTENDED_METADATA, &self.header.metadata_ext)?;
        let mut metadata_ext = BTreeMap::new();
        for (key, value) in &self.header.metadata_ext {
            metadata_ext.insert(
                key.to_string(),
                get_extended_metadata_values_to_human_readable(key, value),
            );
        }
        state.serialize_field(SER_FIELD_EXTENDED_METADATA, &metadata_ext)?;

        state.end()
    }
}

#[derive(Debug)]
pub(crate) struct ContainerInfo {
    pub main_footer: Option<MainFooter>,
    pub segments: BTreeMap<u64, SegmentInfo>,
    pub objects: BTreeMap<u64, ObjectInfo>,
    pub encrypted_objects: BTreeMap<u64, EncryptedObjectInfo>,
}

impl Serialize for ContainerInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        debug!("Serialize container info");
        let mut state = serializer.serialize_struct(
            SER_STRUCT_CONTAINER_INFO,
            1 + 2 * usize::from(self.main_footer.is_some())
                + usize::from(!self.objects.is_empty())
                + usize::from(!self.encrypted_objects.is_empty()),
        )?;
        if let Some(main_footer) = &self.main_footer {
            state.serialize_field(
                SER_FIELD_NUMBER_OF_SEGMENTS,
                &main_footer.number_of_segments,
            )?;
            state.serialize_field(SER_FIELD_DESCRIPTION_NOTE, &main_footer.description_notes)?;
        }
        //segments
        let mut segments = BTreeMap::new();
        for (key, value) in &self.segments {
            segments.insert(key.to_string(), value);
        }
        state.serialize_field(SER_FIELD_SEGMENT_INFOS, &segments)?;
        // objects
        let mut objects = BTreeMap::new();
        for (key, value) in &self.objects {
            objects.insert(key.to_string(), value);
        }
        if !objects.is_empty() {
            state.serialize_field(SER_FIELD_OBJECT_INFOS, &objects)?;
        }
        // encrypted objects
        let mut encrypted_objects = BTreeMap::new();
        for (key, value) in &self.encrypted_objects {
            encrypted_objects.insert(key.to_string(), value);
        }
        if !encrypted_objects.is_empty() {
            state.serialize_field(SER_FIELD_ENCRYPTED_OBJECT_INFOS, &encrypted_objects)?;
        }
        state.end()
    }
}

#[derive(Debug)]
pub(crate) struct SegmentInfo {
    pub header: SegmentHeader,
    pub footer: SegmentFooter,
    pub chunkmaps: BTreeMap<u64, ChunkMaps>, // <object_number, chunkmaps>
}

impl Serialize for SegmentInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        debug!("Serialize segment {}", self.header.segment_number);
        let mut state = serializer.serialize_struct(
            SER_STRUCT_SEGMENT_INFO,
            5 + usize::from(!self.chunkmaps.is_empty()),
        )?;
        // the hex representation of the unique identifier is used to avoid problems with the
        // serialization of big u64 values (as toml only allows signed integer values).
        state.serialize_field(
            SER_FIELD_UNIQUE_IDENTIFIER,
            &hex::encode(self.header.unique_identifier.to_le_bytes()),
        )?;
        state.serialize_field(SER_FIELD_SEGMENT_NUMBER, &self.header.segment_number)?;
        state.serialize_field(
            SER_FIELD_CHUNKMAP_SIZE,
            &format!(
                "{} ({})",
                self.header.chunkmap_size.bytes_as_hrb(),
                self.header.chunkmap_size
            ),
        )?;
        state.serialize_field(SER_FIELD_LENGTH_OF_SEGMENT, &self.footer.length_of_segment)?;
        state.serialize_field(
            SER_FIELD_FIRST_CHUNK_NUMBER,
            &self.footer.first_chunk_number,
        )?;
        let mut chunkmaps = BTreeMap::new();
        for (key, value) in &self.chunkmaps {
            chunkmaps.insert(key.to_string(), value);
        }
        if !chunkmaps.is_empty() {
            state.serialize_field(SER_FIELD_CHUNKMAPS, &chunkmaps)?;
        }
        state.end()
    }
}

fn timestamp_to_datetime_formatted(timestamp: u64) -> String {
    //unwrap should be safe here, because the format string was tested.
    let format = format_description::parse_borrowed::<2>(DEFAULT_DATE_FORMAT).unwrap();

    match OffsetDateTime::from_unix_timestamp(timestamp as i64) {
        Ok(dt) => match dt.format(&format) {
            Ok(formatted_dt) => formatted_dt,
            Err(e) => {
                warn!("An error occurred while trying to format given timestamp to date: {timestamp}.");
                debug!("{e}");
                timestamp.to_string()
            }
        },
        Err(e) => {
            warn!("An error occurred while trying to format given timestamp to date: {timestamp}.");
            debug!("{e}");
            timestamp.to_string()
        }
    }
}

fn get_extended_metadata_values_to_human_readable(
    key: &str,
    value: &MetadataExtendedValue,
) -> MetadataExtendedValue {
    if key == METADATA_ATIME
        || key == METADATA_BTIME
        || key == METADATA_CTIME
        || key == METADATA_MTIME
    {
        if let Some(inner_value) = value.as_any().downcast_ref::<u64>() {
            MetadataExtendedValue::String(timestamp_to_datetime_formatted(*inner_value))
        } else {
            value.clone()
        }
    } else {
        value.clone()
    }
}
