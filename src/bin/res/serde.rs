// - internal
use crate::*;
use crate::res::traits::*;

// - external
use serde::ser::{Serialize, Serializer, SerializeStruct};
use time::{OffsetDateTime, format_description};

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
}

impl Serialize for ObjectInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        debug!("Serialize object {}", &self.header.object_number);
        let footer_value = match self.footer {
            ObjectFooter::Physical(_) => 8,
            _ => 3
        };
        let mut state = serializer.serialize_struct(SER_STRUCT_OBJECT_INFO, 7 + footer_value)?; // TODO: match the footer type to calculate the value
        state.serialize_field(SER_FIELD_OBJECT_NUMBER, &self.header.object_number)?;
        state.serialize_field(SER_FIELD_CHUNK_SIZE, &self.header.chunk_size)?;
        state.serialize_field(SER_FIELD_OBJECT_TYPE, &self.header.object_type)?;
        // check the object footer type and show the appropriate information
        match &self.footer {
            ObjectFooter::Physical(footer) => {
                state.serialize_field(SER_FIELD_ACQUISITION_START, &timestamp_to_datetime_formatted(footer.acquisition_start))?;
                state.serialize_field(SER_FIELD_ACQUISITION_END, &timestamp_to_datetime_formatted(footer.acquisition_end))?;
                state.serialize_field(SER_FIELD_SIZE_OF_DATA, &format!("{} ({})", 
                    footer.length_of_data.bytes_as_hrb(), footer.length_of_data))?;
                state.serialize_field(SER_FIELD_FIRST_CHUNK_NUMBER, &footer.first_chunk_number)?;
                state.serialize_field(SER_FIELD_NUMBER_OF_CHUNKS, &footer.number_of_chunks)?;
                state.serialize_field(SER_FIELD_HASH_HEADER, &footer.hash_header)?;
            },
            ObjectFooter::Logical(footer) => {
                state.serialize_field(SER_FIELD_ACQUISITION_START, &timestamp_to_datetime_formatted(footer.acquisition_start))?;
                state.serialize_field(SER_FIELD_ACQUISITION_END, &timestamp_to_datetime_formatted(footer.acquisition_end))?;
                state.serialize_field(SER_FIELD_NUMBER_OF_FILES, 
                    &(footer.root_dir_filenumbers.len() + footer.file_header_offsets.keys().len()))?;
            },
            ObjectFooter::Virtual(footer) => {
                state.serialize_field(SER_FIELD_CREATION_DATE, &timestamp_to_datetime_formatted(footer.creation_timestamp))?;
                state.serialize_field(SER_FIELD_SIZE_OF_DATA, &format!("{} ({})", 
                    footer.length_of_data.bytes_as_hrb(), footer.length_of_data))?;
                state.serialize_field(SER_FIELD_PASSIVE_OBJECTS, &footer.passive_objects)?;
            }
        }
        // ensure that all table containing elements are at the end of this serialization, see 
        // https://github.com/toml-rs/toml-rs/issues/142 for further information.
        state.serialize_field(SER_FIELD_OBJECT_FLAGS, &self.header.flags)?;
        state.serialize_field(SER_FIELD_ENCRYPTION_HEADER, &self.header.encryption_header)?;
        state.serialize_field(SER_FIELD_COMPRESSION_HEADER, &self.header.compression_header)?;
        state.serialize_field(SER_FIELD_DESCRIPTION_HEADER, &self.header.description_header)?;
        if let Some(files) = &self.files {
            let converted_map: BTreeMap<String, &FileInfo> = files
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect();
            state.serialize_field(SER_FIELD_FILE, &converted_map)?;
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
        debug!("Serialize file {}", &self.header.file_number);
        let mut state = serializer.serialize_struct(SER_STRUCT_FILE_INFO, 7)?;
        state.serialize_field(SER_FIELD_FILE_NUMBER, &self.header.file_number)?;
        state.serialize_field(SER_FIELD_FILE_NAME, &self.header.filename)?;
        state.serialize_field(SER_FIELD_PARENT_FILE_NUMBER, &self.header.parent_file_number)?;
        state.serialize_field(SER_FIELD_ACQUISITION_START, &self.footer.acquisition_start)?;
        state.serialize_field(SER_FIELD_ACQUISITION_END, &self.footer.acquisition_end)?;
        state.serialize_field(SER_FIELD_FIRST_CHUNK_NUMBER, &self.footer.first_chunk_number)?;
        state.serialize_field(SER_FIELD_NUMBER_OF_CHUNKS, &self.footer.number_of_chunks)?;
        state.serialize_field(SER_FIELD_SIZE_OF_DATA, &format!("{} ({})", 
                    self.footer.length_of_data.bytes_as_hrb(), self.footer.length_of_data))?;
        // ensure that all table containing elements are at the end of this serialization, see 
        // https://github.com/toml-rs/toml-rs/issues/142 for further information.
        state.serialize_field(SER_FIELD_FILE_TYPE, &self.header.file_type)?;
        state.serialize_field(SER_FIELD_EXTENDED_METADATA, &self.header.metadata_ext)?;
        state.serialize_field(SER_FIELD_HASH_HEADER, &self.footer.hash_header)?;

        
        state.end()
    }
}

#[derive(Debug)]
pub(crate) struct ContainerInfo {
    pub main_footer: Option<MainFooter>,
    pub segments: BTreeMap<u64, SegmentInfo>,
    pub objects: BTreeMap<u64, ObjectInfo>,
}

impl Serialize for ContainerInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        debug!("Serialize container info");
        let mut state = serializer.serialize_struct(SER_STRUCT_CONTAINER_INFO, 3)?;
        if let Some(main_footer) = &self.main_footer {
            state.serialize_field(SER_FIELD_NUMBER_OF_SEGMENTS, &main_footer.number_of_segments)?;
            state.serialize_field(SER_FIELD_DESCRIPTION_NOTE, &main_footer.description_notes)?;
        }
        //segments
        let mut segments = BTreeMap::new();
        for (key, value) in &self.segments {
            segments.insert(key.to_string(), value);
        };
        state.serialize_field(SER_FIELD_SEGMENT_INFOS, &segments)?;
        // objects
        let mut objects = BTreeMap::new();
        for (key, value) in &self.objects {
            objects.insert(key.to_string(), value);
        };
        state.serialize_field(SER_FIELD_OBJECT_INFOS, &objects)?;
        state.end()
    }
}

#[derive(Debug)]
pub(crate) struct SegmentInfo {
    pub header: SegmentHeader,
    pub footer: SegmentFooter,
    pub chunkmaps: Vec<ChunkMap>
}

impl Serialize for SegmentInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        debug!("Serialize segment {}", &self.header.segment_number);
        let mut state = serializer.serialize_struct(SER_STRUCT_SEGMENT_INFO, 6)?;
        state.serialize_field(SER_FIELD_UNIQUE_IDENTIFIER, &self.header.unique_identifier)?;
        state.serialize_field(SER_FIELD_SEGMENT_NUMBER, &self.header.segment_number)?;
        state.serialize_field(SER_FIELD_CHUNKMAP_SIZE, &format!("{} ({})", 
                    self.header.chunkmap_size.bytes_as_hrb(), self.header.chunkmap_size))?;
        state.serialize_field(SER_FIELD_LENGTH_OF_SEGMENT, &self.footer.length_of_segment)?;
        state.serialize_field(SER_FIELD_FIRST_CHUNK_NUMBER, &self.footer.first_chunk_number)?;
        state.serialize_field(SER_NUMBER_OF_CHUNKMAPS, &self.footer.chunk_map_table.keys().len())?;
        if !self.chunkmaps.is_empty() {
            state.serialize_field(SER_FIELD_CHUNKMAP, &self.chunkmaps)?;
        }
        state.end()
    }
}


fn timestamp_to_datetime_formatted(timestamp: u64) -> String {
    //unwrap should be safe here, because the format string was tested.
    let format = format_description::parse(DEFAULT_DATE_FORMAT).unwrap();

    match OffsetDateTime::from_unix_timestamp(timestamp as i64) {
        Ok(dt) => match dt.format(&format) {
            Ok(formatted_dt) => return formatted_dt,
            Err(e) => {
                warn!("An error occurred while trying to format given timestamp to date: {timestamp}.");
                debug!("{e}");
                return timestamp.to_string();
            }
        },
        Err(e) => {
            warn!("An error occurred while trying to format given timestamp to date: {timestamp}.");
            debug!("{e}");
            return timestamp.to_string();
        }
    }
}