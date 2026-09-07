use crate::*;
use zff::header::{ChunkDeduplicationMap, ChunkHeaderMap, ChunkMap, ChunkSamebytesMap};

pub(crate) fn read_container(
    paths: &[PathBuf],
    args: &Cli,
    passwords: &mut BTreeMap<u64, String>,
) -> Result<(ContainerInfo, BTreeMap<u64, File>)> {
    let mut segments = BTreeMap::new();
    let mut readers = BTreeMap::new();
    let mut main_footer = None;
    let mut identifier = None;
    for path in paths {
        let mut file = File::open(path)?;
        let header = SegmentHeader::decode_directly(&mut file)?;
        let number = header.segment_number;
        if number == 0 || segments.contains_key(&number) {
            return Err(invalid(format!(
                "Invalid or duplicate segment number {number}"
            )));
        }
        if identifier.is_some_and(|id| id != header.unique_identifier) {
            return Err(invalid("Input segments belong to different containers"));
        }
        identifier = Some(header.unique_identifier);
        let footer = match try_find_footer(&mut file)? {
            Footer::Segment(footer) => footer,
            Footer::MainAndSegment((main, footer)) => {
                if main_footer.is_some() || main.number_of_segments != number {
                    return Err(invalid("Duplicate or misplaced main footer"));
                }
                main_footer = Some(main);
                footer
            }
        };
        if footer.length_of_segment != file.metadata()?.len() {
            return Err(invalid(format!(
                "Segment {number} length does not match its footer"
            )));
        }
        segments.insert(
            number,
            SegmentInfo {
                header,
                footer,
                chunkmaps: BTreeMap::new(),
            },
        );
        readers.insert(number, file);
    }
    let main = main_footer
        .as_ref()
        .ok_or_else(|| invalid("Missing main footer: supply all segments"))?;
    if main.number_of_segments != segments.len() as u64
        || segments.keys().copied().ne(1..=main.number_of_segments)
    {
        return Err(invalid(
            "Missing segments: supply every segment of the container",
        ));
    }
    for (global, kind) in [
        (&main.chunk_header_maps, 0),
        (&main.chunk_samebytes_maps, 1),
        (&main.chunk_dedup_maps, 2),
    ] {
        let mut expected = BTreeMap::new();
        for (number, segment) in &segments {
            let table = match kind {
                0 => &segment.footer.chunk_header_map_table,
                1 => &segment.footer.chunk_samebytes_map_table,
                _ => &segment.footer.chunk_dedup_map_table,
            };
            for chunk in table.keys() {
                if expected.insert(*chunk, *number).is_some() {
                    return Err(invalid("Duplicate chunk map index"));
                }
            }
        }
        if global != &expected {
            return Err(invalid("Main and segment chunk map indexes disagree"));
        }
    }
    let mut headers = BTreeMap::new();
    let mut footers = BTreeMap::new();
    for (number, segment) in &segments {
        for (object, offset) in &segment.footer.object_header_offsets {
            if headers.insert(*object, (*number, *offset)).is_some() {
                return Err(invalid(format!("Duplicate header for object {object}")));
            }
        }
        for (object, offset) in &segment.footer.object_footer_offsets {
            if footers.insert(*object, (*number, *offset)).is_some() {
                return Err(invalid(format!("Duplicate footer for object {object}")));
            }
        }
    }
    if headers.keys().ne(footers.keys())
        || headers.keys().ne(main.object_header.keys())
        || headers.keys().ne(main.object_footer.keys())
    {
        return Err(invalid("Object header/footer indexes disagree"));
    }
    for (key, _) in &args.decryption_passwords {
        let number = key
            .parse::<u64>()
            .map_err(|_| invalid("Password keys must be object numbers"))?;
        if key != &number.to_string() || !headers.contains_key(&number) {
            return Err(invalid(format!(
                "Unknown object number in password option: {key}"
            )));
        }
    }
    let mut objects = BTreeMap::new();
    let mut encrypted_objects = BTreeMap::new();
    for (number, (segment, offset)) in headers {
        let (footer_segment, footer_offset) = footers[&number];
        if main.object_header[&number] != segment || main.object_footer[&number] != footer_segment {
            return Err(invalid(format!(
                "Conflicting segment indexes for object {number}"
            )));
        }
        let reader = readers
            .get_mut(&segment)
            .ok_or_else(|| invalid("Missing header segment"))?;
        reader.seek(SeekFrom::Start(offset))?;
        let header = match ObjectHeader::decode_directly(reader) {
            Ok(header) => header,
            Err(e) if matches!(e.kind(), ZffErrorKind::EncryptionError) => {
                reader.seek(SeekFrom::Start(offset))?;
                let mut encrypted = EncryptedObjectHeader::decode_directly(reader)?;
                if encrypted.object_number != number {
                    return Err(invalid("Encrypted object number does not match its index"));
                }

                if let Some(password) = password(args, number)? {
                    let header = encrypted
                        .decrypt_with_password(&password)
                        .map_err(|e| invalid(format!("Cannot decrypt object {number}: {e}")))?;
                    passwords.insert(number, password);
                    header
                } else {
                    let reader = readers
                        .get_mut(&footer_segment)
                        .ok_or_else(|| invalid("Missing footer segment"))?;
                    reader.seek(SeekFrom::Start(footer_offset))?;
                    let footer = EncryptedObjectFooter::decode_directly(reader)?;
                    let footer_number = match &footer {
                        EncryptedObjectFooter::Physical(f) => f.object_number,
                        EncryptedObjectFooter::Logical(f) => f.object_number,
                        EncryptedObjectFooter::Virtual(f) => f.object_number,
                    };
                    if footer_number != number {
                        return Err(invalid("Encrypted footer number does not match its index"));
                    }

                    encrypted_objects.insert(
                        number,
                        EncryptedObjectInfo {
                            header: encrypted,
                            footer,
                        },
                    );
                    continue;
                }
            }
            Err(e) => return Err(e),
        };
        if header.object_number != number {
            return Err(invalid("Object header number does not match its index"));
        }
        let reader = readers
            .get_mut(&footer_segment)
            .ok_or_else(|| invalid("Missing footer segment"))?;
        reader.seek(SeekFrom::Start(footer_offset))?;
        let footer = if header.encryption_header.is_some() {
            let enc = EncryptionInformation::try_from(&header)?;
            EncryptedObjectFooter::decode_directly(reader)?
                .decrypt(&enc.encryption_key, &enc.algorithm)?
        } else {
            ObjectFooter::decode_directly(reader)?
        };
        if footer.object_number() != number {
            return Err(invalid("Object footer number does not match its index"));
        }
        use zff::header::ObjectType;
        if !matches!(
            (&header.object_type, &footer),
            (ObjectType::Physical, ObjectFooter::Physical(_))
                | (ObjectType::Logical, ObjectFooter::Logical(_))
                | (ObjectType::Virtual, ObjectFooter::Virtual(_))
        ) {
            return Err(invalid("Object header and footer types disagree"));
        }
        let mut object = ObjectInfo {
            header,
            footer,
            files: None,
        };
        // Validate logical metadata even when it will not be displayed.
        read_files(&mut object, &mut readers)?;
        objects.insert(number, object);
    }
    let mut container = ContainerInfo {
        main_footer,
        segments,
        objects,
        encrypted_objects,
    };
    // Decode only after passwords and object metadata are available.
    for (segment_number, segment) in &mut container.segments {
        let reader = readers
            .get_mut(segment_number)
            .ok_or_else(|| invalid("Missing segment"))?;
        let headers = read_maps::<ChunkHeaderMap>(
            reader,
            &segment.footer.chunk_header_map_table,
            &container.objects,
            &container.encrypted_objects,
        )?;
        let same = read_maps::<ChunkSamebytesMap>(
            reader,
            &segment.footer.chunk_samebytes_map_table,
            &container.objects,
            &container.encrypted_objects,
        )?;
        let dedup = read_maps::<ChunkDeduplicationMap>(
            reader,
            &segment.footer.chunk_dedup_map_table,
            &container.objects,
            &container.encrypted_objects,
        )?;
        for (number, map) in headers {
            segment.chunkmaps.entry(number).or_default().header_map = map;
        }
        for (number, map) in same {
            segment.chunkmaps.entry(number).or_default().same_bytes_map = map;
        }
        for (number, map) in dedup {
            segment
                .chunkmaps
                .entry(number)
                .or_default()
                .duplicate_chunks = map;
        }
    }
    if args.verbose < 2 && !args.check_integrity && args.public_key.is_none() {
        for object in container.objects.values_mut() {
            object.files = None;
        }
    }
    Ok((container, readers))
}

fn read_maps<M: ChunkMap + HeaderCoding<Item = M>>(
    reader: &mut File,
    table: &BTreeMap<u64, u64>,
    objects: &BTreeMap<u64, ObjectInfo>,
    encrypted: &BTreeMap<u64, EncryptedObjectInfo>,
) -> Result<BTreeMap<u64, M>> {
    let mut maps: BTreeMap<u64, M> = BTreeMap::new();
    for (last_chunk, offset) in table {
        reader.seek(SeekFrom::Start(*offset))?;
        let number = M::inner_structure_data(reader)?.object_number;
        if encrypted.contains_key(&number) {
            continue;
        }
        let object = objects
            .get(&number)
            .ok_or_else(|| invalid("Chunk map references an unknown object"))?;
        reader.seek(SeekFrom::Start(*offset))?;
        let map = if object.header.encryption_header.is_some() {
            let enc = EncryptionInformation::try_from(&object.header)?;
            M::decrypt_and_decode(&enc.encryption_key, &enc.algorithm, reader, *last_chunk)?
        } else {
            M::decode_directly(reader)?
        };
        if map.object_number() != number || map.chunkmap().keys().any(|n| *n == 0 || n > last_chunk)
        {
            return Err(invalid("Chunk map has invalid object or chunk numbers"));
        }
        if let Some(existing) = maps.get_mut(&number) {
            if map
                .chunkmap()
                .keys()
                .any(|n| existing.chunkmap().contains_key(n))
            {
                return Err(invalid("Duplicate chunk map entry"));
            }
            existing.append(map);
        } else {
            maps.insert(number, map);
        }
    }
    Ok(maps)
}

fn read_files(object: &mut ObjectInfo, readers: &mut BTreeMap<u64, File>) -> Result<()> {
    let ObjectFooter::Logical(footer) = &object.footer else {
        return Ok(());
    };
    if !same_keys(
        &footer.file_header_offsets,
        &footer.file_header_segment_numbers,
    ) || !same_keys(&footer.file_header_offsets, &footer.file_footer_offsets)
        || !same_keys(
            &footer.file_header_offsets,
            &footer.file_footer_segment_numbers,
        )
        || footer
            .root_dir_filenumbers
            .iter()
            .any(|n| !footer.file_header_offsets.contains_key(n))
    {
        return Err(invalid("Logical file header/footer indexes disagree"));
    }
    let enc = if object.header.encryption_header.is_some() {
        Some(EncryptionInformation::try_from(&object.header)?)
    } else {
        None
    };
    let mut files = BTreeMap::new();
    for (number, offset) in &footer.file_header_offsets {
        let reader = readers
            .get_mut(&footer.file_header_segment_numbers[number])
            .ok_or_else(|| invalid("Missing file header segment"))?;
        reader.seek(SeekFrom::Start(*offset))?;
        let header = match &enc {
            Some(enc) => FileHeader::decode_encrypted_header_with_key(reader, enc)?,
            None => FileHeader::decode_directly(reader)?,
        };
        let reader = readers
            .get_mut(&footer.file_footer_segment_numbers[number])
            .ok_or_else(|| invalid("Missing file footer segment"))?;
        reader.seek(SeekFrom::Start(footer.file_footer_offsets[number]))?;
        let file_footer = match &enc {
            Some(enc) => FileFooter::decode_encrypted_footer_with_key(reader, enc)?,
            None => FileFooter::decode_directly(reader)?,
        };
        if header.file_number != *number || file_footer.file_number != *number {
            return Err(invalid("File number does not match its index"));
        }
        files.insert(
            *number,
            FileInfo {
                header,
                footer: file_footer,
            },
        );
    }
    object.files = Some(files);
    Ok(())
}

fn same_keys(
    a: &std::collections::HashMap<u64, u64>,
    b: &std::collections::HashMap<u64, u64>,
) -> bool {
    a.len() == b.len() && a.keys().all(|key| b.contains_key(key))
}
