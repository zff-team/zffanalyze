use crate::*;
use std::collections::BTreeSet;
use xxhash_rust::xxh3::Xxh3;
use zff::header::{ChunkHeader, ChunkMap, HashHeader};
use zff::io::zffreader::ZffReader;
use zff::{Hash, Signature};

pub(crate) fn verify(
    container: &ContainerInfo,
    files: BTreeMap<u64, File>,
    passwords: &BTreeMap<u64, String>,
    key: Option<&str>,
) -> Result<()> {
    if !container.encrypted_objects.is_empty() {
        return Err(invalid(
            "Verification incomplete: encrypted objects require passwords",
        ));
    }
    if container.objects.is_empty() {
        return Err(invalid("Verification incomplete: no objects to verify"));
    }
    let mut chunks = BTreeMap::new();
    for segment in container.segments.values() {
        for (object, maps) in &segment.chunkmaps {
            for (number, header) in maps.header_map.chunkmap() {
                if chunks.insert(*number, (*object, *header)).is_some() {
                    return Err(invalid(format!("Duplicate chunk {number}")));
                }
            }
        }
    }
    let main = container
        .main_footer
        .as_ref()
        .ok_or_else(|| invalid("Missing main footer"))?;
    let last = main
        .chunk_header_maps
        .last_key_value()
        .map_or(0, |(n, _)| *n);
    if chunks.len() as u64 != last || chunks.keys().copied().ne(1..=last) {
        return Err(invalid(
            "Verification incomplete: missing or unindexed chunks",
        ));
    }
    let mut reader = ZffReader::with_reader(files.into_values().collect())?;
    // Virtual content is read from validated source extents below. Only source
    // object readers are needed; this also avoids ordering-dependent virtual initialization.
    for (number, object) in &container.objects {
        if !matches!(object.footer, ObjectFooter::Virtual(_)) {
            reader.initialize_object(*number)?;
        }
    }
    for (number, password) in passwords {
        if !matches!(container.objects[number].footer, ObjectFooter::Virtual(_)) {
            reader.decrypt_object(*number, password)?;
        }
    }
    let mut checked = BTreeSet::new();
    let mut streams = 0;
    for (number, object) in &container.objects {
        info!("Checking object {number}");
        let mut verifier = StreamVerifier {
            reader: &reader,
            object: *number,
            chunk_size: object.header.chunk_size,
            chunks: &chunks,
            checked: &mut checked,
            key,
        };
        match &object.footer {
            ObjectFooter::Physical(footer) => {
                verifier.check(
                    0,
                    footer.first_chunk_number,
                    footer.number_of_chunks,
                    footer.length_of_data,
                    &footer.hash_header,
                )?;
                streams += 1;
            }
            ObjectFooter::Logical(_) => {
                let files = object
                    .files
                    .as_ref()
                    .ok_or_else(|| invalid("Verification incomplete: missing logical files"))?;
                if files.is_empty() {
                    return Err(invalid(
                        "Verification incomplete: logical object has no files or hashes",
                    ));
                }
                for (number, file) in files {
                    info!("Checking file {number}");
                    let footer = &file.footer;
                    verifier.check(
                        *number,
                        footer.first_chunk_number,
                        footer.number_of_chunks,
                        footer.length_of_data,
                        &footer.hash_header,
                    )?;
                    streams += 1;
                }
            }
            ObjectFooter::Virtual(_) => {
                streams += super::virtual_verify::verify_virtual(container, object, &reader, key)?;
            }
        }
    }
    if checked.len() != chunks.len() || streams == 0 {
        return Err(invalid(
            "Verification incomplete: unreferenced chunks or no data streams",
        ));
    }
    Ok(())
}

struct StreamVerifier<'a> {
    reader: &'a ZffReader<File>,
    object: u64,
    chunk_size: u64,
    chunks: &'a BTreeMap<u64, (u64, ChunkHeader)>,
    checked: &'a mut BTreeSet<u64>,
    key: Option<&'a str>,
}

impl StreamVerifier<'_> {
    fn check(
        &mut self,
        file: u64,
        first: u64,
        count: u64,
        length: u64,
        hashes: &HashHeader,
    ) -> Result<()> {
        if self.chunk_size == 0 || count != length.div_ceil(self.chunk_size) {
            return Err(invalid(format!("Data length {length} and chunk count {count} disagree (chunk size {}, first chunk {first})", self.chunk_size)));
        }
        if hashes.hashes.is_empty() {
            return Err(invalid("Verification incomplete: no stored data hash"));
        }
        let mut hashers: Vec<_> = hashes
            .hashes
            .iter()
            .map(|h| Hash::new_hasher(h.hash_type()))
            .collect();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut offset = 0;
        // zff 3 records an empty logical file as zero data chunks plus one placeholder.
        let entries = count.max(u64::from(length == 0 && file != 0));
        for index in 0..entries {
            let number = first
                .checked_add(index)
                .ok_or_else(|| invalid("Chunk number overflow"))?;
            let (owner, header) = self
                .chunks
                .get(&number)
                .ok_or_else(|| invalid(format!("Missing chunk {number}")))?;
            if *owner != self.object || !self.checked.insert(number) {
                return Err(invalid(format!("Conflicting ownership of chunk {number}")));
            }
            if length == 0 && file != 0 {
                if header.flags
                    != (zff::header::ChunkFlags {
                        empty_file: true,
                        ..Default::default()
                    })
                    || header.size != 0
                    || header.integrity_hash != 0
                {
                    return Err(invalid("Invalid empty-file placeholder"));
                }
                continue;
            }
            if header.flags.empty_file || header.flags.virtual_chunk || header.flags.error {
                return Err(invalid(format!(
                    "Chunk {number} records an acquisition error"
                )));
            }
            let mut remaining = self.chunk_size.min(length - offset);
            let mut checksum = Xxh3::new();
            while remaining > 0 {
                let size = remaining.min(buffer.len() as u64) as usize;
                let n = self
                    .reader
                    .read_at(&mut buffer[..size], self.object, file, offset)?;
                if n == 0 {
                    return Err(invalid(format!("Unexpected end of data in chunk {number}")));
                }
                checksum.update(&buffer[..n]);
                for hasher in &mut hashers {
                    hasher.update(&buffer[..n]);
                }
                remaining -= n as u64;
                offset += n as u64;
            }
            if checksum.digest() != header.integrity_hash {
                return Err(invalid(format!("Integrity mismatch in chunk {number}")));
            }
        }
        for (stored, hasher) in hashes.hashes.iter().zip(hashers) {
            check_hash(
                stored,
                hasher.finalize().as_ref(),
                self.key,
                self.object,
                file,
            )?;
        }
        Ok(())
    }
}

pub(crate) fn check_hash(
    stored: &zff::header::HashValue,
    actual: &[u8],
    key: Option<&str>,
    object: u64,
    file: u64,
) -> Result<()> {
    if actual != stored.hash().as_slice() {
        return Err(invalid(format!(
            "{} data hash mismatch for object {object}, file {file}",
            stored.hash_type()
        )));
    }
    if let Some(key) = key {
        let signature = stored.ed25519_signature().ok_or_else(|| {
            invalid(format!(
                "Verification incomplete: missing {} signature for object {object}, file {file}",
                stored.hash_type()
            ))
        })?;
        if !Signature::verify_with_base64_key(key, stored.hash(), signature)? {
            return Err(invalid(format!(
                "Invalid {} signature for object {object}, file {file}",
                stored.hash_type()
            )));
        }
    }
    Ok(())
}
