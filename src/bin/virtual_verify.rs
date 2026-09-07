use crate::*;
use std::collections::BTreeSet;
use zff::footer::{VirtualFileFooterContent as Content, VirtualFileMap};
use zff::header::FileType;
use zff::io::zffreader::ZffReader;
use zff::{Hash, ValueEncoder};

pub(crate) fn verify_virtual(
    container: &ContainerInfo,
    object: &ObjectInfo,
    reader: &ZffReader<File>,
    key: Option<&str>,
) -> Result<usize> {
    let ObjectFooter::Virtual(footer) = &object.footer else {
        return Err(invalid("Expected a virtual object"));
    };
    let files = object
        .virtual_files
        .as_ref()
        .ok_or_else(|| invalid("Missing virtual file metadata"))?;
    if files.is_empty() {
        return Err(invalid(
            "Verification incomplete: virtual object has no files or hashes",
        ));
    }
    validate_tree(files, &footer.root_dir_filenumbers)?;
    // zff 3.0.0 may leave this advisory list empty. Resolve every actual
    // dependency from the extents, regardless of whether it is listed here.
    let passive: BTreeSet<_> = footer.passive_objects.iter().copied().collect();
    if passive.len() != footer.passive_objects.len() {
        return Err(invalid("Duplicate passive object reference"));
    }
    for number in &passive {
        let source = container
            .objects
            .get(number)
            .ok_or_else(|| invalid("Missing virtual source object"))?;
        if matches!(source.footer, ObjectFooter::Virtual(_)) {
            return Err(invalid("Virtual-to-virtual mappings are not supported"));
        }
    }
    for (number, file) in files {
        info!("Checking virtual file {number}");
        let hashes = &file.footer.hash_header;
        if hashes.hashes.is_empty() {
            return Err(invalid(
                "Verification incomplete: no stored virtual file data hash",
            ));
        }
        let mut hashers: Vec<_> = hashes
            .hashes
            .iter()
            .map(|h| Hash::new_hasher(h.hash_type()))
            .collect();
        if let Content::FileMap(_, _) = &file.footer.vffc {
            let map = file
                .map
                .as_ref()
                .ok_or_else(|| invalid("Missing virtual file map"))?;
            validate_map(container, map, file.footer.length_of_data)?;
            let mut buffer = vec![0; 64 * 1024];
            for extent in map.extents.values() {
                let mut consumed = 0;
                while consumed < extent.length {
                    let size = (extent.length - consumed).min(buffer.len() as u64) as usize;
                    // validate_map checked the entire source range with checked arithmetic.
                    let n = reader.read_at(
                        &mut buffer[..size],
                        extent.source_object_number,
                        extent.source_filenumber,
                        extent.source_offset + consumed,
                    )?;
                    if n == 0 {
                        return Err(invalid("Unexpected end of virtual source data"));
                    }
                    for hasher in &mut hashers {
                        hasher.update(&buffer[..n]);
                    }
                    consumed += n as u64;
                }
            }
        } else {
            let bytes = inline_bytes(&file.footer.vffc)?;
            if bytes.len() as u64 != file.footer.length_of_data {
                return Err(invalid("Virtual inline content length mismatch"));
            }
            for hasher in &mut hashers {
                hasher.update(&bytes);
            }
        }
        for (stored, hasher) in hashes.hashes.iter().zip(hashers) {
            crate::verify::check_hash(
                stored,
                hasher.finalize().as_ref(),
                key,
                object.header.object_number,
                *number,
            )?;
        }
    }
    Ok(files.len())
}

fn validate_map(container: &ContainerInfo, map: &VirtualFileMap, length: u64) -> Result<()> {
    let mut end = 0;
    for (offset, extent) in &map.extents {
        if *offset != end || extent.length == 0 {
            return Err(invalid(
                "Virtual extents contain a gap, overlap, or zero length",
            ));
        }
        end = offset
            .checked_add(extent.length)
            .ok_or_else(|| invalid("Virtual extent overflow"))?;
        if end > length {
            return Err(invalid("Virtual extent exceeds file length"));
        }
        let source = container
            .objects
            .get(&extent.source_object_number)
            .ok_or_else(|| invalid("Missing virtual source object"))?;
        let source_length = match &source.footer {
            ObjectFooter::Physical(f) => f.length_of_data,
            ObjectFooter::Logical(_) => {
                source
                    .files
                    .as_ref()
                    .and_then(|files| files.get(&extent.source_filenumber))
                    .ok_or_else(|| invalid("Missing virtual source file"))?
                    .footer
                    .length_of_data
            }
            ObjectFooter::Virtual(_) => {
                return Err(invalid("Virtual-to-virtual mappings are not supported"))
            }
        };
        let source_end = extent
            .source_offset
            .checked_add(extent.length)
            .ok_or_else(|| invalid("Virtual source extent overflow"))?;
        if source_end > source_length {
            return Err(invalid("Virtual extent exceeds source length"));
        }
    }
    if end != length {
        return Err(invalid("Virtual extents do not cover the file length"));
    }
    Ok(())
}

// Hash the representation defined by zff's virtual source encoder. In particular,
// hardlinks hash the target file number, not the target's file contents.
fn inline_bytes(content: &Content) -> Result<Vec<u8>> {
    Ok(match content {
        Content::Directory(children) => children.encode_directly(),
        Content::Symlink(target) => target.encode_directly(),
        Content::Hardlink(target) => target.encode_directly(),
        Content::SpecialFile(device, kind) => {
            let mut bytes = device.encode_directly();
            bytes.extend_from_slice(&(*kind as u8).encode_directly());
            bytes
        }
        Content::FileMap(_, _) => return Err(invalid("Expected inline virtual content")),
    })
}

fn validate_tree(files: &BTreeMap<u64, VirtualFileInfo>, roots: &[u64]) -> Result<()> {
    let roots_set: BTreeSet<_> = roots.iter().copied().collect();
    let expected_roots: BTreeSet<_> = files
        .iter()
        .filter(|(_, f)| f.header.parent_file_number == 0)
        .map(|(n, _)| *n)
        .collect();
    if roots_set.len() != roots.len() || roots_set != expected_roots {
        return Err(invalid(
            "Virtual root file index disagrees with file headers",
        ));
    }
    // Index child membership once: scanning a large directory for every child
    // would make validation quadratic in the number of files.
    let listed_children: BTreeSet<_> = files
        .values()
        .filter_map(|f| {
            if let Content::Directory(children) = &f.footer.vffc {
                Some(children)
            } else {
                None
            }
        })
        .flatten()
        .copied()
        .collect();
    let mut checked_parents = BTreeSet::new();
    let mut checked_links = BTreeSet::new();
    for (number, file) in files {
        if !matches!(
            (&file.header.file_type, &file.footer.vffc),
            (FileType::File, Content::FileMap(_, _))
                | (FileType::Directory, Content::Directory(_))
                | (FileType::Symlink, Content::Symlink(_))
                | (FileType::Hardlink, Content::Hardlink(_))
                | (FileType::SpecialFile, Content::SpecialFile(_, _))
        ) {
            return Err(invalid("Virtual file type and footer content disagree"));
        }
        let mut seen = BTreeSet::new();
        let mut current = *number;
        while current != 0 && !checked_parents.contains(&current) {
            if !seen.insert(current) {
                return Err(invalid("Cycle in virtual directory hierarchy"));
            }
            let node = files
                .get(&current)
                .ok_or_else(|| invalid("Missing virtual parent file"))?;
            let parent = node.header.parent_file_number;
            if parent != 0 {
                let parent_file = files
                    .get(&parent)
                    .ok_or_else(|| invalid("Missing virtual parent file"))?;
                let Content::Directory(_) = &parent_file.footer.vffc else {
                    return Err(invalid("Virtual parent is not a directory"));
                };
                if !listed_children.contains(&current) {
                    return Err(invalid("Virtual directory is missing a child"));
                }
            }
            current = parent;
        }
        checked_parents.extend(seen);
        if let Content::Directory(children) = &file.footer.vffc {
            let unique: BTreeSet<_> = children.iter().collect();
            if unique.len() != children.len()
                || children.iter().any(|child| {
                    files
                        .get(child)
                        .is_none_or(|f| f.header.parent_file_number != *number)
                })
            {
                return Err(invalid("Invalid virtual directory children"));
            }
        }
        if let Content::Hardlink(_) = &file.footer.vffc {
            let mut current = *number;
            let mut seen = BTreeSet::new();
            loop {
                if checked_links.contains(&current) {
                    break;
                }
                if !seen.insert(current) {
                    return Err(invalid("Cycle in virtual hardlinks"));
                }
                let target = files
                    .get(&current)
                    .ok_or_else(|| invalid("Missing virtual hardlink target"))?;
                match target.footer.vffc {
                    Content::Hardlink(next) => current = next,
                    Content::FileMap(_, _) => break,
                    _ => return Err(invalid("Virtual hardlink target is not a regular file")),
                }
            }
            checked_links.extend(seen);
        }
    }
    Ok(())
}
