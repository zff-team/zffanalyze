use super::*;
use std::collections::{BTreeMap, VecDeque};
use zff::footer::{VirtualFileExtent, VirtualFileMap};
use zff::{
    Hash, ValueEncoder, VirtualFileContent as Content, VirtualFileFooterMetadata,
    VirtualObjectSource,
};

struct Source {
    entries: VecDeque<(FileHeader, VirtualFileFooterMetadata)>,
    roots: Vec<u64>,
}
impl Iterator for Source {
    type Item = zff::Result<(FileHeader, VirtualFileFooterMetadata)>;
    fn next(&mut self) -> Option<Self::Item> {
        self.entries.pop_front().map(Ok)
    }
}
impl VirtualObjectSource for Source {
    fn remaining_elements(&self) -> u64 {
        self.entries.len() as u64
    }
    fn root_dir_filenumbers(&self) -> &Vec<u64> {
        &self.roots
    }
}

fn entry(
    number: u64,
    parent: u64,
    kind: FileType,
    content: Content,
    bytes: &[u8],
) -> (FileHeader, VirtualFileFooterMetadata) {
    let hashes = [HashType::Blake3, HashType::SHA256]
        .into_iter()
        .map(|kind| {
            let mut hash = Hash::new_hasher(&kind);
            hash.update(bytes);
            HashValue::new(kind, hash.finalize().to_vec(), None)
        })
        .collect();
    (
        FileHeader::new(
            number,
            kind,
            zff::PlatformString::from(std::ffi::OsString::from(format!("virtual-{number}"))),
            parent,
            HashMap::new(),
        ),
        VirtualFileFooterMetadata::new(HashHeader::new(hashes), bytes.len() as u64, content),
    )
}

fn source(source_file: u64) -> Source {
    let data = b"forensic evidence with varied bytes 0123456789".repeat(150);
    // Cross chunk boundaries, reuse a source range, and concatenate disjoint ranges.
    let extents = BTreeMap::from([
        (0, VirtualFileExtent::new(1, source_file, 37, 300)),
        (300, VirtualFileExtent::new(1, source_file, 37, 300)),
        (600, VirtualFileExtent::new(1, source_file, 500, 41)),
    ]);
    let bytes = [&data[37..337], &data[37..337], &data[500..541]].concat();
    let children = vec![2u64, 3, 4, 5, 6, 7];
    let target = zff::PlatformString::from(std::ffi::OsStr::new("virtual-2"));
    let mut special = 42u64.encode_directly();
    special.push(SpecialFileType::Fifo as u8);
    Source {
        roots: vec![1],
        entries: VecDeque::from([
            entry(
                1,
                0,
                FileType::Directory,
                Content::Directory(children.clone()),
                &children.encode_directly(),
            ),
            entry(
                2,
                1,
                FileType::File,
                Content::FileMap(VirtualFileMap::new(2, extents)),
                &bytes,
            ),
            entry(
                3,
                1,
                FileType::File,
                Content::FileMap(VirtualFileMap::new(3, BTreeMap::new())),
                &[],
            ),
            entry(
                4,
                1,
                FileType::Symlink,
                Content::Symlink(target.clone()),
                &target.encode_directly(),
            ),
            entry(
                5,
                1,
                FileType::Hardlink,
                Content::Hardlink(2),
                &2u64.encode_directly(),
            ),
            entry(
                6,
                1,
                FileType::SpecialFile,
                Content::SpecialFile(42, SpecialFileType::Fifo),
                &special,
            ),
            entry(
                7,
                1,
                FileType::Directory,
                Content::Directory(vec![]),
                &Vec::<u64>::new().encode_directly(),
            ),
        ]),
    }
}

fn virtual_fixture(encrypted: bool, logical: bool, mutate: impl FnOnce(&mut Source)) -> Fixture {
    let mut f = fixture(encrypted, true, logical, false, CompressionAlgorithm::Zstd);
    let source_file = if logical {
        let inputs = f
            .paths
            .iter()
            .map(fs::File::open)
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        let mut reader = zff::io::zffreader::ZffReader::with_reader(inputs).unwrap();
        reader.initialize_object(1).unwrap();
        if encrypted {
            reader.decrypt_object(1, "password").unwrap();
        }
        let zff::footer::ObjectFooter::Logical(footer) = reader.object_footer(1).unwrap() else {
            panic!()
        };
        *footer
            .file_header_offsets
            .keys()
            .find(|n| reader.filemetadata(1, **n).unwrap().length_of_data() > 1000)
            .unwrap()
    } else {
        0
    };
    let mut source = source(source_file);
    mutate(&mut source);
    let mut header = ObjectHeader::new(
        2,
        None,
        128,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
        DescriptionHeader::new_empty(),
        ObjectType::Virtual,
        ObjectFlags::default(),
    );
    header.flags.sign_hash = true;
    if encrypted {
        use zff::{
            encrypt_argon2_aes256cbc, gen_random_iv, gen_random_key, gen_random_salt,
            EncryptionAlgorithm,
        };
        let key = gen_random_key(256);
        let salt = gen_random_salt();
        let nonce = gen_random_iv();
        let wrapped =
            encrypt_argon2_aes256cbc(8, 1, 1, &salt, &nonce, "virtual-password", &key).unwrap();
        let pbe = PBEHeader::new(
            KDFScheme::Argon2id,
            PBEScheme::AES256CBC,
            KDFParameters::Argon2idParameters(Argon2idParameters::new(8, 1, 1, salt)),
            nonce,
        );
        let mut enc = EncryptionHeader::new(pbe, EncryptionAlgorithm::AES256GCM, wrapped);
        enc.decrypted_encryption_key = Some(key);
        header.encryption_header = Some(enc);
        header.flags.encryption = true;
    }
    let signing =
        Signature::new_signingkey_from_base64("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=")
            .unwrap();
    let params = ZffCreationParameters {
        signature_key: Some(signing),
        target_segment_size: Some(3000),
        description_notes: None,
        chunkmap_size: None,
        deduplication_metadata: None,
        unique_identifier: 42,
    };
    let virtual_objects: HashMap<ObjectHeader, Box<dyn VirtualObjectSource>> =
        HashMap::from([(header, Box::new(source) as Box<dyn VirtualObjectSource>)]);
    let mut writer: ZffWriter<Cursor<Vec<u8>>, Mutex<Cursor<Vec<u8>>>> = ZffWriter::new(
        HashMap::new(),
        HashMap::new(),
        virtual_objects,
        vec![HashType::Blake3],
        params,
        ZffFilesOutput::ExtendContainer(f.paths.clone()),
    )
    .unwrap();
    for path in writer.generate_files().unwrap() {
        if !f.paths.contains(&path) {
            f.paths.push(path);
        }
    }
    f
}

#[test]
fn virtual_files_and_inline_content_verify_and_serialize() {
    for logical in [false, true] {
        let f = virtual_fixture(false, logical, |_| {});
        success(cli(&f.paths, &["-c", "-k", &f.key]));
        for format in ["toml", "json", "json-pretty"] {
            let text = success(cli(&f.paths, &["-vv", "-f", format]));
            if format == "toml" {
                toml::from_str::<toml::Value>(&text).unwrap();
            } else {
                let json: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(json["object"]["2"]["file"].as_object().unwrap().len(), 7);
            }
        }
    }
}

#[test]
fn encrypted_virtual_files_require_both_passwords() {
    let f = virtual_fixture(true, true, |_| {});
    failure(
        cli(&f.paths, &["-I", "-p", "1:password", "-c"]),
        "encrypted objects require passwords",
    );
    failure(
        cli(&f.paths, &["-I", "-p", "2:virtual-password", "-c"]),
        "encrypted objects require passwords",
    );
    success(cli(
        &f.paths,
        &["-p", "1:password", "-p", "2:virtual-password", "-k", &f.key],
    ));
    success(cli(
        &f.paths,
        &["-p", "1:password", "-p", "2:virtual-password", "-vv"],
    ));
}

fn map(source: &mut Source) -> &mut VirtualFileMap {
    let Content::FileMap(map) = &mut source.entries[1].1.vfc else {
        panic!()
    };
    map
}

#[test]
fn altered_mapping_fails_even_with_intact_source_data() {
    let f = virtual_fixture(false, false, |s| {
        map(s).extents.get_mut(&0).unwrap().source_offset += 1;
    });
    failure(
        cli(&f.paths, &["-c"]),
        "data hash mismatch for object 2, file 2",
    );
    failure(cli(&f.paths, &["-k", &f.key]), "data hash mismatch");
}

#[test]
fn invalid_virtual_ranges_and_sources_are_rejected() {
    for case in 0..9 {
        let f = virtual_fixture(false, false, |s| {
            let map = map(s);
            match case {
                0 => {
                    let extent = map.extents.remove(&300).unwrap();
                    map.extents.insert(301, extent);
                }
                1 => {
                    let extent = map.extents.remove(&300).unwrap();
                    map.extents.insert(299, extent);
                }
                2 => map.extents.get_mut(&0).unwrap().length = 0,
                3 => map.extents.get_mut(&0).unwrap().source_offset = u64::MAX,
                4 => map.extents.get_mut(&0).unwrap().source_offset = 1_000_000,
                5 => map.extents.get_mut(&0).unwrap().source_object_number = 999,
                6 => map.extents.get_mut(&0).unwrap().source_object_number = 2,
                7 => map.extents.get_mut(&300).unwrap().length = u64::MAX,
                _ => {
                    map.extents.remove(&600);
                }
            }
        });
        let expected = [
            "gap, overlap, or zero length",
            "gap, overlap, or zero length",
            "gap, overlap, or zero length",
            "Virtual source extent overflow",
            "Virtual extent exceeds source length",
            "Missing virtual source object",
            "Virtual-to-virtual mappings",
            "Virtual extent overflow",
            "do not cover the file length",
        ];
        failure(cli(&f.paths, &["-c"]), expected[case]);
    }
    let f = virtual_fixture(false, true, |s| {
        map(s).extents.get_mut(&0).unwrap().source_filenumber = 999;
    });
    failure(cli(&f.paths, &["-c"]), "Missing virtual source file");
}

#[test]
fn virtual_hashes_inline_data_and_references_are_checked() {
    let f = virtual_fixture(false, false, |s| {
        s.entries[1].1.hash_header.hashes.clear();
    });
    failure(cli(&f.paths, &["-c"]), "no stored virtual file data hash");
    let f = virtual_fixture(false, false, |s| {
        s.entries[3].1.vfc =
            Content::Symlink(zff::PlatformString::from(std::ffi::OsStr::new("virtual-3")));
    });
    failure(cli(&f.paths, &["-c"]), "data hash mismatch");
    let f = virtual_fixture(false, false, |s| {
        s.entries[4].1.vfc = Content::Hardlink(999);
    });
    failure(cli(&f.paths, &["-c"]), "Missing virtual hardlink target");
    let f = virtual_fixture(false, false, |s| {
        s.entries[4].1.vfc = Content::Hardlink(5);
    });
    failure(cli(&f.paths, &["-c"]), "Cycle in virtual hardlinks");
}

fn virtual_footer_location(f: &Fixture, number: u64) -> (usize, u64) {
    let bytes = fs::read(f.paths.last().unwrap()).unwrap();
    let main_offset = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
    let mut cursor = Cursor::new(&bytes);
    cursor.set_position(main_offset);
    let main = zff::footer::MainFooter::decode_directly(&mut cursor).unwrap();
    let segment_index = main.object_footer[&2] as usize - 1;
    let bytes = fs::read(&f.paths[segment_index]).unwrap();
    let last_offset = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
    let segment_offset = if segment_index + 1 == main.number_of_segments as usize {
        u64::from_le_bytes(
            bytes[last_offset as usize - 8..last_offset as usize]
                .try_into()
                .unwrap(),
        )
    } else {
        last_offset
    };
    let mut cursor = Cursor::new(&bytes);
    cursor.set_position(segment_offset);
    let segment = zff::footer::SegmentFooter::decode_directly(&mut cursor).unwrap();
    cursor.set_position(segment.object_footer_offsets[&2]);
    let zff::footer::ObjectFooter::Virtual(footer) =
        zff::footer::ObjectFooter::decode_directly(&mut cursor).unwrap()
    else {
        panic!()
    };
    (
        footer.file_footer_segment_numbers[&number] as usize - 1,
        footer.file_footer_offsets[&number],
    )
}

fn rewrite_virtual_footer(f: &Fixture, mutate: impl FnOnce(&mut zff::footer::VirtualFileFooter)) {
    let (segment, offset) = virtual_footer_location(f, 2);
    let mut bytes = fs::read(&f.paths[segment]).unwrap();
    let mut cursor = Cursor::new(&bytes);
    cursor.set_position(offset);
    let mut footer = zff::footer::VirtualFileFooter::decode_directly(&mut cursor).unwrap();
    let old_length = cursor.position() - offset;
    mutate(&mut footer);
    let encoded = footer.encode_directly();
    assert!(encoded.len() as u64 <= old_length);
    bytes[offset as usize..offset as usize + encoded.len()].copy_from_slice(&encoded);
    fs::write(&f.paths[segment], bytes).unwrap();
}

#[test]
fn virtual_signatures_must_be_present_and_valid() {
    let f = virtual_fixture(false, false, |_| {});
    rewrite_virtual_footer(&f, |footer| {
        footer.hash_header.hashes[0]
            .ed25519_signature
            .as_mut()
            .unwrap()[0] ^= 1;
    });
    success(cli(&f.paths, &["-c"]));
    failure(cli(&f.paths, &["-k", &f.key]), "Invalid");
    let f = virtual_fixture(false, false, |_| {});
    rewrite_virtual_footer(&f, |footer| {
        footer.hash_header.hashes[0].ed25519_signature = None;
    });
    success(cli(&f.paths, &["-c"]));
    failure(cli(&f.paths, &["-k", &f.key]), "missing");
}

#[test]
fn missing_map_segment_and_mismatched_file_number_are_errors() {
    let f = virtual_fixture(false, false, |_| {});
    rewrite_virtual_footer(&f, |footer| {
        footer.vffc = zff::footer::VirtualFileFooterContent::FileMap(999, 0);
    });
    failure(cli(&f.paths, &["-c"]), "Missing virtual file map segment");
    let f = virtual_fixture(false, false, |_| {});
    rewrite_virtual_footer(&f, |footer| {
        footer.filenumber = 999;
    });
    failure(cli(&f.paths, &["-c"]), "Virtual file number");
}

#[test]
fn inline_lengths_and_directory_indexes_are_checked() {
    let f = virtual_fixture(false, false, |s| {
        s.entries[3].1.length_of_data += 1;
    });
    failure(
        cli(&f.paths, &["-c"]),
        "Virtual inline content length mismatch",
    );
    let f = virtual_fixture(false, false, |s| {
        s.entries[0].1.vfc = Content::Directory(vec![999]);
    });
    failure(cli(&f.paths, &["-c"]), "Invalid virtual directory children");
    let f = virtual_fixture(false, false, |s| {
        s.entries[1].0.file_type = FileType::Directory;
    });
    failure(cli(&f.paths, &["-c"]), "Virtual file type");
    let f = virtual_fixture(false, false, |s| {
        s.roots.push(999);
    });
    failure(
        cli(&f.paths, &["-c"]),
        "Virtual file header/footer indexes disagree",
    );
}

#[test]
fn directory_cycles_and_wrong_map_numbers_are_errors() {
    let f = virtual_fixture(false, false, |s| {
        s.roots.clear();
        s.entries[0].0.parent_file_number = 7;
        s.entries[6].1.vfc = Content::Directory(vec![1]);
    });
    failure(
        cli(&f.paths, &["-c"]),
        "Cycle in virtual directory hierarchy",
    );
    let f = virtual_fixture(false, false, |s| {
        map(s).filenumber = 999;
    });
    failure(cli(&f.paths, &["-c"]), "Virtual file map number");
}
