use std::collections::HashMap;
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;
use tempfile::TempDir;
use zff::header::*;
use zff::io::{
    zffwriter::{SegmentationState, ZffFilesOutput, ZffWriter},
    ZffCreationParameters,
};
use zff::{
    CompressionAlgorithm, HashType, HeaderCoding, LogicalObjectSource,
    LogicalObjectSourceFilesystem, Signature,
};
use zff::{KDFScheme, PBEScheme};

struct Fixture {
    _dir: TempDir,
    paths: Vec<PathBuf>,
    key: String,
}

fn fixture(
    encrypted: bool,
    signed: bool,
    logical: bool,
    segmented: bool,
    compression: CompressionAlgorithm,
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let data = b"forensic evidence with varied bytes 0123456789".repeat(150);
    let mut header = ObjectHeader::new(
        1,
        None,
        128,
        CompressionHeader::new(compression, 3, 1.05),
        DescriptionHeader::new_empty(),
        if logical {
            ObjectType::Logical
        } else {
            ObjectType::Physical
        },
        ObjectFlags::default(),
    );
    header.flags.sign_hash = signed;
    if encrypted {
        use zff::{
            encrypt_argon2_aes256cbc, gen_random_iv, gen_random_key, gen_random_salt,
            EncryptionAlgorithm,
        };
        let key = gen_random_key(256);
        let salt = gen_random_salt();
        let nonce = gen_random_iv();
        let wrapped = encrypt_argon2_aes256cbc(8, 1, 1, &salt, &nonce, "password", &key).unwrap();
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
    // Fixed public key for the test signing seed (base64 conversion supplied by serde is unnecessary).
    let key = base64_key(&signing.verifying_key().to_bytes());
    let mut physical = HashMap::new();
    let mut logical_objects: HashMap<ObjectHeader, Box<dyn LogicalObjectSource>> = HashMap::new();
    if logical {
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file.txt"), &data).unwrap();
        fs::write(source.join("empty.txt"), []).unwrap();
        fs::write(source.join("same.bin"), vec![0u8; 256]).unwrap();
        logical_objects.insert(
            header,
            Box::new(LogicalObjectSourceFilesystem::new(vec![source]).unwrap()),
        );
    } else {
        physical.insert(header, Cursor::new(data));
    }
    let params = ZffCreationParameters {
        signature_key: signed.then_some(signing),
        target_segment_size: segmented.then_some(2500),
        description_notes: None,
        chunkmap_size: None,
        deduplication_metadata: Some(DeduplicationMetadata {
            deduplication_map: DeduplicationChunkMap::new_in_memory_map(),
            original_zffreader: None,
        }),
        unique_identifier: 42,
    };
    let mut writer: ZffWriter<Cursor<Vec<u8>>, Mutex<Cursor<Vec<u8>>>> = ZffWriter::new(
        physical,
        logical_objects,
        HashMap::new(),
        vec![HashType::Blake3, HashType::SHA256],
        params,
        ZffFilesOutput::Stream,
    )
    .unwrap();
    let mut paths = Vec::new();
    loop {
        let mut bytes = Vec::new();
        writer.read_to_end(&mut bytes).unwrap();
        let path = dir
            .path()
            .join(format!("image with spaces.z{:02}", paths.len() + 1));
        fs::write(&path, bytes).unwrap();
        paths.push(path);
        match writer.next_segment() {
            SegmentationState::LastSegmentFinished => break,
            SegmentationState::SegmentFinished => (),
            _ => panic!("Unexpected segmentation state"),
        }
    }
    Fixture {
        _dir: dir,
        paths,
        key,
    }
}

fn base64_key(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn cli(paths: &[PathBuf], args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zffanalyze"))
        .arg("-i")
        .args(paths)
        .args(args)
        .output()
        .unwrap()
}
fn success(output: Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn failure(output: Output, message: &str) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(message),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn physical_formats_and_integrity() {
    for compression in [
        CompressionAlgorithm::None,
        CompressionAlgorithm::Zstd,
        CompressionAlgorithm::Lz4,
    ] {
        let f = fixture(false, false, false, false, compression);
        success(cli(&f.paths, &["-c"]));
        for verbosity in ["-v", "-vv"] {
            let json = success(cli(&f.paths, &["-f", "json", verbosity]));
            let value: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_eq!(value["object"]["1"]["object_number"], 1);
            let toml = success(cli(&f.paths, &[verbosity]));
            toml::from_str::<toml::Value>(&toml).unwrap();
        }
        serde_json::from_str::<serde_json::Value>(&success(cli(&f.paths, &["-f", "json-pretty"])))
            .unwrap();
    }
}

#[test]
fn encrypted_metadata_and_verification() {
    for logical in [false, true] {
        let f = fixture(true, true, logical, logical, CompressionAlgorithm::Zstd);
        let json = success(cli(&f.paths, &["-I", "-vv", "-f", "json"]));
        assert!(serde_json::from_str::<serde_json::Value>(&json)
            .unwrap()
            .get("encrypted_object")
            .is_some());
        failure(
            cli(&f.paths, &["-I", "-c"]),
            "encrypted objects require passwords",
        );
        failure(
            cli(&f.paths, &["-p", "1:wrong", "-c"]),
            "Cannot decrypt object",
        );
        success(cli(&f.paths, &["-p", "1:password", "-c", "-k", &f.key]));
        success(cli(&f.paths, &["-p", "1:password", "-vv"]));
    }
}

#[test]
fn logical_files_including_empty_and_samebytes() {
    let f = fixture(false, true, true, false, CompressionAlgorithm::None);
    success(cli(&f.paths, &["-c", "-k", &f.key]));
    let json = success(cli(&f.paths, &["-vv", "-f", "json"]));
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["object"]["1"]["total_number_of_files"], 4);
    assert_eq!(value["object"]["1"]["file"].as_object().unwrap().len(), 4);
}

#[test]
fn signatures_fail_closed_and_check_data() {
    let f = fixture(false, true, false, false, CompressionAlgorithm::None);
    success(cli(&f.paths, &["-k", &f.key]));
    let other = Signature::new_signing_key();
    failure(
        cli(
            &f.paths,
            &["-k", &base64_key(&other.verifying_key().to_bytes())],
        ),
        "Invalid",
    );
    failure(cli(&f.paths, &["-k", "not base64"]), "");
    corrupt_payload(&f.paths[0]);
    failure(cli(&f.paths, &["-k", &f.key]), "mismatch");
    failure(cli(&f.paths, &["-c"]), "mismatch");
    let unsigned = fixture(false, false, false, false, CompressionAlgorithm::None);
    failure(cli(&unsigned.paths, &["-k", &f.key]), "missing");
}

fn corrupt_payload(path: &Path) {
    let mut bytes = fs::read(path).unwrap();
    let needle = b"forensic evidence with varied bytes";
    let offset = bytes
        .windows(needle.len())
        .position(|s| s == needle)
        .unwrap();
    bytes[offset] ^= 1;
    fs::write(path, bytes).unwrap();
}

#[test]
fn segments_must_be_complete_unique_and_related() {
    let f = fixture(false, false, false, true, CompressionAlgorithm::None);
    assert!(f.paths.len() > 1);
    let mut reversed = f.paths.clone();
    reversed.reverse();
    success(cli(&reversed, &["-c"]));
    failure(cli(&f.paths[1..], &["-c"]), "Missing segments");
    failure(
        cli(&f.paths[..f.paths.len() - 1], &["-c"]),
        "Missing main footer",
    );
    let mut duplicate = f.paths.clone();
    duplicate.push(f.paths[0].clone());
    failure(cli(&duplicate, &[]), "duplicate segment");
    let mut bytes = fs::read(&f.paths[1]).unwrap();
    let mut cursor = Cursor::new(&bytes);
    let mut header = SegmentHeader::decode_directly(&mut cursor).unwrap();
    header.unique_identifier += 1;
    let encoded = header.encode_directly();
    bytes[..encoded.len()].copy_from_slice(&encoded);
    fs::write(&f.paths[1], bytes).unwrap();
    failure(cli(&f.paths, &[]), "different containers");
}

#[test]
fn truncated_input_is_an_error() {
    let f = fixture(false, false, false, false, CompressionAlgorithm::None);
    fs::write(&f.paths[0], b"invalid").unwrap();
    failure(cli(&f.paths, &[]), "");
}

fn rewrite_object_footer(f: &Fixture, mutate: impl FnOnce(&mut zff::footer::ObjectFooter)) {
    use std::io::{Seek, SeekFrom};
    let mut bytes = fs::read(&f.paths[0]).unwrap();
    let mut cursor = Cursor::new(&bytes);
    cursor.seek(SeekFrom::End(-8)).unwrap();
    let main_offset = <u64 as zff::ValueDecoder>::decode_directly(&mut cursor).unwrap();
    cursor.set_position(main_offset - 8);
    let segment_offset = <u64 as zff::ValueDecoder>::decode_directly(&mut cursor).unwrap();
    cursor.set_position(segment_offset);
    let segment = zff::footer::SegmentFooter::decode_directly(&mut cursor).unwrap();
    let offset = segment.object_footer_offsets[&1];
    cursor.set_position(offset);
    let mut footer = zff::footer::ObjectFooter::decode_directly(&mut cursor).unwrap();
    let old_len = cursor.position() - offset;
    mutate(&mut footer);
    let encoded = match footer {
        zff::footer::ObjectFooter::Physical(f) => f.encode_directly(),
        zff::footer::ObjectFooter::Logical(f) => f.encode_directly(),
        zff::footer::ObjectFooter::Virtual(f) => f.encode_directly(),
    };
    assert!(encoded.len() as u64 <= old_len);
    bytes[offset as usize..offset as usize + encoded.len()].copy_from_slice(&encoded);
    fs::write(&f.paths[0], bytes).unwrap();
}

#[test]
fn data_hashes_and_signatures_are_independently_checked() {
    let f = fixture(false, true, false, false, CompressionAlgorithm::None);
    rewrite_object_footer(&f, |footer| {
        let zff::footer::ObjectFooter::Physical(footer) = footer else {
            panic!()
        };
        footer.hash_header.hashes[0].hash[0] ^= 1;
    });
    failure(cli(&f.paths, &["-c"]), "data hash mismatch");
    let f = fixture(false, true, false, false, CompressionAlgorithm::None);
    rewrite_object_footer(&f, |footer| {
        let zff::footer::ObjectFooter::Physical(footer) = footer else {
            panic!()
        };
        footer.hash_header.hashes[0]
            .ed25519_signature
            .as_mut()
            .unwrap()[0] ^= 1;
    });
    success(cli(&f.paths, &["-c"]));
    failure(cli(&f.paths, &["-k", &f.key]), "Invalid");
    let f = fixture(false, true, false, false, CompressionAlgorithm::None);
    rewrite_object_footer(&f, |footer| {
        let zff::footer::ObjectFooter::Physical(footer) = footer else {
            panic!()
        };
        footer.hash_header.hashes.clear();
    });
    failure(cli(&f.paths, &["-c"]), "no stored data hash");
    failure(cli(&f.paths, &["-k", &f.key]), "no stored data hash");
}

#[test]
fn missing_logical_metadata_cannot_be_skipped() {
    let f = fixture(false, false, true, false, CompressionAlgorithm::None);
    rewrite_object_footer(&f, |footer| {
        let zff::footer::ObjectFooter::Logical(footer) = footer else {
            panic!()
        };
        footer.file_footer_offsets.remove(&2);
    });
    failure(cli(&f.paths, &["-c"]), "indexes disagree");
    failure(cli(&f.paths, &["-vv"]), "indexes disagree");
}

#[test]
fn decrypted_keys_are_not_output_and_password_keys_are_validated() {
    let f = fixture(true, false, false, false, CompressionAlgorithm::None);
    let output = success(cli(&f.paths, &["-p", "1:password", "-f", "json"]));
    let value: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert!(value["object"]["1"]["encryption_header"]["decrypted_encryption_key"].is_null());
    failure(
        cli(&f.paths, &["-p", "2:password"]),
        "Unknown object number",
    );
    failure(
        cli(&f.paths, &["-p", "1:password", "-p", "1:password"]),
        "Multiple passwords",
    );
}

fn rewrite_first_chunk(f: &Fixture, mutate: impl FnOnce(&mut ChunkHeader)) {
    let mut bytes = fs::read(&f.paths[0]).unwrap();
    let main_offset = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
    let segment_offset = u64::from_le_bytes(
        bytes[main_offset as usize - 8..main_offset as usize]
            .try_into()
            .unwrap(),
    );
    let mut cursor = Cursor::new(&bytes);
    cursor.set_position(segment_offset);
    let segment = zff::footer::SegmentFooter::decode_directly(&mut cursor).unwrap();
    let offset = *segment.chunk_header_map_table.values().next().unwrap();
    cursor.set_position(offset);
    let mut map = ChunkHeaderMap::decode_directly(&mut cursor).unwrap();
    let object = map.object_number();
    let mut entries = map.flush();
    mutate(entries.first_entry().unwrap().get_mut());
    let encoded = ChunkHeaderMap::new(object, entries).encode_directly();
    bytes[offset as usize..offset as usize + encoded.len()].copy_from_slice(&encoded);
    fs::write(&f.paths[0], bytes).unwrap();
}

#[test]
fn recorded_chunk_checksums_and_acquisition_errors_are_checked() {
    let f = fixture(false, false, false, false, CompressionAlgorithm::None);
    rewrite_first_chunk(&f, |header| header.integrity_hash ^= 1);
    failure(cli(&f.paths, &["-c"]), "Integrity mismatch");
    let f = fixture(false, false, false, false, CompressionAlgorithm::None);
    rewrite_first_chunk(&f, |header| header.flags.error = true);
    failure(cli(&f.paths, &["-c"]), "acquisition error");
}
