use crate::*;

#[test]
fn serialization_failure_is_propagated() {
    struct Failing;
    impl Serialize for Failing {
        fn serialize<S: serde::Serializer>(&self, _: S) -> std::result::Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom(
                "deliberate serialization failure",
            ))
        }
    }
    for format in ["toml", "json", "json-pretty"] {
        let args = Cli::try_parse_from(["zffanalyze", "-i", "unused", "-f", format]).unwrap();
        assert!(print_serialized_data(&args, &Failing, &mut Vec::new()).is_err());
    }
}

#[test]
fn output_write_failure_is_propagated() {
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("broken output"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let args = Cli::try_parse_from(["zffanalyze", "-i", "unused", "-f", "json"]).unwrap();
    assert!(print_serialized_data(&args, &42, &mut Broken).is_err());
}

#[test]
fn virtual_and_empty_containers_cannot_report_verification_success() {
    use zff::header::{CompressionHeader, DescriptionHeader, ObjectFlags, ObjectType};
    let mut container = ContainerInfo {
        main_footer: None,
        segments: BTreeMap::new(),
        objects: BTreeMap::new(),
        encrypted_objects: BTreeMap::new(),
    };
    assert!(
        verify::verify(&container, BTreeMap::new(), &BTreeMap::new(), None)
            .unwrap_err()
            .to_string()
            .contains("no objects")
    );
    let header = ObjectHeader::new(
        1,
        None,
        128,
        CompressionHeader::new(zff::CompressionAlgorithm::None, 0, 1.0),
        DescriptionHeader::new_empty(),
        ObjectType::Virtual,
        ObjectFlags::default(),
    );
    container.objects.insert(
        1,
        ObjectInfo {
            header,
            footer: ObjectFooter::Virtual(zff::footer::ObjectFooterVirtual::new_empty(1)),
            files: None,
        },
    );
    assert!(
        verify::verify(&container, BTreeMap::new(), &BTreeMap::new(), None)
            .unwrap_err()
            .to_string()
            .contains("virtual objects")
    );
    let args = Cli::try_parse_from(["zffanalyze", "-i", "unused"]).unwrap();
    let mut output = Vec::new();
    print_serialized_data(&args, &container, &mut output).unwrap();
    toml::from_str::<toml::Value>(std::str::from_utf8(&output).unwrap()).unwrap();
}
