// - STD
use std::process::exit;
use std::path::PathBuf;
use std::error::Error;
use std::io::{Seek, SeekFrom, Read};

// - modules
pub mod constants;
pub mod traits;
mod serde;

// - re-exports
pub(crate) use self::serde::*;

// - internal
use crate::constants::*;
use zff::{
    Result,
    footer::{SegmentFooter, MainFooter},
    ZffError,
    ZffErrorKind,
    ValueDecoder,
    HeaderCoding,
};

// workaround to enable the correct construction of snap packages. Will be replaced by something more elegant in the future.
#[cfg(target_family = "unix")]
pub fn concat_prefix_path<P: Into<String>, S: Into<String>>(prefix: P, path: S) -> PathBuf {
    let mut new_path = PathBuf::from(prefix.into());
    let path = path.into();

    let canonicalized_path = match PathBuf::from(&path).canonicalize() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("{ERROR_CANONICALIZE_INPUT_FILE_}{path} - {e}");
            exit(EXIT_STATUS_ERROR);
        }
    };
    match canonicalized_path.strip_prefix(UNIX_BASE) {
        Ok(path) => {
            new_path.push(path);
            new_path
        },
        Err(e) => {
            eprintln!("{ERROR_STRIPPING_PREFIX_INPUT_FILE_}{path} - {e}");
            exit(EXIT_STATUS_ERROR);
        }
    }
}

#[cfg(target_family = "windows")]
pub fn concat_prefix_path<P: Into<String>, S: Into<String>>(prefix: P, path: S) -> PathBuf {
    PathBuf::from(path.into())
}

/// Parse a single key-value pair
pub(crate) fn parse_key_val<T, U>(s: &str) -> std::result::Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: std::str::FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find(':')
        .ok_or_else(|| format!("invalid KEY:value -> no `:` found in `{s}`"))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

pub(crate) enum Footer {
    Segment(SegmentFooter),
    MainAndSegment((MainFooter, SegmentFooter))
}

pub(crate) fn try_find_footer<R: Read + Seek>(reader: &mut R) -> Result<Footer> {
    let position = reader.stream_position()?;
    reader.seek(SeekFrom::End(-8))?; //seeks to the end to reads the last 8 bytes (footer offset)
    let mut footer_offset = u64::decode_directly(reader)?;
    reader.seek(SeekFrom::Start(footer_offset))?;
    if let Ok(segment_footer) = SegmentFooter::decode_directly(reader) {
        reader.seek(SeekFrom::Start(position))?;
        return Ok(Footer::Segment(segment_footer));
    }
    reader.seek(SeekFrom::Start(footer_offset))?;
    if let Ok(main_footer) = MainFooter::decode_directly(reader) {
        reader.seek(SeekFrom::Start(footer_offset))?;
        reader.seek(SeekFrom::Current(-8))?; //seeks to the footer offset of the segment footer
        footer_offset = u64::decode_directly(reader)?;
        reader.seek(SeekFrom::Start(footer_offset))?;
        if let Ok(segment_footer) = SegmentFooter::decode_directly(reader) {
            reader.seek(SeekFrom::Start(position))?;
            Ok(Footer::MainAndSegment((main_footer, segment_footer)))
        } else {
            reader.seek(SeekFrom::Start(position))?;
            Err(ZffError::new(ZffErrorKind::Invalid, ""))
        }
    } else {
        reader.seek(SeekFrom::Start(position))?;
        Err(ZffError::new(ZffErrorKind::Invalid, ""))
    }
}