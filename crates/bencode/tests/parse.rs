//! Integration tests: these run against the public API only, exactly as the
//! `engine` crate will use it.

use bencode::{ErrorKind, Limits, Value};

/// A minimal but realistic single-file torrent. Keys are in sorted order at
/// both levels, so this input is canonical.
const TORRENT: &[u8] = b"d8:announce31:http://tracker.example/announce4:infod6:lengthi1024e4:name8:test.iso12:piece lengthi16384e6:pieces20:AAAAAAAAAAAAAAAAAAAAee";

fn kind_of(input: &[u8]) -> Option<ErrorKind> {
    bencode::parse(input).err().map(|e| e.kind)
}

#[test]
fn parses_a_small_torrent() {
    let parsed = bencode::parse(TORRENT).expect("the sample torrent should parse");
    assert!(parsed.canonical);

    let root = parsed.value.as_dict().expect("root is a dict");
    assert_eq!(root.len(), 2);
    assert_eq!(
        root.get(b"announce").and_then(Value::as_bytes),
        Some(b"http://tracker.example/announce".as_slice())
    );

    let info = root.get(b"info").expect("info key is present");
    let info_dict = info.as_dict().expect("info is a dict");
    assert_eq!(info_dict.get(b"length").and_then(Value::as_int), Some(1024));
    assert_eq!(
        info_dict.get(b"piece length").and_then(Value::as_int),
        Some(16384)
    );
    assert_eq!(
        info_dict.get(b"name").and_then(Value::as_bytes),
        Some(b"test.iso".as_slice())
    );
    // 20 bytes = exactly one SHA-1 piece hash.
    assert_eq!(
        info_dict
            .get(b"pieces")
            .and_then(Value::as_bytes)
            .map(<[u8]>::len),
        Some(20)
    );
}

/// The span of `info` is the exact byte range Phase 2 will SHA-1 to get the
/// `info_hash`. Getting this wrong means every peer in the swarm rejects us.
#[test]
fn the_info_span_is_the_raw_bytes_to_hash() {
    let parsed = bencode::parse(TORRENT).expect("parses");
    let info = parsed
        .value
        .as_dict()
        .and_then(|d| d.get(b"info"))
        .expect("info key is present");

    let raw = info
        .span()
        .slice(TORRENT)
        .expect("span is inside the input");
    assert!(raw.starts_with(b"d6:length"), "{:?}", raw.get(..16));
    assert!(raw.ends_with(b"e"));
    // Re-parsing just those bytes must give the same dictionary back.
    let again = bencode::parse(raw).expect("the info span is a complete value");
    assert_eq!(&again.value, info);
}

#[test]
fn t1_rejects_trailing_bytes() {
    // Two values in a row. Accepting this would mean a `.torrent` could smuggle
    // a second document past anything that only inspected the first.
    assert_eq!(kind_of(b"i1ei2e"), Some(ErrorKind::TrailingBytes));
    assert_eq!(kind_of(b"lei1e"), Some(ErrorKind::TrailingBytes));
    // Even a single stray byte counts.
    assert_eq!(kind_of(b"i1e\n"), Some(ErrorKind::TrailingBytes));
}

#[test]
fn t1_rejects_empty_input() {
    assert_eq!(kind_of(b""), Some(ErrorKind::UnexpectedEnd));
}

#[test]
fn t1_rejects_oversized_input() {
    let limits = Limits {
        max_input: 4,
        ..Limits::TORRENT
    };
    let err = bencode::parse_with(b"i12345e", &limits).expect_err("too large");
    assert_eq!(err.kind, ErrorKind::InputTooLarge);
    assert_eq!(err.at, 0);
    // The cap is checked BEFORE parsing starts, so an oversized file costs
    // us one length comparison and nothing else.
}

#[test]
fn tolerates_unsorted_keys_and_says_so() {
    let parsed = bencode::parse(b"d4:zzzzi1e1:ai2ee").expect("parses");
    assert!(!parsed.canonical, "unsorted keys must clear the flag");
    let d = parsed.value.as_dict().expect("is a dict");
    assert_eq!(d.get(b"a").and_then(Value::as_int), Some(2));
    assert_eq!(d.get(b"zzzz").and_then(Value::as_int), Some(1));
}

#[test]
fn a_parsed_value_borrows_from_the_caller_s_buffer() {
    // `owned` must outlive `parsed`. This test exists to document the
    // lifetime: if the two were swapped, the code would not compile.
    let owned: Vec<u8> = b"4:spam".to_vec();
    let parsed = bencode::parse(&owned).expect("parses");
    assert_eq!(parsed.value.as_bytes(), Some(b"spam".as_slice()));
}

#[test]
fn the_default_limits_are_the_torrent_limits() {
    let strict = bencode::parse(b"i1e").expect("parses");
    let explicit = bencode::parse_with(b"i1e", &Limits::TORRENT).expect("parses");
    assert_eq!(strict.value, explicit.value);
}
