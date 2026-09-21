# Phase 0 — Rust Crash Course + Project Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install the Rust toolchain and create a locked-down Cargo workspace (lints, supply-chain checks, CI, log redaction). Teach Rust basics through five small, torrent-flavoured exercises.

**Architecture:** One Cargo workspace. Its members are `crates/bencode` (a stub filled in Phase 1), `crates/engine` (with a `redact` module) and `learn` (crash-course exercises, never shipped). Security lints are set once at workspace level and inherited by every crate. The legacy Python code moves to `legacy-python/`.

**Tech Stack:** Rust stable (edition 2024), cargo, clippy, rustfmt, cargo-deny, GitHub Actions, gitleaks.

**Spec:** `docs/superpowers/specs/2026-09-21-secure-bittorrent-client-design.md` (rev. 2) — §5 crate policy, T16, §7 phase gate, §8 Phases 0a/0b.

## Global Constraints

- `unsafe_code = "forbid"` for every workspace crate.
- clippy `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` = `deny`. `unwrap`/`expect` are allowed only inside tests (`clippy.toml`).
- Edition 2024, resolver 3, `publish = false` on every crate.
- The toolchain is pinned in `rust-toolchain.toml`. `Cargo.lock` is committed.
- Zero third-party dependencies in Phase 0.
- Test names for security controls start with their threat ID, e.g. `t14_...`.
- The user is a complete beginner. After each task, give a plain-language explanation and append it to `docs/learn/NOTES.md`.
- Git commands use `git -c safe.directory=D:/projects/bittorrent-client` until the user adds the global exception.
- Commit messages end with `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

## File map

| File | Responsibility |
|---|---|
| `Cargo.toml` | Workspace: members, shared package metadata, **security lints** |
| `rust-toolchain.toml` | Pins the exact Rust version |
| `clippy.toml` | Allows `unwrap`/`expect` in tests only |
| `.gitignore`, `.gitattributes` | Ignore build output; normalise line endings |
| `legacy-python/*` | Original Python client (reference only) |
| `crates/bencode/{Cargo.toml,src/lib.rs}` | Stub; Phase 1 |
| `crates/engine/{Cargo.toml,src/lib.rs,src/redact.rs}` | `LogPolicy` + `Redacted` log redaction |
| `learn/{Cargo.toml,src/lib.rs}` | Crash course root |
| `learn/src/ex01_piece_math.rs` | Variables, types, functions, `Option`, checked arithmetic |
| `learn/src/ex02_messages.rs` | Enums, `match`, slice patterns |
| `learn/src/ex03_bitfield.rs` | Structs, `impl`, `&self` / `&mut self`, `Vec` |
| `learn/src/ex04_ownership.rs` | Ownership, borrowing, slices, `HashSet` |
| `learn/src/ex05_results.rs` | `Result`, custom errors, the `?` operator |
| `deny.toml` | cargo-deny policy (advisories, licenses, sources) |
| `.github/workflows/ci.yml` | fmt, clippy, test, deny, gitleaks |
| `docs/THREAT_MODEL.md` | Living status table T1–T16 |
| `docs/learn/NOTES.md` | Plain-language notes for the user |

---

### Task 0: Install the toolchain (USER runs this)

**Files:** none

- [ ] **Step 1:** Install the MSVC C++ build tools. Rust on Windows uses Microsoft's linker.

```bash
winget install --id Microsoft.VisualStudio.2022.BuildTools --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
```

- [ ] **Step 2:** Install rustup, the official Rust installer and version manager.

```bash
winget install --id Rustlang.Rustup
```

- [ ] **Step 3:** Close and reopen the terminal and the Claude app so `PATH` updates. Then verify:

```bash
rustc --version
```

```bash
cargo --version
```

Expected: both print a version such as `rustc 1.9x.y (...)`.

- [ ] **Step 4:** Add the git safe-directory exception (the D: drive doesn't record file owners):

```bash
git config --global --add safe.directory D:/projects/bittorrent-client
```

---

### Task 1: Workspace foundation + legacy move

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `clippy.toml`, `.gitattributes`, `crates/bencode/Cargo.toml`, `crates/bencode/src/lib.rs`, `crates/engine/Cargo.toml`, `crates/engine/src/lib.rs`, `learn/Cargo.toml`, `learn/src/lib.rs`, `legacy-python/README.md`
- Modify: `.gitignore`
- Move: `bencoding.py client.py main.py pieces.py protocol.py torrent.py tracker.py test_tracker.py` → `legacy-python/`

**Interfaces:**
- Produces: workspace members `bencode`, `engine` and `learn`, which inherit `[workspace.lints]`.

- [ ] **Step 1: Move the legacy code**

```bash
mkdir -p legacy-python && mv bencoding.py client.py main.py pieces.py protocol.py torrent.py tracker.py test_tracker.py legacy-python/
```

`legacy-python/README.md`:

```markdown
# Legacy Python client (reference only)

The original asyncio prototype. **Never built, tested or shipped.** It's kept as a
readable reference for the protocol flow. Known bugs are listed in the
design spec, §10. Don't copy its patterns without checking that list.
```

- [ ] **Step 2: Write `rust-toolchain.toml`.** Pin it to the exact version from `rustc --version`. For example, if that prints `1.97.0`, write `channel = "1.97.0"`:

```toml
[toolchain]
channel = "1.97.0"
components = ["clippy", "rustfmt"]
profile = "minimal"
```

- [ ] **Step 3: Write the root `Cargo.toml`.** `rust-version` must be the same version as the toolchain channel:

```toml
[workspace]
resolver = "3"
members = ["crates/bencode", "crates/engine", "learn"]

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.97"
license = "MIT OR Apache-2.0"
publish = false

# Security policy for EVERY crate (spec §5 "Crate policy").
[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
indexing_slicing = "deny"
```

- [ ] **Step 4: Write `clippy.toml`**

```toml
allow-unwrap-in-tests = true
allow-expect-in-tests = true
```

- [ ] **Step 5: Write the three member crates**

`crates/bencode/Cargo.toml` (the other two are identical except for `name`, which is `engine` and `learn`):

```toml
[package]
name = "bencode"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish.workspace = true

[lints]
workspace = true
```

`crates/bencode/src/lib.rs`:

```rust
//! Bounded, hardened bencode parser (threat T1). Implemented in Phase 1.
```

`crates/engine/src/lib.rs`:

```rust
//! Torrent engine. Knows nothing about the UI. Spec §4.2.
```

`learn/src/lib.rs`:

```rust
//! Phase 0a Rust crash course. Never shipped.
```

- [ ] **Step 6: Update `.gitignore` and write `.gitattributes`**

`.gitignore`:

```
/target/
.venv/
__pycache__/
node_modules/
*.torrent
```

`.gitattributes`:

```
* text=auto eol=lf
*.png binary
*.ico binary
```

- [ ] **Step 7: Build and prove the unsafe ban works**

Run: `cargo build --workspace`. Expected: `Finished`.

Temporarily add `pub fn bad() { unsafe {} }` to `crates/engine/src/lib.rs`, then run `cargo build -p engine`.
Expected: `error: usage of an unsafe block` … `#[forbid(unsafe_code)]`. **Remove the line** and rebuild; it should say `Finished`.

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "chore: cargo workspace with security lints; move legacy python"
```

---

### Task 2: ex01 — piece math (types, functions, `Option`, overflow)

**Files:**
- Create: `learn/src/ex01_piece_math.rs`
- Modify: `learn/src/lib.rs` (add `pub mod ex01_piece_math;`)

**Interfaces:**
- Produces: `piece_count(u64, u64) -> Option<u64>`, `last_piece_len(u64, u64) -> Option<u64>`, `piece_offset(u64, u64) -> Option<u64>`

- [ ] **Step 1: Write the stubs and the failing tests**

```rust
//! ex01: how many pieces, how long is the last one, where does piece N start?
//! Security lesson: never trust sizes, and never let arithmetic overflow silently.

/// Number of pieces for `total_len` bytes split into `piece_len`-byte pieces.
/// `None` if `piece_len` is 0 (division by zero would crash).
pub fn piece_count(total_len: u64, piece_len: u64) -> Option<u64> {
    todo!()
}

/// Length of the final piece (it's usually shorter). `None` for nonsense input.
pub fn last_piece_len(total_len: u64, piece_len: u64) -> Option<u64> {
    todo!()
}

/// Byte offset where piece `index` starts. `None` if the multiplication overflows.
pub fn piece_offset(index: u64, piece_len: u64) -> Option<u64> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_exact_fit() {
        assert_eq!(piece_count(1024, 256), Some(4));
    }

    #[test]
    fn count_partial_last_piece() {
        assert_eq!(piece_count(1000, 256), Some(4));
    }

    #[test]
    fn t14_count_rejects_zero_piece_len() {
        assert_eq!(piece_count(1000, 0), None);
    }

    #[test]
    fn last_piece_partial() {
        assert_eq!(last_piece_len(1000, 256), Some(232));
    }

    #[test]
    fn last_piece_full() {
        assert_eq!(last_piece_len(1024, 256), Some(256));
    }

    #[test]
    fn last_piece_rejects_empty_or_zero() {
        assert_eq!(last_piece_len(0, 256), None);
        assert_eq!(last_piece_len(1000, 0), None);
    }

    #[test]
    fn offset_normal() {
        assert_eq!(piece_offset(3, 256), Some(768));
    }

    #[test]
    fn t14_offset_overflow_is_caught() {
        assert_eq!(piece_offset(u64::MAX, 2), None);
    }
}
```

- [ ] **Step 2: Run the tests to watch them fail**

Run: `cargo test -p learn ex01`. Expected: 8 FAILED with `not yet implemented`.

- [ ] **Step 3: Implement**

```rust
pub fn piece_count(total_len: u64, piece_len: u64) -> Option<u64> {
    if piece_len == 0 {
        return None;
    }
    Some(total_len.div_ceil(piece_len))
}

pub fn last_piece_len(total_len: u64, piece_len: u64) -> Option<u64> {
    if piece_len == 0 || total_len == 0 {
        return None;
    }
    match total_len % piece_len {
        0 => Some(piece_len),
        rem => Some(rem),
    }
}

pub fn piece_offset(index: u64, piece_len: u64) -> Option<u64> {
    index.checked_mul(piece_len)
}
```

- [ ] **Step 4: Run the tests to watch them pass**

Run: `cargo test -p learn ex01`. Expected: `8 passed`.

- [ ] **Step 5: Commit** — `git add learn && git commit -m "learn: ex01 piece math"`

---

### Task 3: ex02 — peer messages (enums, `match`, slice patterns)

**Files:**
- Create: `learn/src/ex02_messages.rs`
- Modify: `learn/src/lib.rs` (add `pub mod ex02_messages;`)

**Interfaces:**
- Produces: `enum Message`, `Message::id(&self) -> Option<u8>`, `from_wire(u8, &[u8]) -> Option<Message>`

- [ ] **Step 1: Write the enum, the stubs and the failing tests**

```rust
//! ex02: a few BEP-3 peer messages as a Rust enum.
//! Security lesson: every message type has an EXACT payload size (threat T3).
//! Anything else is rejected, not guessed at.

#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have { piece_index: u32 },
}

impl Message {
    /// The ID byte sent on the wire. KeepAlive has no ID (it's an empty frame).
    pub fn id(&self) -> Option<u8> {
        todo!()
    }
}

/// Decode an ID byte plus payload. Unknown ID or wrong size → `None`, never a crash.
pub fn from_wire(id: u8, payload: &[u8]) -> Option<Message> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_match_bep3() {
        assert_eq!(Message::KeepAlive.id(), None);
        assert_eq!(Message::Choke.id(), Some(0));
        assert_eq!(Message::Unchoke.id(), Some(1));
        assert_eq!(Message::Interested.id(), Some(2));
        assert_eq!(Message::NotInterested.id(), Some(3));
        assert_eq!(Message::Have { piece_index: 7 }.id(), Some(4));
    }

    #[test]
    fn decodes_simple_messages() {
        assert_eq!(from_wire(0, &[]), Some(Message::Choke));
        assert_eq!(from_wire(2, &[]), Some(Message::Interested));
    }

    #[test]
    fn decodes_have_big_endian() {
        assert_eq!(from_wire(4, &[0, 0, 1, 2]), Some(Message::Have { piece_index: 258 }));
    }

    #[test]
    fn t3_rejects_have_with_wrong_length() {
        assert_eq!(from_wire(4, &[0, 0, 1]), None);
        assert_eq!(from_wire(4, &[0, 0, 0, 1, 9]), None);
    }

    #[test]
    fn t3_rejects_payload_on_choke() {
        assert_eq!(from_wire(0, &[1]), None);
    }

    #[test]
    fn t3_rejects_unknown_id() {
        assert_eq!(from_wire(99, &[]), None);
    }
}
```

- [ ] **Step 2: Run to see it fail** — `cargo test -p learn ex02`. Expected: FAILED (`not yet implemented`).

- [ ] **Step 3: Implement**

```rust
impl Message {
    pub fn id(&self) -> Option<u8> {
        match self {
            Message::KeepAlive => None,
            Message::Choke => Some(0),
            Message::Unchoke => Some(1),
            Message::Interested => Some(2),
            Message::NotInterested => Some(3),
            Message::Have { .. } => Some(4),
        }
    }
}

pub fn from_wire(id: u8, payload: &[u8]) -> Option<Message> {
    match (id, payload) {
        (0, []) => Some(Message::Choke),
        (1, []) => Some(Message::Unchoke),
        (2, []) => Some(Message::Interested),
        (3, []) => Some(Message::NotInterested),
        (4, [a, b, c, d]) => Some(Message::Have {
            piece_index: u32::from_be_bytes([*a, *b, *c, *d]),
        }),
        _ => None,
    }
}
```

- [ ] **Step 4: Run to see it pass** — `cargo test -p learn ex02`. Expected: `6 passed`.

- [ ] **Step 5: Commit** — `git add learn && git commit -m "learn: ex02 peer messages"`

---

### Task 4: ex03 — bitfield (structs, `impl`, `&self` vs `&mut self`)

**Files:**
- Create: `learn/src/ex03_bitfield.rs`
- Modify: `learn/src/lib.rs` (add `pub mod ex03_bitfield;`)

**Interfaces:**
- Produces: `struct Bitfield` with `new(usize)`, `len`, `is_empty`, `has(usize) -> bool`, `set(usize) -> bool`, `count() -> usize`, `from_bytes(Vec<u8>, usize) -> Option<Bitfield>`

- [ ] **Step 1: Write the struct, the stubs and the failing tests**

```rust
//! ex03: which pieces does a peer have? One bit per piece (BEP-3).
//! The highest bit of byte 0 is piece 0.
//! Security lesson: use `.get()`, never `[i]`, so a bad index can't crash us.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitfield {
    bytes: Vec<u8>,
    num_pieces: usize,
}

impl Bitfield {
    /// An all-zero bitfield for `num_pieces` pieces.
    pub fn new(num_pieces: usize) -> Self {
        todo!()
    }

    pub fn len(&self) -> usize {
        self.num_pieces
    }

    pub fn is_empty(&self) -> bool {
        self.num_pieces == 0
    }

    /// Does the peer have piece `index`? Out of range → false.
    pub fn has(&self, index: usize) -> bool {
        todo!()
    }

    /// Mark piece `index` as present. Returns false (and changes nothing) if out of range.
    pub fn set(&mut self, index: usize) -> bool {
        todo!()
    }

    /// How many pieces are present.
    pub fn count(&self) -> usize {
        todo!()
    }

    /// Build from bytes a peer sent. Takes ownership of `bytes`, so nothing is copied.
    /// Rejects the wrong length, or spare bits that aren't zero (BEP-3 says they must be).
    pub fn from_bytes(bytes: Vec<u8>, num_pieces: usize) -> Option<Self> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty_of_pieces() {
        let bf = Bitfield::new(10);
        assert_eq!(bf.len(), 10);
        assert_eq!(bf.count(), 0);
        assert!(!bf.has(0));
    }

    #[test]
    fn set_then_has() {
        let mut bf = Bitfield::new(10);
        assert!(bf.set(9));
        assert!(bf.has(9));
        assert!(!bf.has(8));
        assert_eq!(bf.count(), 1);
    }

    #[test]
    fn bit_order_is_high_bit_first() {
        let mut bf = Bitfield::new(8);
        bf.set(0);
        assert_eq!(bf.bytes, vec![0b1000_0000]);
    }

    #[test]
    fn t3_out_of_range_is_safe() {
        let mut bf = Bitfield::new(10);
        assert!(!bf.has(10));
        assert!(!bf.has(usize::MAX));
        assert!(!bf.set(10));
        assert_eq!(bf.count(), 0);
    }

    #[test]
    fn from_bytes_accepts_valid() {
        let bf = Bitfield::from_bytes(vec![0b1100_0000, 0b0100_0000], 10).unwrap();
        assert!(bf.has(0) && bf.has(1) && bf.has(9));
        assert_eq!(bf.count(), 3);
    }

    #[test]
    fn t3_from_bytes_rejects_wrong_length() {
        assert_eq!(Bitfield::from_bytes(vec![0], 10), None);
        assert_eq!(Bitfield::from_bytes(vec![0, 0, 0], 10), None);
    }

    #[test]
    fn t3_from_bytes_rejects_spare_bits() {
        // 10 pieces → 16 bits, so the last 6 bits are spare and must be zero.
        assert_eq!(Bitfield::from_bytes(vec![0, 0b0010_0000], 10), None);
    }
}
```

- [ ] **Step 2: Run to see it fail** — `cargo test -p learn ex03`. Expected: FAILED.

- [ ] **Step 3: Implement**

```rust
    pub fn new(num_pieces: usize) -> Self {
        Bitfield {
            bytes: vec![0; num_pieces.div_ceil(8)],
            num_pieces,
        }
    }

    pub fn has(&self, index: usize) -> bool {
        if index >= self.num_pieces {
            return false;
        }
        let bit = 7 - (index % 8);
        match self.bytes.get(index / 8) {
            Some(&byte) => (byte >> bit) & 1 == 1,
            None => false,
        }
    }

    pub fn set(&mut self, index: usize) -> bool {
        if index >= self.num_pieces {
            return false;
        }
        let bit = 7 - (index % 8);
        match self.bytes.get_mut(index / 8) {
            Some(byte) => {
                *byte |= 1 << bit;
                true
            }
            None => false,
        }
    }

    pub fn count(&self) -> usize {
        self.bytes.iter().map(|b| b.count_ones() as usize).sum()
    }

    pub fn from_bytes(bytes: Vec<u8>, num_pieces: usize) -> Option<Self> {
        if bytes.len() != num_pieces.div_ceil(8) {
            return None;
        }
        let bf = Bitfield { bytes, num_pieces };
        let spare_bits_set = bf.count() != (0..num_pieces).filter(|&i| bf.has(i)).count();
        if spare_bits_set {
            return None;
        }
        Some(bf)
    }
```

- [ ] **Step 4: Run to see it pass** — `cargo test -p learn ex03`. Expected: `7 passed`.

- [ ] **Step 5: Commit** — `git add learn && git commit -m "learn: ex03 bitfield"`

---

### Task 5: ex04 — ownership and borrowing

**Files:**
- Create: `learn/src/ex04_ownership.rs`
- Modify: `learn/src/lib.rs` (add `pub mod ex04_ownership;`)

**Interfaces:**
- Produces: `total_len(&[u64]) -> Option<u64>`, `longest_name(&[String]) -> Option<&str>`, `has_case_collision(&[&str]) -> bool`, `normalize(String) -> String`

- [ ] **Step 1: Write the stubs and the failing tests**

```rust
//! ex04: ownership (who owns data) and borrowing (temporarily looking at it).
//! Security lessons: sums of attacker-supplied sizes can overflow (T14), and
//! Windows treats "A.TXT" and "a.txt" as the SAME file (T2).

use std::collections::HashSet;

/// Sum of all file lengths. BORROWS the slice. `None` on overflow.
pub fn total_len(file_lengths: &[u64]) -> Option<u64> {
    todo!()
}

/// The longest name, returned as a BORROW of the caller's data (no copy).
pub fn longest_name(names: &[String]) -> Option<&str> {
    todo!()
}

/// True if two names differ only by upper/lower case.
pub fn has_case_collision(names: &[&str]) -> bool {
    todo!()
}

/// TAKES OWNERSHIP of `name`, changes it in place, and gives it back.
pub fn normalize(name: String) -> String {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_lengths() {
        assert_eq!(total_len(&[100, 200, 300]), Some(600));
        assert_eq!(total_len(&[]), Some(0));
    }

    #[test]
    fn t14_sum_overflow_is_caught() {
        assert_eq!(total_len(&[u64::MAX, 1]), None);
    }

    #[test]
    fn finds_longest_name() {
        let names = vec!["a.txt".to_string(), "movie.mkv".to_string(), "b".to_string()];
        assert_eq!(longest_name(&names), Some("movie.mkv"));
        assert_eq!(longest_name(&[]), None);
    }

    #[test]
    fn t2_detects_case_collision() {
        assert!(has_case_collision(&["Readme.txt", "notes.txt", "README.TXT"]));
        assert!(!has_case_collision(&["a.txt", "b.txt"]));
    }

    #[test]
    fn normalize_lowercases() {
        let owned = String::from("Ubuntu.ISO");
        let result = normalize(owned);
        // `owned` can't be used here any more: it was MOVED into normalize().
        assert_eq!(result, "ubuntu.iso");
    }
}
```

- [ ] **Step 2: Run to see it fail** — `cargo test -p learn ex04`. Expected: FAILED.

- [ ] **Step 3: Implement**

```rust
pub fn total_len(file_lengths: &[u64]) -> Option<u64> {
    file_lengths
        .iter()
        .try_fold(0u64, |acc, &len| acc.checked_add(len))
}

pub fn longest_name(names: &[String]) -> Option<&str> {
    names.iter().max_by_key(|n| n.len()).map(String::as_str)
}

pub fn has_case_collision(names: &[&str]) -> bool {
    let mut seen = HashSet::new();
    for name in names {
        if !seen.insert(name.to_lowercase()) {
            return true;
        }
    }
    false
}

pub fn normalize(mut name: String) -> String {
    name.make_ascii_lowercase();
    name
}
```

- [ ] **Step 4: Run to see it pass** — `cargo test -p learn ex04`. Expected: `5 passed`.

- [ ] **Step 5: Commit** — `git add learn && git commit -m "learn: ex04 ownership and borrowing"`

---

### Task 6: ex05 — `Result`, custom errors, `?`

**Files:**
- Create: `learn/src/ex05_results.rs`
- Modify: `learn/src/lib.rs` (add `pub mod ex05_results;`)

**Interfaces:**
- Produces: `enum PeerAddrError`, `parse_port(&str) -> Result<u16, PeerAddrError>`, `parse_peer(&str) -> Result<SocketAddrV4, PeerAddrError>`, `const MAX_PEERS: usize = 200`, `parse_compact_peers(&[u8]) -> Result<Vec<SocketAddrV4>, PeerAddrError>`

- [ ] **Step 1: Write the error type, the stubs and the failing tests**

```rust
//! ex05: errors as values. `Result<T, E>` is either Ok(T) or Err(E).
//! `?` means "if this is an error, return it right now".
//! Security lesson: trackers send peers as 6-byte chunks (4 IP + 2 port). A
//! hostile tracker can send junk lengths or millions of peers (T7).

use std::net::{Ipv4Addr, SocketAddrV4};

#[derive(Debug, PartialEq, Eq)]
pub enum PeerAddrError {
    MissingColon,
    BadIp,
    BadPort,
    PortZero,
    BadCompactLength,
    TooManyPeers,
}

pub const MAX_PEERS: usize = 200;

pub fn parse_port(s: &str) -> Result<u16, PeerAddrError> {
    todo!()
}

/// Parse "1.2.3.4:6881".
pub fn parse_peer(s: &str) -> Result<SocketAddrV4, PeerAddrError> {
    todo!()
}

/// Parse a tracker's compact peer list (BEP-23).
pub fn parse_compact_peers(bytes: &[u8]) -> Result<Vec<SocketAddrV4>, PeerAddrError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_port() {
        assert_eq!(parse_port("6881"), Ok(6881));
    }

    #[test]
    fn rejects_bad_ports() {
        assert_eq!(parse_port("0"), Err(PeerAddrError::PortZero));
        assert_eq!(parse_port("70000"), Err(PeerAddrError::BadPort));
        assert_eq!(parse_port("abc"), Err(PeerAddrError::BadPort));
        assert_eq!(parse_port(""), Err(PeerAddrError::BadPort));
    }

    #[test]
    fn parses_peer() {
        assert_eq!(
            parse_peer("10.0.0.5:6881"),
            Ok(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 6881))
        );
    }

    #[test]
    fn peer_errors_bubble_up_through_question_mark() {
        assert_eq!(parse_peer("10.0.0.5"), Err(PeerAddrError::MissingColon));
        assert_eq!(parse_peer("999.0.0.1:80"), Err(PeerAddrError::BadIp));
        assert_eq!(parse_peer("10.0.0.5:0"), Err(PeerAddrError::PortZero));
    }

    #[test]
    fn parses_compact_peers() {
        let bytes = [127, 0, 0, 1, 0x1A, 0xE1, 10, 0, 0, 2, 0x1A, 0xE2];
        let peers = parse_compact_peers(&bytes).unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers.first(), Some(&SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 6881)));
    }

    #[test]
    fn t7_rejects_ragged_length() {
        assert_eq!(parse_compact_peers(&[1, 2, 3, 4, 5]), Err(PeerAddrError::BadCompactLength));
    }

    #[test]
    fn t7_rejects_too_many_peers() {
        let bytes = vec![1u8; 6 * (MAX_PEERS + 1)];
        assert_eq!(parse_compact_peers(&bytes), Err(PeerAddrError::TooManyPeers));
    }

    #[test]
    fn t7_rejects_port_zero_in_compact() {
        assert_eq!(parse_compact_peers(&[1, 2, 3, 4, 0, 0]), Err(PeerAddrError::PortZero));
    }
}
```

- [ ] **Step 2: Run to see it fail** — `cargo test -p learn ex05`. Expected: FAILED.

- [ ] **Step 3: Implement**

```rust
pub fn parse_port(s: &str) -> Result<u16, PeerAddrError> {
    let port: u16 = s.parse().map_err(|_| PeerAddrError::BadPort)?;
    if port == 0 {
        return Err(PeerAddrError::PortZero);
    }
    Ok(port)
}

pub fn parse_peer(s: &str) -> Result<SocketAddrV4, PeerAddrError> {
    let (ip_part, port_part) = s.rsplit_once(':').ok_or(PeerAddrError::MissingColon)?;
    let ip: Ipv4Addr = ip_part.parse().map_err(|_| PeerAddrError::BadIp)?;
    let port = parse_port(port_part)?;
    Ok(SocketAddrV4::new(ip, port))
}

pub fn parse_compact_peers(bytes: &[u8]) -> Result<Vec<SocketAddrV4>, PeerAddrError> {
    if !bytes.len().is_multiple_of(6) {
        return Err(PeerAddrError::BadCompactLength);
    }
    let count = bytes.len() / 6;
    if count > MAX_PEERS {
        return Err(PeerAddrError::TooManyPeers);
    }
    let mut peers = Vec::with_capacity(count);
    for chunk in bytes.chunks_exact(6) {
        if let [a, b, c, d, p1, p2] = chunk {
            let port = u16::from_be_bytes([*p1, *p2]);
            if port == 0 {
                return Err(PeerAddrError::PortZero);
            }
            peers.push(SocketAddrV4::new(Ipv4Addr::new(*a, *b, *c, *d), port));
        }
    }
    Ok(peers)
}
```

- [ ] **Step 4: Run to see it pass** — `cargo test -p learn ex05`. Expected: `8 passed`.

- [ ] **Step 5: Lint the whole crash course** — `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all --check`. Expected: no output, exit code 0. If rustfmt complains, run `cargo fmt --all` and re-check.

- [ ] **Step 6: Commit** — `git add learn && git commit -m "learn: ex05 results and errors"`

---

### Task 7: engine log redaction (T8 privacy-safe logs)

**Files:**
- Create: `crates/engine/src/redact.rs`
- Modify: `crates/engine/src/lib.rs` (add `pub mod redact;`)

**Interfaces:**
- Produces: `struct LogPolicy { pub diagnostics: bool }` (`Default` = diagnostics off), `LogPolicy::redact<'a, T: ?Sized>(&self, &'a T) -> Redacted<'a, T>`, and `Redacted` implementing `Display` + `Debug`

- [ ] **Step 1: Write the failing tests**

```rust
//! Log redaction (spec T8). Sensitive values (peer IPs, torrent names, tracker
//! URLs) are logged ONLY through `LogPolicy::redact`, which prints `[redacted]`
//! unless the user explicitly turned on diagnostic logging.

use std::fmt;

const MASK: &str = "[redacted]";

/// Default: diagnostics OFF, so sensitive values are hidden.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogPolicy {
    pub diagnostics: bool,
}

pub struct Redacted<'a, T: ?Sized> {
    value: &'a T,
    reveal: bool,
}

impl LogPolicy {
    pub fn redact<'a, T: ?Sized>(&self, value: &'a T) -> Redacted<'a, T> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    #[test]
    fn t8_default_policy_hides_ip() {
        let policy = LogPolicy::default();
        assert_eq!(format!("peer {}", policy.redact(&IP)), "peer [redacted]");
    }

    #[test]
    fn t8_default_policy_hides_debug_output_too() {
        let policy = LogPolicy::default();
        assert_eq!(format!("{:?}", policy.redact("secret-name.iso")), "[redacted]");
    }

    #[test]
    fn t8_diagnostics_reveals() {
        let policy = LogPolicy { diagnostics: true };
        assert_eq!(policy.redact(&IP).to_string(), "203.0.113.7");
        assert_eq!(format!("{:?}", policy.redact("a.iso")), "\"a.iso\"");
    }
}
```

- [ ] **Step 2: Run to see it fail** — `cargo test -p engine`. Expected: FAILED (`not yet implemented`).

- [ ] **Step 3: Implement**

```rust
impl LogPolicy {
    pub fn redact<'a, T: ?Sized>(&self, value: &'a T) -> Redacted<'a, T> {
        Redacted {
            value,
            reveal: self.diagnostics,
        }
    }
}

impl<T: fmt::Display + ?Sized> fmt::Display for Redacted<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.reveal {
            fmt::Display::fmt(self.value, f)
        } else {
            f.write_str(MASK)
        }
    }
}

impl<T: fmt::Debug + ?Sized> fmt::Debug for Redacted<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.reveal {
            fmt::Debug::fmt(self.value, f)
        } else {
            f.write_str(MASK)
        }
    }
}
```

- [ ] **Step 4: Run to see it pass** — `cargo test -p engine`. Expected: `3 passed`.

- [ ] **Step 5: Commit** — `git add crates/engine && git commit -m "feat(engine): log redaction policy (T8)"`

---

### Task 8: Supply chain + CI (T16)

**Files:**
- Create: `deny.toml`, `.github/workflows/ci.yml`

- [ ] **Step 1: Write `deny.toml`**

```toml
# cargo-deny policy (spec T16). Checks every dependency for known
# vulnerabilities, unacceptable licenses and untrusted sources.
[graph]
all-features = true

[advisories]
version = 2
yanked = "deny"

[licenses]
version = 2
allow = ["MIT", "Apache-2.0", "Unicode-3.0", "BSD-3-Clause", "ISC", "Zlib"]
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"
wildcards = "deny"
allow-wildcard-paths = true

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

- [ ] **Step 2: Install cargo-deny and run it** (this builds it from crates.io, so **ask the user before installing**)

```bash
cargo install --locked cargo-deny
```

Run: `cargo deny check`. Expected: `advisories ok, bans ok, licenses ok, sources ok`.

- [ ] **Step 3: Write `.github/workflows/ci.yml`**

```yaml
name: ci
on: [push, pull_request]

# Least privilege: CI can read the code and nothing else.
permissions:
  contents: read

jobs:
  rust:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace

  deny:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2

  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

(Stretch goal, T16: pin each `uses:` to a full commit SHA instead of a tag.)

- [ ] **Step 4: Run the CI Rust steps locally**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`. Expected: every test passes (37 total: 34 in `learn`, 3 in `engine`) and there are no warnings.

- [ ] **Step 5: Commit** — `git add deny.toml .github && git commit -m "ci: fmt, clippy, tests, cargo-deny, gitleaks (T16)"`

---

### Task 9: Threat-model tracker, learning notes, phase gate

**Files:**
- Create: `docs/THREAT_MODEL.md`, `docs/learn/NOTES.md`

- [ ] **Step 1: Write `docs/THREAT_MODEL.md`**

```markdown
# Threat Model — Status Tracker

Full descriptions of each threat are in the spec, §5. This file tracks **status only**.
Status is one of: `planned` → `implemented` → `tested` → `reviewed`.

| ID | Threat | Phase | Status | Evidence |
|---|---|---|---|---|
| T1 | Malicious bencode | 1 | planned | |
| T2 | Path traversal / FS races | 2 | planned | (lesson: `learn::ex04` case collision) |
| T3 | Malformed peer messages | 4 | planned | (lesson: `learn::ex02`, `learn::ex03`) |
| T4 | Piece poisoning | 5 | planned | |
| T5 | Resource exhaustion | 4–5 | planned | |
| T6 | Reflection / amplification | 3 | planned | |
| T7 | Hostile trackers / SSRF | 3 | planned | (lesson: `learn::ex05`) |
| T8 | Privacy / network failure | 0b, 8 | partial | `engine::redact` tests `t8_*` |
| T9 | UI / IPC compromise | 7 | planned | |
| T10 | Tampered installer / update | 9 | planned | |
| T11 | Seeding abuse | 5 | planned | |
| T12 | Local attacker / config | 7 | planned | |
| T13 | Downloaded-content execution | 2 | planned | |
| T14 | Metainfo sanity | 2 | planned | (lesson: `learn::ex01`, `learn::ex04`) |
| T15 | External launch inputs | 7 | planned | |
| T16 | Supply chain | 0b | implemented | `deny.toml`, `ci.yml`, workspace lints |
```

- [ ] **Step 2: Write `docs/learn/NOTES.md`.** Collect the plain-language explanation given after each task, under one heading per task.

- [ ] **Step 3: Phase gate (spec §7)**

- Compiles: `cargo build --workspace`.
- Tests pass: `cargo test --workspace`.
- Threat review: T8 is partial and T16 is implemented; nothing new is open.
- Explanation given to the user.

- [ ] **Step 4: Commit** — `git add docs && git commit -m "docs: threat-model tracker and phase 0 learning notes"`
