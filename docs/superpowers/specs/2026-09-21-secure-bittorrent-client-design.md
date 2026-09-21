# Secure BitTorrent Client — Design Spec

> **Status:** Awaiting user review. All brainstorming questions are answered (2026-09-21).
> No code is written until this spec is approved. After approval, it is turned into a task-by-task implementation plan.

---

## 1. Goal

Build a **security-first BitTorrent desktop client** in **Rust + Tauri**. It downloads and seeds files from `.torrent` files, and later from magnet links. It will be installable from a download website.

The project is also a **learning vehicle**. The user is a complete Rust beginner, and every phase is taught as **concept → threat → design → build → test**.

**Legality.** The BitTorrent protocol is legal, and so are clients like qBittorrent and uTorrent. Only piracy is illegal. All testing uses legal content: our own test files, Ubuntu/Debian ISOs, or public-domain works from the Internet Archive.

---

## 2. Decisions

| # | Question | Decision |
|---|---|---|
| 1 | App architecture | **Tauri 2.** Rust engine, web UI in the OS webview, **no network port opened for the UI** |
| 1b | Rust experience | **Complete beginner.** Crash course in Phase 0. Early phases are synchronous. Compiler errors are taught, not hidden. |
| 2 | Scope | **v1: `.torrent` only.** **v2: magnet links + DHT, a firm requirement.** v1 must be designed so v2 doesn't need a rewrite. |
| 3 | Seeding | **Download + upload**, with upload rate limits and strict request validation |
| 4 | Privacy | **All four:** SOCKS5 proxy, network kill switch (interface binding), protocol encryption (MSE/PE), IP blocklist |
| 5 | Target OS | **Windows first.** Tauri keeps macOS and Linux possible later. |
| 6 | Testing | **Unit + fuzzing + local test swarm** |

---

## 3. Architecture

```
┌──────────────────────── one desktop process ────────────────────────┐
│                                                                      │
│  UI (TypeScript, OS webview)        Rust side                        │
│  ┌──────────────────┐   Tauri IPC   ┌──────────────────────────────┐ │
│  │ torrent list      │ ───────────► │ src-tauri: command layer      │ │
│  │ add / pause / rm  │  allowlisted │  - validates every argument   │ │
│  │ speeds, settings  │ ◄─────────── │  - no fs/shell plugins to UI  │ │
│  └──────────────────┘   events      └──────────────┬───────────────┘ │
│   CSP: no remote scripts,                          │                  │
│   no eval, no inline JS                            ▼                  │
│                                     ┌──────────────────────────────┐ │
│                                     │ engine crate (tokio)          │ │
│                                     │  session ─ torrents by hash   │ │
│                                     │  peer sources: tracker (v1),  │ │
│                                     │               DHT (v2)        │ │
│                                     │  peer conns ─ wire protocol   │ │
│                                     │  piece picker ─ storage       │ │
│                                     │  net layer: proxy / bind /    │ │
│                                     │   blocklist / encryption      │ │
│                                     └──────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
          ▲ network: trackers + peers (all untrusted)
```

### 3.1 Repository layout (Cargo workspace)

```
bittorrent-client/
├─ crates/
│  ├─ bencode/        # hardened bencode parser/encoder (no deps, fuzzed)
│  ├─ engine/         # all torrent logic, no UI knowledge
│  └─ test-swarm/     # tiny HTTP tracker + harness for end-to-end tests
├─ src-tauri/         # Tauri app: IPC commands, capabilities, bundling
├─ ui/                # TypeScript frontend (Vite, vanilla TS to start)
├─ fuzz/              # cargo-fuzz targets
├─ legacy-python/     # the original Python client, kept as reference only
└─ docs/
```

**Why separate crates:** the `bencode` and `engine` crates don't depend on Tauri. They can be tested and fuzzed alone, and the UI can't reach engine internals except through the command layer.

### 3.2 Engine modules

| Module | Responsibility |
|---|---|
| `metainfo` | Turns decoded bencode into a validated `Metainfo`. Computes `info_hash`. Holds the file list. |
| `storage` | Maps pieces to files and offsets, runs the **path sandbox**, handles preallocation, reads for seeding, writes for downloading |
| `tracker` | HTTP (BEP-3) and UDP (BEP-15) announces; implements `PeerSource` |
| `peer` | Handshake, message framing and parsing, per-connection state machine, timeouts |
| `picker` | Rarest-first piece selection, request pipelining, endgame mode |
| `choker` | Tit-for-tat unchoking, optimistic unchoke, upload slots |
| `net` | Socket creation: interface binding (kill switch), SOCKS5, blocklist check, MSE/PE |
| `ratelimit` | Token-bucket limits for upload and download, global and per peer |
| `session` | Owns all torrents (keyed by `InfoHash`), config, and resume data. Sends events to the UI. |

### 3.3 Designed for v2 (magnet + DHT)

- Torrents are keyed by **`InfoHash`**, never by file path.
- `Torrent.metainfo: Option<Metainfo>`. It is `None` until metadata arrives, which in v2 comes over BEP-9.
- Peer discovery goes through a **`PeerSource` trait**. `TrackerSource` is the v1 implementation; `DhtSource` is added in v2.
- The handshake reserves and sets the **extension-protocol bit (BEP-10)**, and the message parser tolerates extension messages from v1 onwards.

---

## 4. Threat model

**Core rule:** every byte from the network, from a `.torrent` file, or from the UI is **untrusted until validated**.

**What Rust gives us for free:** no buffer overflows, use-after-free or data races in safe code.
**What it does not:** logic bugs, unbounded allocation, panics (a crash is still a DoS), and path traversal.
**Policy:**
- `#![forbid(unsafe_code)]` in `bencode` and `engine`.
- No `unwrap()`/`expect()` on untrusted data. clippy enforces this.
- Every size read from input is checked against a cap *before* allocating.

| ID | Threat | Source | Impact | Mitigation |
|---|---|---|---|---|
| T1 | Malicious bencode: deep nesting, huge length prefixes, non-canonical ints | `.torrent`, tracker | Crash or memory exhaustion | Parser with a **max depth** (e.g. 64), **max input size** (e.g. 10 MB for `.torrent`), string length checked against the remaining input, strict integer grammar (no `i-0e`, no leading zeros), trailing data rejected, dict keys required to be sorted |
| T2 | **Path traversal** in multi-file torrents (`..`, absolute paths, `C:\`, `\\?\`, UNC, `CON`/`NUL`/`AUX`, trailing dots or spaces, ADS `file:stream`) | `.torrent` | **Arbitrary file write**, e.g. into Startup | Each path component validated against a strict allowlist. The final path is **resolved and confirmed to be inside the download directory**. Symlinks, junctions and reparse points are refused. Files are created with no-follow semantics. |
| T3 | Oversized or malformed peer messages | Peer | Memory exhaustion, crash | Length prefix capped (e.g. 16 KiB block + header, bitfield ≤ `ceil(pieces/8)`). Exact size checked per message type. Per-connection buffer cap. |
| T4 | Piece poisoning | Peer | Corrupt data, wasted bandwidth | SHA-1 verification before any piece is marked complete. Each piece records its contributors, and a peer is banned after repeated hash failures. |
| T5 | Resource exhaustion: connection floods, slowloris peers, request spam | Peers | Engine stalls | Global and per-torrent connection caps, handshake timeout, idle timeout, per-peer request queue cap, half-open connection limit |
| T6 | Reflection and amplification via UDP tracker (v2: DHT) | Third party | Our client attacks someone else | UDP tracker connection-ID handshake (BEP-15), outgoing rate limits, never sending a large reply to an unverified source |
| T7 | Hostile tracker responses: huge peer lists, private or loopback IPs, redirect chains | Tracker | Memory use, **SSRF-style scanning of the LAN** | Response size cap, peer-count cap, loopback/private/multicast peers dropped by default, redirects limited, HTTPS preferred |
| T8 | IP exposure to the swarm and ISP | Swarm, ISP | Privacy loss | SOCKS5 proxy, kill switch (bind to one interface, stop all traffic if it goes down), MSE/PE encryption, clear in-UI explanation of what each does and **does not** protect |
| T9 | UI compromise: XSS through torrent names, or malicious IPC calls | `.torrent` contents, UI | Engine controlled by an attacker | Tauri **capabilities allowlist** (only our commands), strict **CSP**, no `innerHTML` with torrent data (text nodes only), every IPC argument validated in Rust, no fs/shell/http plugins exposed |
| T10 | Tampered installer or update | MITM, compromised host | Malware on the user's PC | Tauri updater with **signed manifests**, code-signed installer, SHA-256 checksums on the website, HTTPS only |
| T11 | **Seeding abuse:** requests for pieces we don't have, out-of-range offsets, oversized block lengths, request floods | Peer | Crash, info leak, bandwidth drain | Each request checked: piece index < count, we have the piece, `offset + len ≤ piece_len`, `len ≤ 16 KiB`, peer is unchoked. Per-peer request queue cap and upload rate limit. Reads only through the sandboxed `storage` API. |
| T12 | Blocklist or config file tampering | Local file, downloaded list | Parser crash, disabled protections | Blocklist parser with size and line caps. Config validated on load. Unsafe values are rejected with a fallback to defaults. |

**MSE/PE note:** it uses RC4 and a 768-bit Diffie-Hellman key exchange. This is **obfuscation against ISP traffic shaping, not real security**. The UI and docs will say so plainly; overselling it would be a security bug in itself.

---

## 5. Testing strategy

| Layer | Tool | What it covers |
|---|---|---|
| Unit tests | `cargo test` | Every module, including a test for every threat mitigation (e.g. "rejects `..` path", "rejects depth 65") |
| Property tests | `proptest` | Encode→decode round-trips, piece/offset math, path validator invariants |
| Fuzzing | `cargo-fuzz` (libFuzzer) | Bencode parser, metainfo builder, peer message parser, tracker response parser, blocklist parser. Runs in **WSL or GitHub Actions (Linux)**, because fuzzing support on Windows is limited. |
| Malicious fixtures | Hand-crafted `.torrent` files | A "museum" of known attacks: path traversal, nesting bombs, huge lengths |
| Local swarm (E2E) | `crates/test-swarm` | Our own minimal HTTP tracker plus instances of our client. Seed a generated file from one instance, download it with another, verify hashes. Also a hostile-peer mode that sends malformed messages. |
| Static checks | `clippy` (pedantic subset), `cargo audit`, `cargo deny` | Lints, known-vulnerable dependencies, license policy |
| CI | GitHub Actions | Runs everything on each push (Windows build + Linux fuzz smoke test) |

---

## 6. Roadmap

Each phase ends with passing tests and a commit. The Rust concepts column is the teaching plan.

### v1

| Phase | Build | Rust concepts taught | Threats addressed |
|---|---|---|---|
| **0a** | Rust crash course: standalone exercises, no torrent code | cargo, variables, types, functions, `match`, `struct`, `enum`, ownership intro | Why memory safety matters |
| **0b** | Project setup: git, workspace, Tauri scaffold, clippy, CI, move Python to `legacy-python/` | crates, modules, `Cargo.toml`, tests | Dependency pinning, `cargo audit`/`deny` |
| **1** | `bencode` crate | **ownership and borrowing**, `&[u8]` slices, `Result` and `?`, recursive enums, error types | **T1** + first fuzz target |
| **2** | `metainfo` + `storage` path sandbox (single- and multi-file) | `Path`/`PathBuf`, `impl` blocks, newtypes (`InfoHash`), validation | **T2**, T9 (safe names) |
| **3** | Tracker client (HTTP, then UDP) | **async/await, tokio**, `reqwest`, `UdpSocket`, `PeerSource` trait | T6, T7 |
| **4** | Peer wire protocol (handshake, messages, connection state machine) | traits, byte encoding and decoding, `tokio::spawn`, timeouts, `select!` | **T3**, T5 |
| **5** | Piece picker, pipelining, storage writes, resume data | **`Arc`, `Mutex`, channels (`mpsc`)**, shared state | T4 |
| **6** | Seeding: choker, upload handling, rate limiting | token buckets, fairness scheduling | **T11**, T5 |
| **7** | `test-swarm` crate + end-to-end tests + hostile-peer tests | integration tests, test harnesses | Validates T3–T5, T11 |
| **8** | Tauri UI + IPC commands + events | Tauri commands, `serde`, TypeScript basics | **T9** |
| **9** | Privacy: interface binding (kill switch), SOCKS5, IP blocklist, MSE/PE | lower-level sockets, the `socket2` crate, DH + RC4 streams | **T8**, T12 |
| **10** | Packaging: Tauri bundler (MSI/NSIS), code signing, signed updater | build configs, release profiles | **T10** |
| **11** | Distribution website: download page, checksums, release notes | — | T10 |

### v2 (required)

| Phase | Build | Threats |
|---|---|---|
| **v2-a** | Extension protocol (BEP-10) + metadata exchange (BEP-9) | Metadata size caps. Metadata must SHA-1-match the `info_hash`. |
| **v2-b** | Magnet URI parsing | Strict URI parsing, hex and base32 hash validation, tracker URL validation |
| **v2-c** | DHT (BEP-5, Kademlia) as a `DhtSource` | T6 reflection, Sybil / eclipse resistance, routing-table limits, token validation, rate limits |

---

## 7. Out of scope (for now)

- macOS and Linux builds (possible later with Tauri)
- Streaming playback, RSS feeds, a torrent search engine, a web UI for remote access
- uTP (BEP-29) transport; TCP only in v1
- Torrent creation (`.torrent` file authoring), unless it's needed for the test swarm, where it's a test-only tool

---

## 8. Legacy Python code

The existing Python client (`bencoding.py`, `torrent.py`, `tracker.py`, `pieces.py`, `protocol.py`, `client.py`) moves to `legacy-python/`. It serves as a **reading reference** for the protocol flow. Its known bugs are recorded here so they aren't repeated in the port:

- Unbounded recursive bencode decoder (T1)
- Single-file torrents only
- `event=started` is never sent
- A list is modified while it's being iterated in `next_request`
- A bare `except Exception: pass` hides errors
- No message length cap (T3)
- One request at a time (no pipelining)
- No seeding
