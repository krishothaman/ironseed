# Secure BitTorrent Client — Design Spec (rev. 2)

> **Status:** APPROVED by user, 2026-09-21.
> **Rev. 2** merges an external security review (Manus) with the author's own additions. Section 9 records what was taken from each source.
> **Product claim:** *"A security-conscious, experimental, Windows-first BitTorrent client for authorized content, with bounded parsing, sandboxed storage, signed releases, and explicitly documented privacy limitations."*
> It is **not** anonymous, **not** VPN-equivalent and **not** production-hardened until it has had independent review.

---

## 1. Goal

A BitTorrent desktop client in **Rust + Tauri 2**, Windows first. It downloads and seeds from `.torrent` files; later milestones add magnet links and DHT. It will be installable from a download website.

It is also a **Rust-learning project**. The user is a complete beginner, so every phase follows **concept → threat → smallest safe design → build → test → security review**, explained in plain language.

**Legality.** The BitTorrent protocol and client software are lawful in many jurisdictions. Whether specific content may be copied depends on its copyright status. Testing uses only self-created files, official Linux images, and public-domain or otherwise authorized content. (This is not legal advice.)

---

## 2. Decisions

| # | Topic | Decision |
|---|---|---|
| 1 | Architecture | **Tauri 2.** Rust engine plus a TypeScript UI in WebView2. **No network port opened for the UI.** |
| 2 | Rust experience | Complete beginner. Crash course first, early phases synchronous, compiler errors taught. |
| 3 | Scope | **Milestone 1: `.torrent` only.** **Milestone 2: magnet links + DHT (required).** BitTorrent v2 (BEP-52) is a *separate, later* project. |
| 4 | Seeding | Download + upload, with limits and strict request validation |
| 5 | Privacy | SOCKS5 proxy, kill switch (interface binding), MSE/PE obfuscation, IP blocklist. Every one fails closed and shows a visible status. |
| 6 | Target OS | Windows first |
| 7 | Testing | Unit, property, fuzzing, local hostile swarm, and Windows-specific tests |
| 8 | Rigor | Controls are **tiered** (§6): *Required* before any public build, *Stretch* afterwards |

---

## 3. Scope and terminology

**Milestone 1 (M1)** includes:
- `.torrent` import and BitTorrent v1 metainfo with SHA-1 piece verification
- HTTP and UDP trackers over TCP peer connections
- Downloading and seeding
- The Tauri UI with an IPC allowlist
- Windows packaging with signed updates

**M1 excludes:** magnet links, metadata exchange, DHT, uTP, streaming, RSS, remote administration, search, and torrent authoring (except as a test-only tool).

**Rule:** M1 never *advertises* features it doesn't implement. For example, the BEP-10 extension bit is **not** set in M1, though the parser tolerates message ID 20 and ignores it safely.

| Later milestone | Content |
|---|---|
| **M2-a** Extension protocol | BEP-10 negotiation, BEP-9 metadata exchange |
| **M2-b** Magnet support | Strict magnet URI parsing, then metadata acquisition through M2-a |
| **M2-c** Mainline DHT | BEP-5 peer discovery over UDP |
| **M3** BitTorrent v2 / hybrid | BEP-52 metadata and piece layers. Specified separately, later. |

**Designed for M2 now:** torrents are keyed by `InfoHash`, never by file path. `metainfo` is `Option<Metainfo>`, so it can arrive later. Peer discovery goes through a `PeerSource` trait.

---

## 4. Architecture

```
┌──────────────────────── one desktop process ────────────────────────┐
│  UI (TypeScript, WebView2)          Rust                             │
│  ┌──────────────────┐   Tauri IPC   ┌──────────────────────────────┐ │
│  │ torrent list,     │ ───────────► │ src-tauri: command layer      │ │
│  │ add/pause/remove, │  allowlisted │ = SECURITY BOUNDARY           │ │
│  │ speeds, settings  │ ◄─────────── │ typed args, validated,        │ │
│  └──────────────────┘   events      │ errors never leak paths       │ │
│  CSP: no remote/inline script,      └──────────────┬───────────────┘ │
│  no eval; text nodes only                          ▼                  │
│                                     ┌──────────────────────────────┐ │
│                                     │ engine (tokio)                │ │
│                                     │ session · metainfo · storage  │ │
│                                     │ tracker · peer · picker       │ │
│                                     │ choker · ratelimit · net      │ │
│                                     └──────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
               ▲ trackers + peers: ALL UNTRUSTED
```

### 4.1 Workspace

```
bittorrent-client/
├─ crates/
│  ├─ bencode/       # bounded parser/encoder; no dependencies; fuzzed
│  ├─ engine/        # all torrent logic; knows nothing about the UI
│  └─ test-swarm/    # local tracker, seeders, hostile peers (tests only)
├─ src-tauri/        # IPC commands, capabilities, bundling, updater
├─ ui/               # TypeScript (Vite, vanilla TS)
├─ fuzz/             # cargo-fuzz targets and corpora
├─ learn/            # Phase 0 Rust exercises (not shipped)
├─ legacy-python/    # original client: reference only, never built or shipped
└─ docs/             # specs, plans, threat model, limitations
```

### 4.2 Engine modules

| Module | Responsibility |
|---|---|
| `metainfo` | Bencode → validated `Metainfo`. `info_hash` = SHA-1 of the **raw info-dict bytes**. Sanity limits. |
| `storage` | Handle-relative, reparse-point-safe file creation. Piece↔file mapping, atomic writes, quotas, free-space checks, resume state, Mark-of-the-Web. |
| `tracker` | HTTP and UDP (BEP-15) clients with response correlation, address policy and limits. Implements `PeerSource`. |
| `peer` | Handshake, framing, state machine, deadlines, request validation |
| `picker` | Rarest-first, pipelining, endgame, completion |
| `choker` / `ratelimit` | Tit-for-tat, optimistic unchoke, token buckets |
| `net` | The **only** place sockets are created. Proxy, DNS policy, IPv4/IPv6 policy, interface binding, blocklist, MSE/PE. |
| `session` | Torrent lifecycle, config, persistence, shutdown, UI events |
| `redact` | Log redaction helpers, used by all logging |

---

## 5. Threat model

**Rule:** every network byte, local file, file name, config value, update artifact and UI argument is untrusted.

**What Rust gives us:** memory safety in safe code.
**What it doesn't:** protection from DoS, logic bugs, path races, privacy leaks, unsafe updates, or broken authorization.

**Crate policy:**
- `#![forbid(unsafe_code)]` in `bencode` and `engine`. Any Windows API needed goes through a reviewed crate such as `cap-std` or `windows`, never ad-hoc `unsafe`.
- No `unwrap()` or `expect()` on fallible paths, enforced by clippy.
- Every length is checked against a cap *before* allocating.

### T1 — Malicious bencode
**Controls:**
- Caps on input size (`.torrent` ≤ 10 MiB), nesting depth (≤ 64), item count per list or dict, string length (≤ remaining input), and integer digits (≤ 20).
- Strict integer grammar: no `-0`, no leading zeros, no empty integer.
- **Duplicate keys are rejected.**
- **Unsorted keys are tolerated**, because many real torrents have them, and a flag records that the input was non-canonical.
- Trailing bytes after the top-level value are rejected.
- The parser records the **byte span** of every value, so `info_hash` can be computed over the original bytes.

### T2 — Path traversal and Windows filesystem races
- **Component allowlist** rejects: `..` and `.`, empty components, absolute and drive-qualified paths, UNC and `\\?\` device paths, `:` (alternate data streams), reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`, including with extensions), trailing dots or spaces, control characters, `<>:"/\|?*`, and invalid UTF-8.
- **Case-insensitive collision detection** across the torrent's own files (`a.txt` vs `A.TXT`).
- **Race resistance:** the download root is opened once as a directory handle, and every directory and file is created **relative to that handle** with `cap-std`. Reparse points (junctions, symlinks) are refused at every component. **We never do string-resolve-then-check.**
- **Tests:** a junction is swapped in mid-creation, a pre-planted junction exists, and the path is long (> 260 characters).
- The download directory is user-chosen. System, Program Files, Windows and Startup directories are refused.
- **Overwrite policy:** existing files are never overwritten unless the user explicitly resumes into them.

### T3 — Malformed peer messages
**Controls:**
- The frame length is capped *before* allocating: ≤ 16 KiB + 13 for `piece` messages; bitfield ≤ ⌈pieces/8⌉.
- Each message type must have its exact size.
- Per-connection buffer cap.
- Deadlines for the handshake, idle time and total connection time.

### T4 — Piece poisoning
**Controls:**
- SHA-1 verification before a piece is marked complete.
- Each piece records who contributed to it.
- **Cautious reputation:** a peer is banned only after repeated failures, never after one, and the threshold is configurable. A failed piece is optionally re-fetched from a single peer to attribute blame.
- Tested with a mix of honest and corrupting peers.

### T5 — Resource exhaustion
**Controls:**
- Global and per-torrent caps on connections, half-open connections, outstanding requests, tracker response size, disk queue, and UI event rate.
- A slowloris defence through deadlines.

### T6 — Reflection and amplification
**Controls:**
- UDP tracker: validate packet length, `action` and `transaction_id`; use only a live connection ID (≤ 60 s); never assume a fixed packet size.
- Rate-limit all outgoing UDP traffic.

### T7 — Hostile trackers, and SSRF through announce URLs
**Controls:**
- **Address policy** applies to both tracker-supplied peers **and to announce URLs from the torrent**. Loopback, private (RFC 1918), link-local, CGNAT, multicast and unspecified addresses are blocked by default; LAN addresses are an explicit opt-in.
- DNS results are re-checked, so a public hostname that resolves to a LAN address is also blocked.
- Only the `http`, `https` and `udp` schemes are allowed.
- Response byte cap, peer-count cap, and ≤ 2 redirects, each redirect re-checked against the address policy.

### T8 — Privacy and network failure (exposure reduction, **not** anonymity)
- **SOCKS5 with a DNS policy:** remote DNS through the proxy when the proxy is on (`socks5h` semantics). No local lookups of tracker or peer hostnames.
- **UDP under a proxy:** most SOCKS5 proxies don't support UDP, so **UDP trackers (and, in M2, DHT) are disabled while a proxy is active**, unless UDP ASSOCIATE is verified. The UI explains the cost: no UDP trackers and weaker seeding, since a proxy can't accept incoming connections.
- **IPv6:** disabled whenever the proxy or kill-switch path can't cover it.
- **Interface binding** applies to *every* socket (tracker, peer, DNS, and DHT in M2), because all sockets are created in `net`. **If binding fails, the network stops; there is no silent fallback.**
- **Kill-switch state machine:** states `Off / Armed / Tripped`. Tested for interface loss, proxy failure and partial socket creation. A manual checklist covers sleep/wake and restart (automated later, as a stretch goal).
- **MSE/PE** is described in the UI as "traffic obfuscation (RC4, weak), not encryption for privacy".
- **Blocklist:** limits on size, lines and ranges. A failed update keeps the old list and **reports the failure**.
- **Log redaction:** by default, no peer IPs, torrent names, proxy credentials, or tracker URLs with passkeys. Diagnostic logging is an explicit opt-in. A redaction unit test covers this.
- **UI limitations panel:** what each control does and does not protect.

### T9 — UI / IPC compromise
**Controls:**
- A capabilities allowlist is committed to git, and **a test checks that commands outside it fail**.
- The Tauri **isolation pattern**.
- Strict CSP: no remote scripts, no inline scripts, no `eval`.
- **Text nodes only** for torrent names and tracker messages; never `innerHTML`.
- No fs, shell, http or process plugins exposed to the webview.
- Devtools disabled in release builds, and no remote-domain IPC.
- Command errors are structured and never contain full paths.

### T10 — Tampered installer or update
**Controls:**
- HTTPS only.
- The Tauri updater verifies **signed manifests and artifacts**.
- **Anti-rollback:** older versions are rejected.
- SHA-256 checksums on the website.
- The updater's signing key is kept out of git and separate from CI build credentials.
- **Tests:** corrupt signature, wrong public key, altered manifest, altered artifact, downgrade, and unreachable server.
- *Stretch:* Authenticode code signing (it costs money and mainly affects SmartScreen), reproducible builds, provenance, and a revocation and key-rotation plan.

### T11 — Seeding abuse
Every request is checked:
- the piece index is below the piece count,
- we have the piece and it's verified,
- `offset + len ≤ piece_len`,
- `0 < len ≤ 16 KiB`,
- the peer is unchoked and interested,
- the queue is under its cap,
- duplicate requests are dropped,
- the global and per-peer rate limits allow it.

Reads happen **only** through the `storage` API.

### T12 — Local attacker and config tampering
**Controls:**
- Config and resume files are validated on load, and unsafe security settings **fail closed**.
- Atomic replace (write a temp file, then rename).
- Files live in a per-user app-data directory.
- Secrets (proxy password) go in the Windows Credential Manager (`keyring` crate), not plain config.

### T13 — Downloaded-content execution
**Controls:**
- Downloaded files are **inert**: never auto-opened, never previewed.
- **Mark-of-the-Web** (`Zone.Identifier`, the hidden tag Windows attaches to downloaded files) is written on completed files, so Windows SmartScreen warns before running one.
- The UI warns that executables and scripts in a download are untrusted.

### T14 — Metainfo sanity (small file, huge claims)
**Controls:**
- Piece length is a power of two between 16 KiB and 64 MiB.
- `pieces.len() % 20 == 0`.
- The piece count must equal ⌈total/piece_len⌉.
- File count ≤ 100,000, total size ≤ 1 PiB, path depth ≤ 32, name length ≤ 255.

### T15 — External launch inputs
**Controls:**
- `.torrent` file association (and, in M2, `magnet:` links) is a **new untrusted input channel**, since a website can trigger it.
- **Adding a torrent always requires user confirmation in the UI.** Nothing auto-starts from an external launch.

### T16 — Supply chain
**Controls:**
- `Cargo.lock` and `package-lock.json` are committed.
- `cargo audit`, `cargo deny` (advisories, licenses, sources) and `npm audit` run in CI.
- Secret scanning (gitleaks).
- The number of dependencies is kept minimal and new ones get reviewed.
- CI uses least-privilege tokens.

---

## 6. Tiering

| Tier | Meaning | Includes |
|---|---|---|
| **Required** | Must pass before *any* public build | All of T1–T16 except the items marked *stretch* |
| **Stretch** | After the first public build | Authenticode, reproducible builds, provenance, key revocation and rotation, automated sleep/wake tests, interop with a second established client |

---

## 7. Testing and acceptance gates

**Tests:**
- **Unit** tests for every module. Every control in §5 gets at least one test that names its threat ID, e.g. `t2_rejects_reserved_name`.
- **Property** tests (`proptest`): round-trips, piece math, path invariants, request bounds.
- **Fuzzing** (`cargo-fuzz`, run in WSL or Linux CI): bencode, metainfo, peer messages, tracker responses, blocklist and config (magnet in M2). Corpus, duration and crash triage are recorded.
- **Local swarm:** honest, malformed, slow, corrupting and flooding peers; tracker failure; disk full.
- **Windows-specific:** junction races, reserved names, case collisions, long paths, proxy failure, interface loss, installer and updater tests.
- **Static checks:** `clippy -D warnings`, `cargo audit`, `cargo deny`, gitleaks.
- **Interop:** against at least one established client (qBittorrent) using legal torrents. A second client is a stretch goal.

**Phase gate:** each phase must compile, pass its tests, get a threat review, get a commit, and get a plain-language explanation for the user.

**Public-release gate:**
- No open high-severity findings.
- No unresolved fuzz crashes.
- Hostile-peer, path-race, proxy and kill-switch failure tests all pass.
- Update artifacts are signed.
- `docs/LIMITATIONS.md` is published.

---

## 8. Roadmap

| Phase | Build | Rust concepts taught | Threats |
|---|---|---|---|
| **0a** | Rust crash course (`learn/`) | cargo, types, functions, `match`, structs, enums, ownership | — |
| **0b** | Foundation: git, workspace, CI, lint policy, error model, logging/redaction, `THREAT_MODEL.md`, legacy code moved | crates, modules, tests, `Cargo.toml` | T16 |
| **1** | Bounded bencode | ownership and borrowing, slices, `Result`/`?`, enums, error types | T1 |
| **2** | Metainfo + storage | `Path`, newtypes, `impl`, traits, `cap-std` | T2, T13, T14 |
| **3** | Trackers (HTTP → UDP) | async/await, tokio, `PeerSource` trait | T6, T7 |
| **4** | Peer protocol | byte encoding, `tokio::spawn`, `select!`, timeouts | T3, T5 |
| **5** | Pieces, seeding, choker, rate limits | `Arc`, `Mutex`, channels | T4, T11 |
| **6** | Local swarm + E2E tests | integration tests | T3–T5, T11 |
| **7** | Tauri UI + IPC | Tauri commands, `serde`, TypeScript | T9, T12, T15 |
| **8** | Network controls | `socket2`, state machines | T8 |
| **9** | Release security | release profiles, updater | T10 |
| **10** | Distribution website | — | T10 |
| **M2-a/b/c** | Extension protocol, magnet, DHT | — | + metadata caps, BEP-5 tokens, Sybil limits |
| **M3** | BitTorrent v2 / hybrid | — | specified separately |

---

## 9. Provenance of rev. 2 changes

- **From the external review (Manus):**
  - milestone renaming, and separating out BitTorrent v2
  - race-resistant Windows storage
  - DNS and IPv6 leak policy, and kill-switch semantics
  - log redaction
  - inert downloads
  - anti-rollback and updater failure tests
  - supply-chain controls, local-attacker threats, and disk-exhaustion controls
  - acceptance gates
  - not advertising unimplemented extensions
  - narrowed legality and product claims
- **From the author:**
  - raw-bytes `info_hash` (tolerate unsorted keys, don't reject them)
  - SSRF through announce URLs and DNS re-checks
  - Mark-of-the-Web
  - UDP-under-SOCKS5 limitation
  - external-launch confirmation (T15)
  - metainfo sanity limits (T14)
  - Tauri isolation pattern and disabled devtools
  - Credential Manager for secrets
  - tiering (Authenticode and similar items as stretch goals)
- **Declined:** strict rejection of unsorted keys, because it breaks real torrents.

---

## 10. Legacy Python — known bugs not to repeat

- Unbounded recursive decoder
- `info_hash` computed by **re-encoding** (wrong for non-canonical torrents)
- Single-file torrents only
- `event=started` never sent
- A list is modified while it's being iterated
- A bare `except: pass`
- No frame cap
- No pipelining
- No seeding
