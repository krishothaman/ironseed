# Threat Model — Status Tracker

Full descriptions of each threat are in the spec, §5
(`docs/superpowers/specs/2026-09-21-secure-bittorrent-client-design.md`).
This file tracks **status only**, so there is one place to answer
"which defences actually exist today?"

Status is one of:

| Status | Meaning |
|---|---|
| `planned` | Designed in the spec, no code yet |
| `partial` | Some of the defence exists |
| `implemented` | Code exists |
| `tested` | Code exists **and** tests prove it |
| `reviewed` | Tested, plus a deliberate review pass against the spec |

Evidence in brackets is a *lesson* from the Phase 0a crash course, not shipping code.

| ID | Threat | Phase | Status | Evidence |
|---|---|---|---|---|
| T1 | Malicious bencode | 1 | planned | |
| T2 | Path traversal / FS races | 2 | planned | (lesson: `learn::ex04` case collision) |
| T3 | Malformed peer messages | 4 | planned | (lessons: `learn::ex02`, `learn::ex03`) |
| T4 | Piece poisoning | 5 | planned | |
| T5 | Resource exhaustion | 4–5 | planned | (lesson: `learn::ex05` `MAX_PEERS`) |
| T6 | Reflection / amplification | 3 | planned | |
| T7 | Hostile trackers / SSRF | 3 | planned | (lesson: `learn::ex05`) |
| T8 | Privacy / network failure | 0b, 8 | partial | `engine::redact`, tests `t8_*` (3) |
| T9 | UI / IPC compromise | 7 | planned | |
| T10 | Tampered installer / update | 9 | planned | |
| T11 | Seeding abuse | 5 | planned | |
| T12 | Local attacker / config | 7 | planned | |
| T13 | Downloaded-content execution | 2 | planned | |
| T14 | Metainfo sanity | 2 | planned | (lessons: `learn::ex01`, `learn::ex04`) |
| T15 | External launch inputs | 7 | planned | |
| T16 | Supply chain | 0b | implemented | `deny.toml`, `.github/workflows/ci.yml`, workspace lints |

## Project-wide defences (apply to every threat)

| Defence | Where | Effect |
|---|---|---|
| `unsafe_code = "forbid"` | root `Cargo.toml` | No memory-unsafe code can be written at all |
| `unwrap_used`, `expect_used`, `panic` denied | root `Cargo.toml` | Attacker-triggered crashes (DoS) are much harder to write by accident |
| `indexing_slicing` denied | root `Cargo.toml` | No `list[i]` panics on attacker-chosen indexes |
| Pinned toolchain | `rust-toolchain.toml` | Reproducible builds; a known compiler |
| CI on every push | `.github/workflows/ci.yml` | fmt, clippy, tests, cargo-deny, gitleaks |
| `permissions: contents: read` | `.github/workflows/ci.yml` | Least privilege for CI tokens |

## Rules for updating this file

1. A threat moves to `tested` only when a test **fails** without the defence.
2. Name tests after the threat (`t3_rejects_have_with_wrong_length`) so the evidence
   column can be verified with `cargo test t3_`.
3. Update this file in the **same commit** as the defence, never later.
