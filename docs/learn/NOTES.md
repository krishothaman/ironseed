# Learning Notes

Plain-language notes, one section per task. Reread these anytime.

---

## Setup — installing Rust (and the exFAT lesson)

- **rustc** is the *compiler*. It turns the Rust code you write into an `.exe` your computer can run.
- **cargo** is Rust's *project manager*. It builds, tests, and downloads libraries. You'll mostly type `cargo ...`, not `rustc`.
- **rustup** installs and updates Rust itself.
- **Build Tools (MSVC)**: Microsoft's *linker*, the tool that glues compiled pieces into one `.exe`. Rust uses it on Windows.

**Lesson:** a file system is more than "a place files go".

| Feature | NTFS (C:) | exFAT (D:) |
|---|---|---|
| Hard links (one file, many names) | ✅ | ❌ ← this broke the Rust installer |
| Permissions ("only krish can edit") | ✅ | ❌ ← any program can edit anything |
| Junctions / symlinks | ✅ | ❌ |
| Journaling (survives power cuts) | ✅ | ❌ |

So Rust lives on C:, and our project lives on D:. Our security tests for file paths
will run in the Windows temp folder (C:), because exFAT can't even create the
tricky links those tests need.

---

## Task 1 — The project foundation

**What we built:** an empty but *locked-down* project skeleton.

```
bittorrent-client/
├─ Cargo.toml            ← the "master plan" for the whole project
├─ rust-toolchain.toml   ← "use EXACTLY Rust 1.98.1"
├─ clippy.toml           ← small settings for the code checker
├─ crates/
│  ├─ bencode/           ← (empty) will read .torrent files — Phase 1
│  └─ engine/            ← (empty) the torrent engine
├─ learn/                ← your practice exercises
└─ legacy-python/        ← the old Python code, kept only to read
```

### New words

- **Crate**: Rust's name for a package or library. We have three.
- **Workspace**: several crates managed together, like a folder of related projects that share settings.
- **`Cargo.toml`**: a settings file. `[workspace]` lists our crates; `[workspace.lints]` lists rules every crate must follow.
- **Lint**: an automatic check that complains about risky code.

### The security rules we switched on (and why)

| Rule | What it bans | Why it matters |
|---|---|---|
| `unsafe_code = "forbid"` | `unsafe { }` blocks | `unsafe` is Rust's "trust me" switch: it turns OFF memory-safety checks. Most security bugs in C/C++ torrent clients are memory bugs. We just ban it. |
| `unwrap_used = "deny"` | `.unwrap()` | `.unwrap()` means "I'm sure this worked; if not, **crash**". An attacker who can make it fail can crash our app (a DoS, "denial of service"). |
| `expect_used = "deny"` | `.expect("..")` | Same as unwrap, just with a message. |
| `panic = "deny"` | `panic!()` | A panic is a deliberate crash. |
| `indexing_slicing = "deny"` | `list[i]` | If `i` is too big, Rust crashes. With data from strangers, `i` is attacker-controlled. We'll use `list.get(i)`, which returns "nothing" instead of crashing. |

`clippy.toml` allows `unwrap` **only inside tests**, where a crash just means "test failed".

**We proved the rule works:** we added `unsafe {}` and the build **refused**:
`error: usage of an unsafe block`. A security rule you've never seen fail is a
rule you can't trust.

### Why pin the Rust version?

`rust-toolchain.toml` says "1.98.1". Everyone who builds this project (you, CI, a
future teammate) gets *exactly* the same compiler, with no "works on my machine"
surprises. It's also a supply-chain habit: know exactly what builds your code.

### Why keep the Python code?

It still shows the order things happen in BitTorrent. But it has bugs (listed in the
spec, section 10), so it goes in `legacy-python/` as a reference, never as code we run.
