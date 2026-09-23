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

---

## Task 2 — ex01 piece math (`learn/src/ex01_piece_math.rs`)

**Torrent idea:** a torrent splits a file into equal **pieces** (for example 256 KiB each).
The last piece is usually shorter. We need three answers: how many pieces, how
long is the last one, and where does piece N start in the file.

### Rust you learned

```rust
pub fn piece_count(total_len: u64, piece_len: u64) -> Option<u64> {
```
- `fn` makes a function. `pub` means other files may use it.
- `total_len: u64` is an input named `total_len` of type `u64`: an **unsigned 64-bit number**,
  meaning whole numbers from 0 up to about 18 quintillion. No negatives, no decimals.
- `-> Option<u64>` is what it returns. **`Option` means "maybe a number":**
  - `Some(4)` → "here's the answer: 4"
  - `None` → "there is no sensible answer"

  Rust has **no `null`**. If something might be missing, the type *says so*,
  and the compiler forces the caller to handle the `None` case.
- `if ... { return None; }` bails out early.
- `match` is a smarter `if`: "look at this value, and pick the branch that fits":
  ```rust
  match total_len % piece_len {   // % = remainder after division
      0   => Some(piece_len),     // divides evenly → last piece is full size
      rem => Some(rem),           // otherwise → last piece = the remainder
  }
  ```
- The last line without a `;` is the return value. `Some(...)` at the end = return it.

### TDD (test-driven development)

1. Write tests first (`#[test] fn ...`), using `assert_eq!(actual, expected)`.
2. Run them → **watch them fail** (we used `todo!()`, which means "not written yet").
3. Write the real code.
4. Run them → **watch them pass**.

Seeing a test fail first proves it really tests something. A test that can
never fail protects nothing.

### Security lesson — attackers control the numbers (threat T14)

A `.torrent` file is written by a stranger. It can claim **any** numbers:

| Attack | What happens in naive code | Our defence |
|---|---|---|
| `piece length = 0` | division by zero → **crash** | `if piece_len == 0 { return None }` |
| `piece index` huge | `index × piece_len` gets bigger than a `u64` can hold → **overflow** | `checked_mul` returns `None` instead |

**Overflow** is like a car odometer rolling past 999999 back to 000000. In Rust:
- in a *debug* build, overflow **crashes** (a denial of service),
- in a *release* build, it silently **wraps around** to a small wrong number. Our code
  would then write data to the **wrong place in the file**.

The old Python code did `index * piece_length` with no check at all.
`checked_mul` means: "multiply, but if it overflows, tell me with `None`".

Test names starting with `t14_` link each test to threat T14 in the spec, so we can
prove every threat has a test.

---

## Task 3 — ex02 peer messages (`learn/src/ex02_messages.rs`)

**Torrent idea:** peers talk by sending small **messages**. Each one starts with an
**ID byte** saying what kind of message it is (0 = choke, 1 = unchoke, 2 = interested,
3 = not interested, 4 = have), followed by a **payload**, the extra data (possibly none).

### Rust you learned

- **`enum`**: a type that is *exactly one of* a fixed list of choices:
  ```rust
  pub enum Message { KeepAlive, Choke, Unchoke, Interested, NotInterested,
                     Have { piece_index: u32 } }
  ```
  `Have` carries data with it (which piece the peer now has). The others carry nothing.
  A `Message` can never be "something else". The compiler knows the full list.
- **`#[derive(Debug, PartialEq, Eq)]`**: asks Rust to auto-write code so we can
  print a message (`Debug`) and compare two with `==` (`PartialEq`, `Eq`). Tests need both.
- **`impl Message { ... }`**: attaches functions (**methods**) to the type.
  `&self` means "look at this message, but don't change it or take it away".
- **`match` must be exhaustive**: in `id()` we list every variant. If we later add
  a new message and forget it here, the code **won't compile**. The compiler reminds us.
- **`Have { .. }`**: "a Have, and I don't care what's inside".
- **`&[u8]`**: a **slice**, meaning a view into a run of bytes someone else owns.
- **Slice patterns**: `match` can check a slice's *shape*:
  - `[]` matches only an empty slice,
  - `[a, b, c, d]` matches only exactly 4 bytes, and names them,
  - `_` matches anything else.
- **`u32::from_be_bytes([a,b,c,d])`**: glue 4 bytes into one number, **big-endian**
  (most significant byte first, the "network byte order" BitTorrent uses).
  `[0, 0, 1, 2]` → 0×2²⁴ + 0×2¹⁶ + 1×256 + 2 = **258**.
- **`*a`**: the pattern gives us *references* to the bytes. `*` means "the value itself".

### Security lesson — exact sizes or reject (threat T3)

Peers are strangers. A malicious one can send an ID with the wrong amount of data:

| Evil input | Naive code | Ours |
|---|---|---|
| `have` with 3 bytes | reads past the end → crash (or, in C, reads memory it shouldn't) | shape `[a,b,c,d]` doesn't match → `None` |
| `have` with 5 bytes | silently ignores the extra byte; parsers disagree → confusion bugs | `None` |
| `choke` with a payload | ignored | `None` (choke must be empty) |
| ID 99 | undefined behaviour / crash | `_ => None` |

Rule: **the protocol says the exact size. Anything else is rejected, never guessed at.**
We never index with `payload[0]`. The pattern match *proves* the length first.

---

## Task 4 — ex03 bitfield (`learn/src/ex03_bitfield.rs`)

**Torrent idea:** when you connect, a peer tells you which pieces it has as a
**bitfield**: one bit per piece, 1 = "have it", 0 = "don't". 8 pieces fit in one byte.
The *highest* bit of byte 0 is piece 0:

```
byte 0:  1 1 0 0 0 0 0 0    byte 1:  0 1 0 0 0 0 0 0
piece:   0 1 2 3 4 5 6 7             8 9 · · · · · ·   ← 6 spare bits (10 pieces)
```
So this peer has pieces 0, 1 and 9.

### Rust you learned

- **`struct`**: a bundle of named fields (like a form with boxes):
  `struct Bitfield { bytes: Vec<u8>, num_pieces: usize }`.
  The fields have no `pub`, so **outside code can't touch them directly.**
  It must go through our methods, which do the safety checks. This is **encapsulation**.
- **`Vec<u8>`**: a growable list of bytes that *owns* its data.
  `vec![0; n]` means "n zeros".
- **`usize`**: an unsigned number sized for counting and indexing in memory.
- **`Self`** inside `impl Bitfield` just means `Bitfield`.
- **`&self` vs `&mut self`**:
  - `has(&self)` → *read-only* borrow: "let me look".
  - `set(&mut self)` → *mutable* borrow: "let me change it".
  - Rust enforces that you need `let mut bf` to call `set`. Nothing changes by surprise.
- **`.get(i)` / `.get_mut(i)`** return `Option`: `Some(item)` if `i` is in range,
  `None` if not. **No crash possible.** (`bytes[i]` would crash on a bad `i`, and our
  lint bans it.)
- **Bit tricks**:
  - `byte >> bit` slides the bits right; `& 1` keeps only the lowest one → "is this bit on?"
  - `*byte |= 1 << bit` → switch that one bit on, leaving the others alone.
  - `count_ones()` → how many 1-bits in a byte.
- **Iterators + closures**: `bytes.iter().map(|b| b.count_ones() as usize).sum()`
  reads as "for each byte, count its ones, add them all up". `|b| ...` is a
  **closure**, a tiny unnamed function.
- **Ownership**: `from_bytes(bytes: Vec<u8>, ...)` *takes* the Vec. The caller hands
  it over, and no copy is made. (More on this in Task 5.)

### Security lesson — never trust an index or a length (threat T3)

| Evil input | Naive code | Ours |
|---|---|---|
| "do you have piece 18 quintillion?" (`usize::MAX`) | `bytes[huge]` → **crash** | range check + `.get()` → `false` |
| bitfield with too few / too many bytes | reads past the end, or garbage state | wrong length → `None` |
| spare bits set to 1 | peer "has" pieces that don't exist → later code may try to fetch piece #12 of a 10-piece torrent | rejected (BEP-3 says spare bits must be 0) |

The spare-bit check: count *all* 1-bits, then count only the 1-bits for real pieces
(0 up to `num_pieces`). If they differ, some spare bit was on → reject.

---

## Task 5 — ex04 ownership and borrowing (`learn/src/ex04_ownership.rs`)

**The big Rust idea.** Every piece of data has exactly **one owner**. When the owner
goes away, the data is freed automatically. No garbage collector, no manual `free()`.

Think of a **library book**:

| Rust | Book analogy | Syntax |
|---|---|---|
| **Own** | you bought the book; it's yours to scribble in or throw away | `String`, `Vec<u64>` |
| **Move** | you *give* the book to a friend; you don't have it any more | `normalize(owned)` |
| **Borrow** | you lend it; friend can read it, then gives it back | `&names`, `&[u64]` |
| **Mutable borrow** | you lend it *and* let them write in it (only one person at a time) | `&mut x` |

Rules the compiler enforces:
1. One owner at a time.
2. Either **many readers** (`&`) **or one writer** (`&mut`), never both at once.
3. A borrow can't outlive the thing it borrows.

These rules kill whole families of C/C++ bugs at compile time:
*use-after-free*, *double free*, *data races*. Those bugs are how many real
torrent clients got hacked.

### We watched the compiler catch a use-after-move

We temporarily added `println!("{owned}")` after `normalize(owned)`:
```
error[E0382]: borrow of moved value: `owned`
75 |         let result = normalize(owned);
   |                                ----- value moved here
78 |         println!("{owned}");
   |                    ^^^^^ value borrowed here after move
```
In C this would compile and read freed memory. Rust refuses to build it.

### Rust you learned

- **`&[u64]`**: borrow a list of numbers (read-only). The caller keeps ownership.
- **`String` vs `&str`**: `String` is an *owned* text you can grow/change;
  `&str` is a *borrowed view* of some text. `longest_name` returns `&str` that
  points *into the caller's* `Vec<String>`. No copying.
- **`mut name: String`**: we own it now, so we're allowed to change it in place.
- **`try_fold`**: like a running total, but it **stops early** if a step returns `None`.
  `acc.checked_add(len)` = add, or `None` on overflow.
- **`max_by_key(|n| n.len())`**: pick the item with the biggest length.
- **`.map(String::as_str)`**: turn `Option<&String>` into `Option<&str>`.
- **`HashSet`**: a collection with no duplicates. `insert` returns `false` if the
  item was already there. We use that to spot repeats.

### Security lessons

**T14 — sizes add up.** A torrent lists many files. A hostile one can list
`[u64::MAX, 1]`: each size alone is "valid", but the **total overflows**. Code that
trusts the total might allocate the wrong amount or write to the wrong offset.
`try_fold` + `checked_add` catches it.

**T2 — Windows ignores case.** On Windows, `README.TXT` and `Readme.txt` are the **same
file**. A torrent listing both makes the second download **overwrite** the first. An
attacker could use that to replace a harmless file with a malicious one *after* you've
checked it. We lowercase every name into a `HashSet`; a repeat = collision = reject.

(Note: real Windows case rules are a bit different from Rust's `to_lowercase` for some
non-English letters. The real engine will handle that properly in Phase 4; this is
the idea.)

---

## Task 6 — ex05 results and errors (`learn/src/ex05_results.rs`)

**Torrent idea:** a **tracker** is a server that tells you "here are some peers".
Each peer is an address: an **IP** (which computer) plus a **port** (which door
on that computer), like `10.0.0.5:6881`. Trackers usually send them packed as
**6 bytes each** (BEP-23): 4 bytes of IP + 2 bytes of port.

### Rust you learned

- **`Result<T, E>`**: like `Option`, but the failure says **why**:
  - `Ok(6881)` → success, here's the value
  - `Err(PeerAddrError::PortZero)` → failed, and this is the reason
- **Our own error enum** `PeerAddrError { MissingColon, BadIp, BadPort, ... }`:
  every way parsing can fail has a name. The caller can `match` on it.
- **`?` (the question mark)**: "if this is an `Err`, **return it right now**;
  otherwise unwrap the `Ok` and keep going". It turns this:
  ```rust
  let port = match parse_port(p) { Ok(v) => v, Err(e) => return Err(e) };
  ```
  into `let port = parse_port(p)?;`. Errors "bubble up" to the caller. **No crash, no exceptions.**
- **`.map_err(|_| PeerAddrError::BadPort)`**: swap the library's error for ours.
- **`.ok_or(PeerAddrError::MissingColon)`**: turn an `Option` into a `Result`
  (`None` → that error).
- **`s.parse()`**: turn text into a number / IP. Rust figures out *which* type from
  the annotation (`let port: u16 = ...`).
- **`rsplit_once(':')`**: split at the *last* colon → `Some(("10.0.0.5", "6881"))`.
- **`u16`**: 0 to 65 535, exactly the range of a port. So `"70000"` fails to parse
  *automatically*. The type does the checking.
- **`const MAX_PEERS: usize = 200`**: a fixed value, named so the limit is obvious.
- **`Vec::with_capacity(count)`**: reserve space up front (safe, because `count ≤ 200`).
- **`as_chunks::<6>()`**: split bytes into `[u8; 6]` arrays. Clippy suggested this over
  our first version (`chunks_exact(6)` + a pattern check), because now **the type itself**
  guarantees each chunk is exactly 6 bytes. The shape check can't be forgotten.

### Security lesson — hostile trackers (threat T7)

| Evil tracker sends | Naive code | Ours |
|---|---|---|
| 5 bytes (not a multiple of 6) | reads a half peer / past the end | `BadCompactLength` |
| 10 million peers | allocates huge memory, dials millions of IPs → your PC becomes a **DDoS cannon** against a victim | `TooManyPeers` (cap 200) |
| port 0 | tries to connect to an invalid port | `PortZero` |
| `999.0.0.1` | undefined behaviour in some parsers | `BadIp` |

That middle row is a real attack: a tracker can list a **victim's** IP thousands of times
so every downloader floods it. Caps on how many peers we accept (and later, rate limits
on how fast we dial) stop our client being used as a weapon.

**Phase 0a crash course complete:** functions, `Option`, `match`, enums, slices, structs,
`&self`/`&mut self`, ownership/borrowing, `Result` and `?`. 34 tests.

---

## Task 7 — engine log redaction (`crates/engine/src/redact.rs`)

**First real engine code.** Programs write **logs**: diary lines like
`connected to peer 203.0.113.7` that help debug problems. But logs are dangerous:
- they sit on disk in plain text,
- users paste them into GitHub issues and Discord to get help,
- malware or anyone using the PC can read them.

A log full of peer IPs and torrent names says **exactly what you downloaded and who
you talked to.** That's a privacy leak (threat T8).

**Our rule:** sensitive values are only ever logged through `policy.redact(value)`.
By default it prints `[redacted]`. Only if the user deliberately turns on
**diagnostic mode** does the real value appear.

```rust
let policy = LogPolicy::default();            // diagnostics: false
format!("peer {}", policy.redact(&ip))        // → "peer [redacted]"

let policy = LogPolicy { diagnostics: true }; // user opted in
format!("peer {}", policy.redact(&ip))        // → "peer 203.0.113.7"
```

**Secure by default:** the safe choice is the one you get without doing anything.

### Rust you learned

- **`#[derive(Default)]`**: auto-writes `LogPolicy::default()`. For a `bool`,
  default is `false`, so **privacy is on unless someone switches it off**.
- **`Copy`**: `LogPolicy` is tiny (one bool), so it's copied instead of moved.
  Using it doesn't "give it away" like a `String` would.
- **Traits** = a promise that a type can do something. Like a job skill:
  - `Display` → "can be shown to humans" (what `{}` uses)
  - `Debug` → "can be shown to programmers" (what `{:?}` uses)
  - `impl fmt::Display for Redacted` = "here's how a Redacted shows itself".
  We implemented **both**, so neither `{}` nor `{:?}` can leak the value.
- **Generics `<T>`**: `Redacted<T>` works for *any* type: an IP, a file name, a URL.
  One piece of code, reused for all of them.
- **Trait bounds `T: fmt::Display`**: "Redacted<T> can be Displayed *only if* T itself
  can be". The compiler checks this.
- **`?Sized`**: allows `T` to be something without a fixed size, like `str`, so we
  can redact `"a.iso"` directly.
- **Lifetimes `'a`**: `Redacted<'a, T>` holds a *borrow* (`&'a T`) of the value.
  `'a` is a label that says "this Redacted can't outlive the thing it points at".
  Remember ownership rule 3 from Task 5. This is how Rust writes it down.
  Bonus: no copying the value, so redaction is basically free.
- **`f.write_str(MASK)`**: write our fixed text instead of the real value.

### Why wrap values instead of "just being careful"?

"Remember not to log IPs" fails the first time someone is tired. A **wrapper type**
makes the safe path the easy path, and later we can search the code for any log line
that prints an IP *without* `redact`. A rule the code enforces beats a rule people
must remember.

---

## Task 8 — supply chain and CI (`deny.toml`, `.github/workflows/ci.yml`)

**The problem: we don't write all our code.** A Rust project pulls in libraries
(**crates**) written by strangers, and those pull in *more* libraries. A medium project
can end up with 300+ of them. **Every single one runs with your full permissions.**

That's the **supply chain** (threat T16). Real attacks that happened elsewhere:
- a popular package was taken over and a new version stole crypto wallets,
- a maintainer deleted a tiny package and broke thousands of builds,
- typo-squatting: `reqwests` instead of `reqwest`, and you never notice the `s`.

### `deny.toml` — the doorman for libraries

`cargo deny check` inspects every dependency and refuses:

| Section | Checks | Why |
|---|---|---|
| `[advisories]` | known security holes; `yanked = "deny"` blocks versions the author pulled | a library with a public exploit shouldn't ship in our app |
| `[licenses]` | only MIT / Apache-2.0 / BSD-3 / ISC / Zlib / Unicode-3.0 | some licences force us to publish our source or add legal duties |
| `[bans]` | `wildcards = "deny"` | a wildcard version (`"*"`) means "any future version, sight unseen" — that's how a hijacked package gets in |
| `[sources]` | only crates.io | no random git repos, which can be rewritten silently |

Current result: `advisories ok, bans ok, licenses ok, sources ok` (we have no
dependencies yet — this is the doorman **hired before** the guests arrive).

### `.github/workflows/ci.yml` — the robot reviewer

**CI** = Continuous Integration: GitHub runs checks automatically on every push.
Three jobs, in parallel:

1. **rust** (on Windows, our target OS): `cargo fmt --check` → `cargo clippy -D warnings`
   → `cargo test`. Same three commands we run by hand.
2. **deny**: cargo-deny, as above.
3. **secrets**: **gitleaks** scans the *whole history* for passwords and API keys.
   Committing a secret and deleting it later doesn't help — git keeps every version.
   The only real fix is never committing it, so we check every push.

```yaml
permissions:
  contents: read
```
**Least privilege.** By default a CI job gets a token that can *write* to your repo. If
a dependency of a build step were malicious, it could push commits. We cut it down to
read-only: CI can look at the code and nothing else.

### Why CI matters even when you work alone

A check you must remember to run is a check you'll skip when tired or in a hurry.
CI runs the same checks the same way, every time, and a red ✗ appears on GitHub for
anyone to see. **Discipline you don't have to supply is the only kind that lasts.**

(Stretch goal from the spec: pin each `uses:` to an exact commit ID rather than a tag
like `@v4`, since a tag can be moved to point at different code.)

---

## Task 9 — threat tracker and the phase gate (`docs/THREAT_MODEL.md`)

**Idea:** a security plan nobody checks is just a wish. So we keep a one-page table:
16 threats, and for each one, *what actually exists today*.

| Status | Meaning |
|---|---|
| `planned` | Written in the spec, no code |
| `partial` | Part of the defence exists |
| `implemented` | Code exists |
| `tested` | Code exists **and** a test proves it |
| `reviewed` | Tested, plus a deliberate re-read against the spec |

Today: **T16 implemented** (supply chain), **T8 partial** (log redaction), the other 14
`planned`. Being honest about "planned" is the point — a tracker that says everything is
fine is worse than no tracker.

### The trick that makes it verifiable

Tests are **named after the threat** they defend: `t3_rejects_have_with_wrong_length`,
`t7_rejects_too_many_peers`, `t14_offset_overflow_is_caught`. So the claim in the table
can be checked by a command rather than trusted:

```
cargo test t7_        → runs every T7 test
```
Right now 16 of our 37 tests are named after a threat.

### Phase gate (spec §7)

A **gate** means: don't start the next phase until these are all true.

| Check | Result |
|---|---|
| `cargo build --workspace` | clean |
| `cargo test --workspace` | 37 passed, 0 failed |
| `cargo clippy -D warnings` | clean |
| `cargo fmt --check` | clean |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok |
| Threats reviewed | T8 partial, T16 implemented, nothing newly open |
| Explained to you | yes, one section per task in this file |

Gates stop the classic failure: rushing forward on a shaky base and paying for it
five times over later.

---

# ✅ Phase 0 complete

**What exists now:** a locked-down Rust workspace (no `unsafe`, no `unwrap`, no raw
indexing), a pinned toolchain, supply-chain checks, CI on every push, privacy-safe
logging, a threat tracker, and 37 tests.

**What you learned:** functions, `Option`, `match`, enums, slice patterns, structs,
`&self` vs `&mut self`, **ownership and borrowing**, `Result` and `?`, traits,
generics and lifetimes — every one of them through a real torrent problem.

**Next, Phase 1:** the bencode parser — the code that reads a `.torrent` file. It is
the single most attacker-exposed part of the app, because the file comes from a
stranger before we have checked anything at all. That is threat T1.
