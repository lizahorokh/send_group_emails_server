# Background and Motivation
The `server_setup` binary needs to reuse the logic that already exists in the sibling `fetch_data` and `verify_signature` projects.  Right now all three projects are independent binary crates, so their code cannot be easily shared.  We want to expose the reusable logic from `fetch_data` and `verify_signature` as libraries and make `server_setup` depend on them so we avoid code duplication and keep a single source of truth.

# Key Challenges and Analysis
1. **Binary-only crates** – `fetch_data` and `verify_signature` currently expose only `main.rs`.  A Cargo package cannot be used as a dependency unless it also provides a library target.
2. **No top-level workspace** – Each project builds in isolation.  Introducing a workspace will make cross-crate paths simple and give us one-shot builds/tests.
3. **Refactor without breaking binaries** – We must move logic into `lib.rs` while keeping the existing command-line binaries working.
4. **Update `server_setup` imports** – After the libraries exist, we need to replace any duplicated code with proper `use fetch_data::...` or `use verify_signature::...` statements.
5. **Testing** – Add/adjust tests to make sure the refactor did not change behaviour.

# High-level Task Breakdown
| # | Task | Role | Success Criteria |
|---|------|------|------------------|
|1|Draft refactor & dependency plan (this doc)|Planner|Document created & agreed ✔|
|2|Convert `fetch_data` into a library crate (steps below)|Executor|`cargo test && cargo build -p fetch_data` passes|
|3|Convert `verify_signature` into a library crate in the same way|Executor|`cargo build -p verify_signature` passes|
|4|Create a top-level Cargo workspace including `fetch_data`, `verify_signature`, `server_setup` (and optionally `database`)|Executor|`cargo build` from repo root builds all members|
|5|Add path dependencies in `server_setup/Cargo.toml` for the two new libraries|Executor|`server_setup` compiles with `cargo build -p server_setup`|
|6|Refactor `server_setup` code to call into the new libraries instead of duplicating logic|Executor|Build succeeds and manual smoke-test runs|
|7|Write integration tests exercising the end-to-end flow (fetch → verify → setup)|Executor|`cargo test` green in workspace|
|8|Final cross-check & wrap-up|Planner|All boxes ticked, tests green, user acceptance|

# Project Status Board
- [x] Task 1: Plan documented
- [ ] Task 2: Convert `fetch_data` to lib crate
- [ ] Task 3: Convert `verify_signature` to lib crate
- [ ] Task 4: Create workspace
- [ ] Task 5: Add deps to `server_setup`
- [ ] Task 6: Refactor `server_setup`
- [ ] Task 7: Integration tests
- [ ] Task 8: Review & finalise

# Current Status / Progress Tracking
_Not started – waiting for Executor to pick up Task 2._

# Executor's Feedback or Assistance Requests
- Provided one-line PowerShell command with JSON body for user request.
- Clarified correct JSON quoting; advised user to avoid embedding unescaped braces in string.
- Provided PowerShell command with `group_signature` as escaped JSON string within JSON body.

# Lessons
_(empty)_

## Detailed Instructions for Tasks 2 & 3

1. **Add a library target**
   • In each project directory (`fetch_data/`, `verify_signature/`) create `src/lib.rs`.

2. **Move reusable code**
   • Identify pure functions/structs/enums in `src/main.rs` that implement core logic (e.g. HTTP fetch, JSON parsing, proof verification).
   • Cut-and-paste them into `lib.rs` and mark `pub` as needed so other crates can call them.

3. **Expose a clean API**
   • Define `pub mod` blocks or `pub fn` wrappers in `lib.rs`.
   • Re-export with `pub use` if necessary so that external code can simply `use fetch_data::get_emails();` etc.

4. **Slim down `main.rs`**
   • Replace the old code with thin CLI glue that calls into the new library functions.
   • Keep argument parsing / logging in `main.rs`; move business logic to `lib.rs`.

5. **Update Cargo.toml**
   • Ensure `[lib]` section exists (Cargo adds it implicitly, but you can be explicit):
     ```toml
     [lib]
     name = "fetch_data"
     path = "src/lib.rs"
     crate-type = ["rlib"]
     ```
   • Keep the existing `[[bin]]` section (or default) so `cargo run -p fetch_data` still works.

6. **Add unit tests**
   • In `lib.rs` or `tests/` directory add tests for the newly extracted functions.

7. **Verify build**
   • Run `cargo build -p fetch_data` and `cargo test -p fetch_data`.
   • Repeat for `verify_signature`.

These steps convert the crates into dual-purpose library + binary packages, making them importable from `server_setup` while preserving CLI functionality.

# Glossary / Notes
• **`pub mod`** – Declares a public module.  A _module_ groups items (functions, structs, sub-modules, etc.) and controls their visibility.  Marking it `pub` means external crates can import the module itself (e.g. `use fetch_data::parser::Email;`).  Inside a module, items still need their own visibility modifiers (`pub`/private).

• **`pub fn`** – Declares a public function item.  This exposes the specific function directly to other modules/crates.  You place it either in the crate root (`lib.rs`) or inside a module.  `pub fn` does not create a namespace; it is a single callable symbol.

Difference: `pub mod` opens a namespace, whereas `pub fn` exposes one callable inside whatever namespace it already resides in.

• **Serialising `Vec<String>` to JSON** – In Rust use `serde` + `serde_json`:
  ```rust
  use serde_json; // add to Cargo.toml: serde = { version = "1", features = ["derive"] } and serde_json = "1"
  
  let emails: Vec<String> = vec!["alice@example.com".into(), "bob@example.com".into()];
  let json = serde_json::to_string(&emails)?; // -> "[\"alice@example.com\",\"bob@example.com\"]"
  ```
  Note that `Vec<str>` is invalid (because `str` is unsized).  Use `Vec<String>` or `Vec<&str>`.

• **Join a `Vec<String>` → `String`** – Use `join` (requires `&str` slices):
  ```rust
  let words = vec!["foo".to_string(), "bar".to_string()];
  let csv = words.join(", "); // "foo, bar"
  ```
  Alternative: `let single = words.concat();` (concatenates with no separator) or iterate and `push_str` into a `String` buffer.

- Fixed server_setup Email struct: group_signature now String not Json to match API and verification logic.

• **Calling a blocking/synchronous function from async code** – If the function performs I/O or sleeps, calling it directly inside an `async fn` will block the executor's worker thread.  This stalls the entire runtime: no other tasks on that thread can make progress until the call returns.  In Tokio this can also trigger a panic if the sync function internally creates/drops its own Tokio runtime.  Best-practice options:
  1. Replace the sync API with an async equivalent and `await` it.
  2. Wrap the sync call in `tokio::task::spawn_blocking` (or `tokio::task::spawn`) so it runs on a dedicated thread pool, keeping the async scheduler free.