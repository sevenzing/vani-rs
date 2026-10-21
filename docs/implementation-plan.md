# vani-rs Implementation Plan

**Status:** Approved for implementation  
**Project path:** `/home/ferry/projects/vani-rs`  
**Repository:** public GitHub repository `sevenzing/vani-rs` (not yet created)

## Objective

Build a safe, maintainable Rust CLI that searches deterministic Ethereum key candidates for an address matching a required user-supplied regex. The first real search for an address beginning with `0x012345` is a separate operation and must not start without the user's explicit authorization.

## Product requirements

### CLI and matching

- Require `--pattern` / `-n`; there is no default pattern.
- Provide short aliases for CLI options where they remain unambiguous: `--seed` / `-s`, `--seed-file` / `-f`, `--pattern` / `-n`, `--threads` / `-t`, `--iter` / `-i`, and `--case-insensitive` / `-c`. Document all long and short forms in `--help` and README. Keep stdin selection explicit if a short alias would collide or make the interface less clear.
- Use Rust's `regex` syntax. Compile the regex once before the search.
- Strip one optional leading `0x` from the supplied pattern. Match against the 40 hexadecimal characters of the EIP-55 address, without its display prefix.
- If the pattern does not begin with `^`, add a start anchor. If it does not end with `$`, add an end anchor. Thus `012345.*` means the address begins with `012345`; explicit anchors allow narrower matching.
- Matching is case-sensitive by default. `--case-insensitive` / `-c` enables the regex engine's Unicode-aware case-insensitive mode (e.g. via an inline `(?i)` flag around the normalized expression); do not lowercase raw regex syntax, which can change metacharacter semantics such as `\\S`.
- Support `--threads N`; default to all logical CPUs. Reject zero threads and invalid patterns with useful errors.

### Candidate derivation

- Generate a new seed from 32 bytes supplied by the operating system's cryptographically secure random source.
- Encode seed bytes as Base64 for `seed.secret` and seed text accepted by CLI inputs.
- Accept a seed from `--seed` / `-s <BASE64>`, `--seed-file` / `-f <PATH>`, or stdin. Accept any decoded seed length; warn when it is shorter than 32 bytes. Avoid claiming that length proves entropy.
- For every seed and iteration, deterministically derive a valid secp256k1 scalar with HMAC-SHA-256, an unambiguous domain-separated iteration encoding, and rejection sampling. Never use the iteration number itself or simple concatenation as a private key. Handle rejected scalar values by deriving another block with an explicit counter.
- Use maintained, established Rust cryptographic libraries for secp256k1, Keccak-256, secure randomness, and zeroization; verify crate suitability and APIs during implementation.
- `--iter` / `-i N` sets the first candidate index; index zero is the default. Fixed seed and index must reproduce the same candidate.

### Output, secret storage, and resume

- Store run data under the project-root `data/` directory, excluded from Git.
- Create timestamped UTC directories named like `YYYY-MM-DDTHH-MM-SSZ-result`, adding a random suffix on collision. Directory permissions must be `0700`.
- Store `seed.secret` as Base64 with permissions `0600`. Never overwrite existing secret files.
- When launched from an existing result directory, reuse its seed and directory; do not replace the seed. If a key file already exists, create a uniquely suffixed key filename instead of overwriting it.
- With a seed supplied directly or from an external seed file/stdin, create a new result directory and copy the selected seed there. A seed file in the current result directory is the existing-run case.
- On a match, write `0x` plus exactly 64 hexadecimal characters to `private-key.secret` (or a unique suffixed filename on collision), with `0600` permissions. Use create-new semantics and ensure restrictive permissions are effective before secret bytes are written.
- Never print the full seed or private key, and never put them into logs, Git, or progress documentation. At startup, show only masked previews of the seed and key material, revealing the first and last four characters with the middle replaced by `*`.
- Apply best-effort zeroization to in-memory seed and private-key buffers.
- On Ctrl-C, stop cleanly, print final statistics, and print a safe resume command using `--seed-file <path> --iter N` and all non-default search settings. For parallel search, `N` must be a safe lower bound that cannot skip any unexamined iteration; some already-completed work may be repeated. Persisting a separate progress checkpoint is out of scope for the first version.

### Progress and estimates

- Refresh one terminal line once per second; do not flood terminal output.
- Report elapsed time, completed candidates, average/current rate, approximate probability of a match by the current iteration, and estimated remaining iterations and remaining time until the 50% success point where supportable. If the estimated 50% point has already been passed, report zero remaining iterations/time.
- Limit probability estimation to patterns that can be safely recognized as simple hexadecimal prefixes with arbitrary suffixes. Label estimates approximate. For other expressions, report that estimation is unavailable rather than spending significant CPU or presenting false precision. The 50% display must distinguish total expected iterations from remaining iterations at the current count; ETA uses the current/average observed rate and reports time remaining, not only total runtime.
- Print final statistics both on match and on Ctrl-C.

## Architecture direction

Keep a small CLI entry point and separate the core responsibilities so they can be tested without starting an unbounded search:

1. **Configuration and pattern module**: parse/validate options, normalize optional `0x`, add implicit anchors, and compile the matcher once.
2. **Candidate module**: derive candidate scalars and EIP-55 addresses from seed plus iteration; own cryptographic correctness and deterministic test vectors.
3. **Search module**: allocate unique iterations to workers, aggregate batched counts, coordinate cancellation, and expose a resume-safe completed watermark.
4. **Progress/estimation module**: calculate bounded estimates and render the once-per-second terminal status.
5. **Result storage module**: create private directories/files without overwrites, store Base64 seed, and persist matched key safely.
6. **CLI orchestration**: connect validated options and modules, handle Ctrl-C, print masked previews and safe resume commands.

Prefer deep modules with small interfaces and strong types; parse user input into validated types at the boundary. Avoid needless abstractions for dependencies that do not vary.

## Delivery milestones

1. Initialize the crate, English-only project docs, MIT license, `.gitignore`, formatter/linter settings, and CI.
2. Implement and test seed parsing, HMAC candidate derivation, secp256k1 validation, Ethereum address derivation, and EIP-55 formatting.
3. Implement regex normalization/matching and conservative prefix-only probability estimates.
4. Implement multi-threaded search, one-line progress, statistics, Ctrl-C handling, and safe resume-point calculation.
5. Implement secure result-directory/file creation, README usage/security guidance, and end-to-end tests.
6. Run formatting, tests, Clippy, and CI-equivalent checks; review the diff and verify no secret values are emitted or tracked.
7. After implementation review and owner approval, create/publish the public GitHub repository if not already created. Do not start a long vanity search until separately authorized.

## Acceptance criteria

- The known Ethereum vector for private key `1` yields `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf`.
- Same seed and iteration always produce the same valid private key/address; distinct iteration indices are encoded unambiguously.
- Regex examples work, including optional `0x`, implicit anchors, explicit anchors, and case-insensitive mode.
- A bounded integration test finds a known pattern using a fixed test seed/index without launching a long search.
- Parallel workers do not duplicate assigned iterations during a run; interruption's resume point cannot skip unexamined iterations.
- Result directory and secret files use the required permissions, and collision handling never overwrites existing data.
- Captured stdout/stderr and logs never contain the full seed or private key.
- `cargo fmt --check`, `cargo test`, and `cargo clippy --all-targets --all-features -- -D warnings` pass; CI runs the appropriate checks.
- The project contains a clear README, MIT license, and GitHub Actions CI configuration.
- No long-running real vanity search is performed as part of implementation or tests.

## Decisions still worth verifying during implementation

- Select and verify the specific maintained Rust crates and versions; cryptographic correctness must be covered by published known-answer vectors.
- Treat Unix permission enforcement as a platform-specific requirement for the VPS target; fail closed if secure file creation cannot be guaranteed.
- Test Ctrl-C and resume-watermark behavior under races, including a worker holding a lower iteration while others finish higher indices.
