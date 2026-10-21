# vani-rs

A Rust CLI that searches deterministic Ethereum key candidates for an address matching a
regular expression. Unix only (secrets are stored with modes `0700`/`0600`).

> **Security notice:** this tool handles private keys. It is unaudited. Review the code, run it on
> a trusted machine, and treat everything under `data/` as secret.

## Usage

```sh
cargo build --release
./target/release/vani-rs --pattern '0x012345.*'
```

| Long                 | Short | Meaning                                                                  |
| -------------------- | ----- | ------------------------------------------------------------------------ |
| `--pattern <REGEX>`  | `-n`  | Required address regex                                                   |
| `--seed <BASE64>`    | `-s`  | Base64 seed                                                              |
| `--seed-file <PATH>` | `-f`  | Seed from a Base64 file                                                  |
| `--stdin`            |       | Seed from standard input                                                 |
| `--threads <N>`      | `-t`  | Worker threads, at least 1 (default: all logical CPUs)                   |
| `--iter <N>`         | `-i`  | First iteration (default 0)                                              |
| `--case-insensitive` | `-c`  | Case-insensitive matching                                                |
| `--data-dir <DIR>`   |       | Result directory root (default `data`)                                   |

`--seed`, `--seed-file`, and `--stdin` are mutually exclusive. Seed source precedence:

1. An explicit `--seed`, `--seed-file`, or `--stdin` always wins; the current directory is not
   consulted.
2. Otherwise, if the current directory is a result directory (named
   `YYYY-MM-DDTHH-MM-SSZ-result[-xxxxxxxx]`, mode `0700`) containing `seed.secret`, that seed and
   directory are reused.
3. Otherwise a fresh 32-byte seed is drawn from the OS CSPRNG.

Only a `seed.secret` inside such a result directory (found by step 2 or passed with
`--seed-file`) resumes that directory. Any other explicit seed is copied into a new result
directory. A result directory with permissions looser than `0700` is rejected. Seeds of any length are accepted, with a warning below 32 bytes
(length does not prove entropy).

### Pattern semantics

- Matched against the 40 hex characters of the EIP-55 address, without `0x`.
- One leading `0x` is removed. A missing `^` or `$` is added, so `012345.*` means "starts with
  `012345`" and `012345` alone means the whole address equals it (which is impossible).
  The body is wrapped as `^(?:body)$`, so alternation like `a.*|b.*` is anchored as a whole.
- Rust `regex` syntax; case-sensitive by default (EIP-55 casing counts). With `-c` the regex
  engine's own `(?i)` mode is used; the pattern text is never lowercased.

### Examples

```sh
vani-rs -n '0x012345.*'            # prefix 012345, checksum case matters
vani-rs -n '0xdead.*beef' -c       # prefix dead, suffix beef, any case
vani-rs -n '.*0000$' -t 8          # suffix 0000
```

## Candidate derivation

For seed `S` and iteration `i` (u64), the private key is the first valid output of
`HMAC-SHA-256(S, "vani-rs/candidate/v1" || i as 8 bytes big-endian || counter as 4 bytes big-endian)`
for counter `0, 1, 2, ...`. A block is rejected if it is zero or not below the secp256k1 order
(no modulo bias). The address is the last 20 bytes of Keccak-256 of the uncompressed public key,
formatted with EIP-55. See `docs/adr/0001-deterministic-candidate-derivation.md`.

Libraries: `k256`, `sha3`, `hmac`, `sha2`, `getrandom`, `zeroize`, `regex`, `clap`, `ctrlc`.
Known-answer tests cover private key `1` (`0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf`), Keccak-256,
EIP-55 vectors, and RFC 4231 HMAC.

## Output and secret storage

Each run writes `data/<UTC timestamp>-result/` (`0700`) containing `seed.secret` (Base64, `0600`).
On a match the key goes to `private-key.secret` as `0x` + 64 hex characters (`0600`), or to a
uniquely suffixed name if that file exists. Files are created with create-new semantics and are
never overwritten. `data/` is git-ignored.

- Running from inside a result directory, or passing its `seed.secret` with `--seed-file`,
  reuses that directory and seed. A seed from any other source is copied into a new directory.
- The program prints only masked previews (first and last 4 characters) of the seed and of the
  first candidate key, never the full values, and the private key only in its file.
  The address is printed on a match.
- In-memory seed and key buffers are zeroized on a best-effort basis; copies inside third-party
  crates, swap, or core dumps are not controlled.

## Progress, estimates, and Ctrl-C

On a terminal, one status line is refreshed every second (elapsed, count, average and current
rate, estimate). Estimates are approximate and offered only for simple hex prefixes followed by `.*` or `.+`
(e.g. `0x012345.*`, `0x012345.+`); other patterns show "estimate unavailable". Letters in a case-sensitive prefix
count as 1/32 each, digits (and any case-insensitive character) as 1/16. The line shows the
probability of a match so far, the total iterations for the 50% point, and the iterations and time
*remaining* to that point at the current count and average rate (zero once it has been passed).
Counts cover the current run only.

On Ctrl-C (or SIGTERM) the program stops, prints final statistics and a resume command:

```text
vani-rs --seed-file /path/data/<dir>/seed.secret --iter N --pattern '...'
```

`N` is a safe lower bound: workers hold disjoint batches, so some iterations above `N` may be
repeated, but none below it is skipped. The whole `u64` iteration range is searchable,
including `u64::MAX`; when it is exhausted the program reports so instead of a resume command. Exit codes: `0` found, `130` interrupted, `2` exhausted,
`1` error.

**Planned:** recording the next iteration in the result directory on failure and Ctrl-C
(see `TODO.md`). Today it is only printed.

## Development

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Tests are bounded and deterministic; no long search runs. CI runs the same checks.

## License

MIT, see `LICENSE`.
