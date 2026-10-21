# TODO

- **Record the next iteration on failure and Ctrl-C.** Persist the safe resume point (the
  `N` printed in the resume command) in the result directory, e.g. as `next-iteration` with
  mode `0600`, written atomically (temp file + rename). Do this on Ctrl-C and on error exits so a
  restart from the result directory can continue without copying the printed command. It must
  remain a conservative lower bound (see "Resume point" in `GLOSSARY.md`); the first version
  only prints it.
- Optional periodic checkpointing of the resume point during long runs.
- Consider SIMD/batched Keccak or a faster secp256k1 backend if throughput matters.
