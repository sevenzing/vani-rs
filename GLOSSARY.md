# vani-rs Domain Glossary

This glossary defines the domain language for generating Ethereum addresses from deterministic candidate keys and searching those addresses for a user-supplied pattern.

## Search concepts

**Seed**:
Secret input that, together with an iteration number, identifies a deterministic candidate private key. A seed is not itself an Ethereum private key.
_Avoid_: Master private key

**Iteration**:
A non-negative index identifying one candidate in a search. Given the same seed and iteration, candidate derivation produces the same private key.
_Avoid_: Attempt number (ambiguous with completed work)

**Candidate private key**:
A valid secp256k1 private scalar derived for one seed and iteration.
_Avoid_: Seed, search index

**Candidate address**:
The Ethereum address derived from a candidate private key and represented using EIP-55 checksum casing.
_Avoid_: Public key (an Ethereum address is not the public key)

**Pattern**:
A regular expression matched against the candidate address's 40 hexadecimal characters, excluding the `0x` display prefix.
_Avoid_: Prefix (patterns may describe more than a prefix)

**Search run**:
One execution that examines candidates for a seed and pattern under configured runtime parameters.
_Avoid_: Session (ambiguous with an application session)

**Result directory**:
A private local directory associated with a search run, containing its seed and, when found, its private-key result.
_Avoid_: Checkpoint (the directory does not necessarily contain progress state)

**Resume point**:
The lowest iteration from which restarting a stopped parallel search is guaranteed not to skip an unexamined candidate. Restarting there may repeat work.
_Avoid_: Checkpoint (progress state is not persisted in the first version)
