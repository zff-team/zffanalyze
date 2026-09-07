# zffanalyze
[![crate][crate-image]][crate-link]
![GPL3.0-License][license-image]
![Rust Version][rustc-image]
[![website][website-image]][website-link]
[![zffanalyze](https://snapcraft.io/zffanalyze/badge.svg)](https://snapcraft.io/zffanalyze)
[![zffanalyze](https://snapcraft.io/zffanalyze/trending.svg?name=0)](https://snapcraft.io/zffanalyze)

```zffanalyze``` is a command line utility to analyze zff images.

# Installation

## Install via snapd

```bash
sudo snap install zffanalyze
```

## Install via cargo

```bash
$ cargo install zffanalyze --locked
```

## build yourself

### Prerequisites
First, you need Rust 1.89.0 or newer. [Install Rust and Cargo](https://rustup.rs/) to build or install ```zffanalyze```.

After that you still need the gcc, which you can install as follows (depends on the distribution):
###### Debian/Ubuntu
```bash
$ sudo apt-get install gcc
```
###### Fedora
```bash
$ sudo dnf install gcc
```

### build via cargo

Then you can easily build this tool yourself by using cargo:
```bash
[/home/ph0llux/projects/zffanalyze] $ cargo build --release --locked
```

# Usage

To show the metadata of the given zff file, execute:
```bash
zffanalyze -i <YOUR_ZFF_IMAGE.z01>
```

If you want to perform an integrity check, you can simply execute:
```bash
zffanalyze -i <YOUR_ZFF_IMAGE.z01> -c
```

To check data integrity and verify all stored hash signatures with an existing base64 Ed25519 public key, execute:
```bash
zffanalyze -i <YOUR_ZFF_IMAGE.z01> -k "c9IvuVj4lnGVSXR5Azx8SAyqQBpeHMKpB/4v8/Cj4Ew="
```

Supply **all segments** of the same container, in any order, for example:

```bash
zffanalyze -i image.z01 image.z02 image.z03 -c
```

`-c` checks chunk checksums and recomputes every stored object/file data hash.
`-k` performs those integrity checks and verifies every stored hash signature.
Verification fails if data hashes are missing, data is corrupt, segments are
missing or duplicated, acquisition errors are recorded, or objects cannot be
decrypted. With `-k`, missing or invalid signatures also cause failure. Virtual objects can be inspected, but verification rejects
them because they do not provide independent data hashes. A container containing
virtual objects therefore cannot receive a successful whole-container verification.

For encrypted objects, supply `-p OBJECT:PASSWORD` (repeat for multiple objects)
or enter the password interactively. `-I` skips password prompts and displays
encrypted metadata; it does not permit verification to skip encrypted objects.
Incorrect supplied passwords are errors. Command-line passwords may be visible
in process listings; prefer the interactive prompt.

The default output is TOML. Use `-f json` or `-f json-pretty` for JSON, `-v` to
include chunk maps and chunk headers, and `-vv` to include logical file metadata.
Metadata output omits decrypted encryption keys.

Exit status `0` means output or complete verification succeeded, `1` means an
input, output, or verification error, and `2` means invalid command-line usage.
Diagnostics go to stderr; metadata goes to stdout.

### Development checks

Run `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`,
and `cargo test --locked`. On machines configured with the isolated builder,
use `.scripts/test_and_verify.sh` and `.scripts/build_and_release.sh` instead.
Tests generate containers with zff 3.0.0 and check the CLI's output and exit status.

### License

```zffanalyze``` is open source and licensed under GPL-3.0-only; see [LICENSE](LICENSE).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, shall be licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/zffanalyze
[crate-link]: https://crates.io/crates/zffanalyze
[license-image]: https://img.shields.io/crates/l/zffanalyze
[rustc-image]: https://img.shields.io/badge/rustc-1.89.0+-blue.svg
[website-image]: https://img.shields.io/website-up-down-green-red/http/zff.dev.svg
[website-link]: https://zff.dev
