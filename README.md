[![crates.io](https://img.shields.io/crates/v/orbis-pkg-util)](https://crates.io/crates/orbis-pkg-util)
[![ci](https://github.com/videobitva/orbis/actions/workflows/ci.yml/badge.svg)](https://github.com/videobitva/orbis/actions/workflows/ci.yml)

# Orbis

A Rust library and toolset for working with PlayStation 4 PKG and PFS file formats.

## Install

```bash
cargo install orbis-pkg-util
```

## Building manually

Requires [Rust](https://www.rust-lang.org/tools/install). Compiles on Windows, Linux, and macOS.

```bash
cargo build --release
```

Binaries will be in `target/release/`. To install them into your Cargo bin directory:

```bash
cargo install --path orbis-pkg-util
```

## Usage

Extract a PKG file (output directory defaults to title ID):

```bash
orbis-pkg-util extract game.pkg
```

View PKG metadata:

```bash
orbis-pkg-util metadata game.pkg
```

List PKG entries:

```bash
orbis-pkg-util list game.pkg
```

## Crates

| Crate | Description |
|-------|-------------|
| [orbis-pfs](orbis-pfs/) | Library for reading PFS (PlayStation File System) images |
| [orbis-pkg](orbis-pkg/) | Library for parsing and extracting PS4 PKG files |
| [orbis-pkg-util](orbis-pkg-util/) | Command-line utility for PKG operations |

## Performance

Although the `orbis-*` crates have not been specifically optimized for performance, they perform well in practice. Benchmarked with a ~30 GB Bloodborne PKG (CUSA03173_01) on a test system (Intel W-3175X, Samsung 990 Pro NVMe, 192 GB DDR4-4000 6-channel):

| Tool | Min | Avg | Max |
|------|-----|-----|-----|
| `orbis-pkg-util` | 9 s | 16 s | 23 s |
| `shadPKG` | 73 s | 73 s | 75 s |

## Acknowledgements

- [shadPS4](https://github.com/shadps4-emu/shadPS4) — motivated this project. Its since-removed PKG install code served as the initial reference for understanding PKG and PFS structures.
- [Obliteration](https://github.com/obhq/obliteration) — provided a valuable Rust reference implementation for working with these formats.
- [shadPKG](https://github.com/seregonwar/ShadPKG) — used as a known-good tool for validating and debugging extraction output.
- [PSDevWiki](https://www.psdevwiki.com/) — community-reverse-engineered specifications for the PKG and PFS formats.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
