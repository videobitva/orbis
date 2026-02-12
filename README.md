# Orbis

A Rust library and toolset for working with PlayStation 4 PKG and PFS file formats.

## Building

```bash
cargo build --release
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

## Performance

Although the `orbis-*` crates have not been specifically optimized for performance, they perform well in practice. On a test system (Intel W-3175X, Samsung 990 Pro NVMe, 192 GB DDR4-4000 6-channel), full PKG extraction benchmarks yielded:

| Tool | Min | Avg | Max |
|------|-----|-----|-----|
| `orbis-pkg-util` | 8 s | 18 s | 20 s |
| `shadPKG` | 73 s | 73 s | 75 s |

## Crates

| Crate | Description |
|-------|-------------|
| [orbis-pfs](orbis-pfs/) | Library for reading PFS (PlayStation File System) images |
| [orbis-pkg](orbis-pkg/) | Library for parsing and extracting PS4 PKG files |
| [orbis-pkg-util](orbis-pkg-util/) | Command-line utility for PKG operations |

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
