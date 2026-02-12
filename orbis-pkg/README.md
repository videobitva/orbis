# orbis-pkg

Rust library for parsing and extracting PlayStation 4 PKG files.

## Features

- Parse PKG headers and entry tables
- Extract PKG metadata (content ID, title ID, content type, flags)
- Decrypt PKG entries

## Usage

```rust
use orbis_pkg::Pkg;

// Open a PKG file
let pkg = Pkg::open("game.pkg")?;

// Access header information
let header = pkg.header();
println!("Content ID: {}", header.content_id());
println!("Title ID: {}", header.content_id().title_id());

// Iterate over entries
for result in pkg.entries() {
    let (index, entry) = result?;
    let data = pkg.entry_data(&entry)?;
    // Process entry data
}

// Access PFS image for game content
if let Some(pfs_image) = pkg.pfs_image() {
    let pfs = orbis_pfs::open_slice(pfs_image.data, Some(pfs_image.ekpfs))?;
    // Extract PFS contents
}
```
