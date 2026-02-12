# orbis-pfs

Rust library for reading PFS (PlayStation File System) images used in PS4 games.

## Features

- Parse PFS headers and inodes
- Read files and directories from PFS images
- XTS-AES decryption support
- PFSC (compressed PFS) decompression

## Usage

```rust
use orbis_pfs;
use std::io::Cursor;

// Open a PFS image with optional EKPFS key for decryption
let pfs = orbis_pfs::open(Cursor::new(pfs_data), Some(ekpfs_key))?;

// Access the root directory
let root = pfs.root().open()?;

// Iterate over directory entries
for (name, item) in root {
    match item {
        orbis_pfs::directory::Item::File(file) => {
            // Read file contents
        }
        orbis_pfs::directory::Item::Directory(dir) => {
            // Recurse into directory
        }
    }
}
```
