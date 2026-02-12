# orbis-pkg-util

Command-line utility for working with PlayStation 4 PKG files.

## Installation

```bash
cargo install --path .
```

## Commands

### extract

Extract PKG contents to a directory. Defaults to title ID (e.g., `CUSA03173`).

```bash
orbis-pkg-util extract game.pkg
orbis-pkg-util extract game.pkg --output ./extracted
orbis-pkg-util extract game.pkg -q  # quiet mode
```

### metadata

Display PKG metadata including content ID, type, and flags.

```bash
orbis-pkg-util metadata game.pkg
```

Output:
```
PKG Metadata
============
Content ID:    EP9000-CUSA03173_00-BLOODBORNE0000EU
  Service ID:  EP
  Publisher:   9000
  Title ID:    CUSA03173
  Version:     00
  Label:       BLOODBORNE0000EU
Content Type:  0x1A (GD (Game Data))
DRM Type:      0x0F (PS4)
...
```

### info

Display PKG header information.

```bash
orbis-pkg-util info game.pkg
```

### list

List all entries in a PKG file.

```bash
orbis-pkg-util list game.pkg
```
