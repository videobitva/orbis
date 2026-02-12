mod cli;

use clap::Parser;
use cli::{Cli, Command};
use orbis_pkg_util::{ConsoleProgress, PkgExtractor, SilentProgress};
use snafu::{ResultExt, Snafu};
use std::path::{Path, PathBuf};

/// Top-level application errors for orbis-pkg-util.
#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("failed to open PKG file '{}'", path.display()))]
    OpenPkg {
        path: PathBuf,
        source: orbis_pkg_util::OpenPkgError,
    },

    #[snafu(display("failed to extract PKG"))]
    Extract {
        source: orbis_pkg_util::ExtractError,
    },

    #[snafu(display("failed to read entry"))]
    ReadEntry { source: orbis_pkg::EntryReadError },

    #[snafu(display("failed to get current directory"))]
    GetCurrentDir { source: std::io::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

#[snafu::report]
fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Extract {
            pkg_path,
            output,
            force,
            quiet,
        } => cmd_extract(&pkg_path, output.as_deref(), force, quiet),
        Command::Info { pkg_path } => cmd_info(&pkg_path),
        Command::List { pkg_path } => cmd_list(&pkg_path),
    }
}

fn cmd_extract(path: &Path, output: Option<&Path>, force: bool, quiet: bool) -> Result<()> {
    let pkg = unsafe { orbis_pkg_util::open_pkg(path).context(OpenPkgSnafu { path })? };

    // Use title ID from content ID as default output directory name.
    let output_dir = match output {
        Some(path) => path.to_path_buf(),
        None => {
            let title_id = pkg.header().content_id().title_id();
            std::env::current_dir()
                .context(GetCurrentDirSnafu)?
                .join(title_id)
        }
    };

    if !quiet {
        println!(
            "Extracting {} to {}...",
            path.display(),
            output_dir.display()
        );
    }

    let start = std::time::Instant::now();

    // Extract based on verbosity.
    if quiet {
        let extractor = PkgExtractor::new(&pkg, SilentProgress, force);
        extractor.extract(&output_dir).context(ExtractSnafu)?;
    } else {
        let extractor = PkgExtractor::new(&pkg, ConsoleProgress::new(), force);
        extractor.extract(&output_dir).context(ExtractSnafu)?;
    }

    let elapsed = start.elapsed();

    if !quiet {
        println!("Done in {:.2}s.", elapsed.as_secs_f64());
    }

    Ok(())
}

fn cmd_info(path: &Path) -> Result<()> {
    use orbis_pkg::header::{content_type_name, drm_type_name};

    let pkg = unsafe { orbis_pkg_util::open_pkg(path).context(OpenPkgSnafu { path })? };
    let header = pkg.header();
    let content_id = header.content_id();

    println!("PKG: {}", path.display());
    println!();
    println!("Content ID:     {}", content_id);
    println!("  Service ID:   {}", content_id.service_id());
    println!("  Publisher:    {}", content_id.publisher_code());
    println!("  Title ID:     {}", content_id.title_id());
    println!("  Version:      {}", content_id.version());
    println!("  Label:        {}", content_id.label());
    println!(
        "Content Type:   0x{:02X} ({})",
        header.content_type(),
        content_type_name(header.content_type())
    );
    println!("Content Flags:  {}", header.content_flags());
    println!(
        "DRM Type:       0x{:02X} ({})",
        header.drm_type(),
        drm_type_name(header.drm_type())
    );
    println!("PKG Type:       0x{:08X}", header.pkg_type());
    println!("PKG Size:       {} bytes", header.pkg_size());
    println!("File Count:     {}", header.file_count());
    println!("Entry Count:    {}", header.entry_count());
    println!("Table Offset:   0x{:X}", header.table_offset());
    println!("PFS Offset:     0x{:X}", header.pfs_offset());
    println!("PFS Size:       {} bytes", header.pfs_size());

    Ok(())
}

fn cmd_list(path: &Path) -> Result<()> {
    let pkg = unsafe { orbis_pkg_util::open_pkg(path).context(OpenPkgSnafu { path })? };

    println!("Entries in {}:", path.display());
    println!("{:>6}  {:>10}  {:>10}  Path", "Index", "ID", "Size");
    println!("{:-<6}  {:-<10}  {:-<10}  {:-<30}", "", "", "", "");

    for result in pkg.entries() {
        let (index, entry) = result.context(ReadEntrySnafu)?;
        let path_str = entry
            .to_path(Path::new(""))
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| format!("(id: 0x{:08X})", entry.id()));

        println!(
            "{:>6}  0x{:08X}  {:>10}  {}",
            index,
            entry.id(),
            entry.data_size(),
            path_str
        );
    }

    Ok(())
}
