mod error;

pub use self::error::ExtractError;

use crate::progress::ExtractProgress;
use orbis_pfs::directory::DirEntry;
use orbis_pfs::image::Image;
use orbis_pkg::Pkg;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Extracts a PKG file to the specified output directory.
pub struct PkgExtractor<'a, R: AsRef<[u8]> + Sync, P: ExtractProgress> {
    pkg: &'a Pkg<R>,
    progress: P,
    overwrite: bool,
}

impl<'a, R: AsRef<[u8]> + Sync, P: ExtractProgress> PkgExtractor<'a, R, P> {
    /// Creates a new extractor for the given PKG.
    ///
    /// If `overwrite` is `true`, existing files will be replaced during extraction.
    /// Otherwise, extraction will fail if an output file already exists.
    pub fn new(pkg: &'a Pkg<R>, progress: P, overwrite: bool) -> Self {
        Self {
            pkg,
            progress,
            overwrite,
        }
    }

    /// Extracts the entire PKG to the specified directory.
    ///
    /// This extracts:
    /// - PKG entries to `{output}/sce_sys/`
    /// - PFS contents to `{output}/`
    ///
    /// PFS file extraction is parallelised with rayon.
    pub fn extract(&self, output: impl AsRef<Path>) -> Result<(), ExtractError> {
        let output = output.as_ref();

        // Extract PKG entries to sce_sys subdirectory.
        self.extract_entries(output.join("sce_sys"))?;

        // Extract PFS contents.
        self.extract_pfs(output)?;

        Ok(())
    }

    /// Extracts only the PKG entries (metadata files) to the specified directory.
    pub fn extract_entries(&self, output: impl AsRef<Path>) -> Result<(), ExtractError> {
        let output = output.as_ref();
        let total = self.pkg.entry_count();
        let mut extracted = 0usize;
        let mut skipped = 0usize;

        for result in self.pkg.entries() {
            let (num, entry) =
                result.map_err(|e| ExtractError::ReadEntryFailed { num: 0, source: e })?;

            // Get file path for this entry (skip entries without known paths).
            let path = match entry.to_path(output) {
                Some(p) => p,
                None => continue,
            };

            // Report progress.
            self.progress.entry_start(&path, num, total);

            // Get decrypted entry data, skipping entries that can't be decrypted.
            let data = match self.pkg.entry_data(&entry) {
                Ok(data) => data,
                Err(orbis_pkg::EntryDataError::NoDecryptionKey { key_index }) => {
                    self.progress
                        .entry_skipped(&path, &format!("no key for index {}", key_index));
                    skipped += 1;
                    continue;
                }
                Err(e) => return Err(ExtractError::GetEntryDataFailed { num, source: e }),
            };

            // Create parent directory.
            if let Some(parent) = path.parent() {
                create_dir_all(parent).map_err(|e| ExtractError::CreateDirectoryFailed {
                    path: parent.to_path_buf(),
                    source: e,
                })?;
            }

            // Write file.
            let mut file = File::create(&path).map_err(|e| ExtractError::CreateFileFailed {
                path: path.clone(),
                source: e,
            })?;

            file.write_all(&data)
                .map_err(|e| ExtractError::WriteFailed {
                    path: path.clone(),
                    source: e,
                })?;

            extracted += 1;
        }

        if total > 0 {
            self.progress.entries_completed(extracted, skipped);
        }

        Ok(())
    }

    /// Extracts the PFS contents to the specified directory.
    ///
    /// Directories are created sequentially, then all files are extracted
    /// in parallel using rayon.
    pub fn extract_pfs(&self, output: impl AsRef<Path>) -> Result<(), ExtractError> {
        let output = output.as_ref();

        // Get PFS image and encryption key.
        let pfs_image = self.pkg.get_pfs_image().ok_or(ExtractError::NoPfsImage)?;

        // Open outer PFS (encrypted, slice-backed).
        let outer_pfs = orbis_pfs::open_slice(pfs_image.data, Some(pfs_image.ekpfs))
            .map_err(|e| ExtractError::OpenOuterPfsFailed { source: e })?;

        let mut outer_root = outer_pfs
            .root()
            .open()
            .map_err(|e| ExtractError::OpenOuterSuperRootFailed { source: e })?;

        // Open outer uroot directory.
        let mut outer_uroot = match outer_root.remove(b"uroot") {
            Some(DirEntry::Directory(d)) => d
                .open()
                .map_err(|e| ExtractError::OpenOuterUrootFailed { source: e })?,
            _ => return Err(ExtractError::NoOuterUroot),
        };

        // Get inner PFS image (pfs_image.dat).
        let inner_file = match outer_uroot.remove(b"pfs_image.dat") {
            Some(DirEntry::File(f)) => f,
            _ => return Err(ExtractError::NoInnerImage),
        };

        // Convert the file handle to an Image adapter, then open the inner PFS.
        let is_compressed = inner_file.is_compressed();
        let file_image = inner_file.into_image();

        // Use Box<dyn Image> to unify the compressed/uncompressed branches.
        let inner_image: Box<dyn Image> = if is_compressed {
            let pfsc = orbis_pfs::pfsc::PfscImage::open(file_image)
                .map_err(|e| ExtractError::CreateDecompressorFailed { source: e })?;
            Box::new(pfsc)
        } else {
            Box::new(file_image)
        };

        let inner_pfs = orbis_pfs::open_image(inner_image)
            .map_err(|e| ExtractError::OpenInnerPfsFailed { source: e })?;

        let mut inner_root = inner_pfs
            .root()
            .open()
            .map_err(|e| ExtractError::OpenInnerSuperRootFailed { source: e })?;

        // Get inner uroot.
        let inner_uroot = match inner_root.remove(b"uroot") {
            Some(DirEntry::Directory(d)) => d,
            _ => return Err(ExtractError::NoInnerUroot),
        };

        // Phase 1: Walk the directory tree and collect all work items.
        let mut dirs: Vec<PathBuf> = Vec::new();
        let mut files: Vec<FileWork<'_>> = Vec::new();

        collect_pfs_items(inner_uroot, output, "/", &mut dirs, &mut files)?;

        if dirs.is_empty() && files.is_empty() {
            return Ok(());
        }

        self.progress.pfs_start(files.len());

        // Phase 2: Create all directories (sequential — fast, must precede file writes).
        for dir in &dirs {
            self.progress.pfs_directory(dir);
            create_dir_all(dir).map_err(|e| ExtractError::CreateDirectoryFailed {
                path: dir.clone(),
                source: e,
            })?;
        }

        // Phase 3: Extract all files in parallel.
        let overwrite = self.overwrite;

        files.par_iter().try_for_each(|work| {
            self.progress.pfs_file(&work.output_path, work.file.len());
            extract_single_file(work, &self.progress, overwrite)
        })?;

        self.progress.pfs_completed();

        Ok(())
    }
}

/// A file to be extracted, collected during the directory walk.
struct FileWork<'a> {
    file: orbis_pfs::file::File<'a, Box<dyn Image + 'a>>,
    output_path: PathBuf,
    pfs_path: String,
}

/// Recursively walks a PFS directory tree and collects all directories
/// and files into flat lists for later parallel extraction.
fn collect_pfs_items<'a>(
    dir: orbis_pfs::directory::Directory<'a, Box<dyn Image + 'a>>,
    output: &Path,
    pfs_path: &str,
    dirs: &mut Vec<PathBuf>,
    files: &mut Vec<FileWork<'a>>,
) -> Result<(), ExtractError> {
    let items = dir
        .open()
        .map_err(|e| ExtractError::OpenPfsDirectoryFailed {
            path: pfs_path.to_string(),
            source: e,
        })?;

    for (name, item) in items {
        let name_str =
            std::str::from_utf8(&name).map_err(|_| ExtractError::UnsupportedFileName {
                path: format!("{}{}", pfs_path, String::from_utf8_lossy(&name)),
            })?;

        let item_output = output.join(name_str);
        let item_pfs_path = format!("{}{}/", pfs_path, name_str);

        match item {
            DirEntry::Directory(subdir) => {
                dirs.push(item_output.clone());
                collect_pfs_items(subdir, &item_output, &item_pfs_path, dirs, files)?;
            }
            DirEntry::File(file) => {
                files.push(FileWork {
                    file,
                    output_path: item_output,
                    pfs_path: item_pfs_path,
                });
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}

/// Extracts a single file from the PFS to disk.
///
/// Called from rayon worker threads in parallel.
fn extract_single_file<P: ExtractProgress>(
    work: &FileWork<'_>,
    progress: &P,
    overwrite: bool,
) -> Result<(), ExtractError> {
    let mut opts = OpenOptions::new();
    opts.write(true);

    if overwrite {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }

    let mut dest = opts
        .open(&work.output_path)
        .map_err(|e| ExtractError::CreateFileFailed {
            path: work.output_path.clone(),
            source: e,
        })?;

    let mut buffer = vec![0u8; 8 * 1024 * 1024]; // 8MB buffer
    let mut offset = 0u64;

    loop {
        let read = match work.file.read_at(offset, &mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(ExtractError::ReadPfsFileFailed {
                    path: work.pfs_path.clone(),
                    source: e,
                });
            }
        };

        dest.write_all(&buffer[..read])
            .map_err(|e| ExtractError::WriteFailed {
                path: work.output_path.clone(),
                source: e,
            })?;

        offset += read as u64;
    }

    progress.pfs_file_completed(offset);

    Ok(())
}
