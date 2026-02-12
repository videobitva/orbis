use std::path::Path;

/// Trait for receiving extraction progress updates.
///
/// All methods take `&self` (not `&mut self`) so the progress reporter can be
/// shared across threads during parallel extraction.
pub trait ExtractProgress: Send + Sync {
    /// Called when starting to extract a PKG entry.
    fn entry_start(&self, _path: &Path, _current: usize, _total: usize) {}

    /// Called when an entry is skipped (e.g., cannot be decrypted).
    fn entry_skipped(&self, _path: &Path, _reason: &str) {}

    /// Called when all PKG entries have been extracted.
    fn entries_completed(&self, _extracted: usize, _skipped: usize) {}

    /// Called when starting PFS extraction.
    fn pfs_start(&self, _total_items: usize) {}

    /// Called when creating a directory from PFS.
    fn pfs_directory(&self, _path: &Path) {}

    /// Called when starting to extract a file from PFS.
    fn pfs_file(&self, _path: &Path, _size: u64) {}

    /// Called when a PFS file has been fully extracted.
    fn pfs_file_completed(&self, _written: u64) {}

    /// Called when PFS extraction is complete.
    fn pfs_completed(&self) {}
}

/// A no-op progress implementation that discards all updates.
pub struct SilentProgress;

impl ExtractProgress for SilentProgress {}

/// Console progress reporter using an indicatif progress bar.
///
/// PKG entries are printed as before (few items, no contention concern).
/// PFS file extraction uses a progress bar that redraws at a fixed rate,
/// avoiding the stdout lock contention caused by per-file `println!`.
#[cfg(feature = "cli")]
pub struct ConsoleProgress {
    pfs_bar: indicatif::ProgressBar,
}

#[cfg(feature = "cli")]
impl ConsoleProgress {
    pub fn new() -> Self {
        Self {
            pfs_bar: indicatif::ProgressBar::hidden(),
        }
    }
}

#[cfg(feature = "cli")]
impl Default for ConsoleProgress {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "cli")]
impl ExtractProgress for ConsoleProgress {
    fn pfs_start(&self, total_items: usize) {
        self.pfs_bar
            .set_draw_target(indicatif::ProgressDrawTarget::stderr());
        self.pfs_bar.set_length(total_items as u64);
        self.pfs_bar.set_position(0);
        self.pfs_bar.set_style(
            indicatif::ProgressStyle::default_bar()
                .template("{bar:40.cyan/blue} {pos}/{len} files [{elapsed_precise}]")
                .unwrap()
                .progress_chars("━╸─"),
        );
        self.pfs_bar.reset();
    }

    fn pfs_file_completed(&self, _written: u64) {
        self.pfs_bar.inc(1);
    }

    fn pfs_completed(&self) {
        let total = self.pfs_bar.position();
        self.pfs_bar.finish_and_clear();
        println!("PFS extraction complete ({} files).", total);
    }
}
