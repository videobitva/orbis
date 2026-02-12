use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "orbis-pkg-util")]
#[command(about = "PS4 PKG file utility", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Extract a PKG file to a directory
    Extract {
        /// Path to the PKG file
        #[arg(value_name = "PKG_FILE")]
        pkg_path: PathBuf,

        /// Output directory (defaults to title id)
        #[arg(short, long, value_name = "DIR")]
        output: Option<PathBuf>,

        /// Overwrite existing files
        #[arg(short, long)]
        force: bool,

        /// Suppress progress output
        #[arg(short, long)]
        quiet: bool,
    },

    /// Display information about a PKG file
    Info {
        /// Path to the PKG file
        #[arg(value_name = "PKG_FILE")]
        pkg_path: PathBuf,
    },

    /// List entries in a PKG file
    List {
        /// Path to the PKG file
        #[arg(value_name = "PKG_FILE")]
        pkg_path: PathBuf,
    },
}
