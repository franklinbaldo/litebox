// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use litebox_util_fs_archive::writer::{collect_from_directory, write_archive};
use litebox_util_fs_archive::{Archive, ENTRY_TYPE_DIR, ENTRY_TYPE_FILE};

#[derive(Parser)]
#[command(name = "lbfs", about = "LiteBox filesystem archive tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an .lbfs archive from a directory.
    Create {
        /// Source directory to archive.
        #[arg(short = 'C', long = "directory")]
        directory: PathBuf,
        /// Output .lbfs file path.
        #[arg(short = 'o', long = "output", default_value = "archive.lbfs")]
        output: PathBuf,
    },
    /// Extract an .lbfs archive to a directory.
    Extract {
        /// Input .lbfs file path.
        input: PathBuf,
        /// Output directory (created if it does not exist).
        #[arg(short = 'o', long = "output", default_value = ".")]
        output: PathBuf,
    },
    /// List the contents of an .lbfs archive.
    List {
        /// Input .lbfs file path.
        input: PathBuf,
        /// Show detailed information (size, mode, uid, gid, offset).
        #[arg(short = 'l', long = "long")]
        long: bool,
    },
}

fn cmd_create(directory: &Path, output: &Path) -> anyhow::Result<()> {
    let entries = collect_from_directory(directory)?;
    let file = fs::File::create(output)?;
    let writer = io::BufWriter::new(file);
    write_archive(&entries, writer)?;

    let file_count = entries
        .iter()
        .filter(|e| e.entry_type == ENTRY_TYPE_FILE)
        .count();
    let dir_count = entries
        .iter()
        .filter(|e| e.entry_type == ENTRY_TYPE_DIR)
        .count();
    let meta = fs::metadata(output)?;
    #[expect(clippy::cast_precision_loss)]
    let size_mb = meta.len() as f64 / 1_048_576.0;
    eprintln!(
        "Created {} ({} files, {} dirs, {:.1} MB)",
        output.display(),
        file_count,
        dir_count,
        size_mb,
    );
    Ok(())
}

fn cmd_extract(input: &Path, output: &Path) -> anyhow::Result<()> {
    let data = fs::read(input)?;
    let archive = Archive::parse(&data)?;

    fs::create_dir_all(output)?;

    for entry in archive.entries() {
        if entry.is_dir() {
            let dir_path = output.join(&entry.path);
            fs::create_dir_all(&dir_path)?;
        }
    }

    for entry in archive.entries() {
        if entry.is_file() {
            let file_path = output.join(&entry.path);
            if let Some(parent) = file_path.parent() {
                fs::create_dir_all(parent)?;
            }
            let content = archive.file_data(entry);
            fs::write(&file_path, content)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    &file_path,
                    fs::Permissions::from_mode(entry.header.mode.get()),
                )?;
            }
        }
    }

    let count = archive.entries().len();
    eprintln!("Extracted {count} entries to {}", output.display());
    Ok(())
}

fn cmd_list(input: &Path, long: bool) -> anyhow::Result<()> {
    let data = fs::read(input)?;
    let archive = Archive::parse(&data)?;

    for entry in archive.entries() {
        if long {
            let type_char = if entry.is_dir() { 'd' } else { '-' };
            println!(
                "{}{:04o}  {:5}:{:<5}  {:>10}  @{:<10x}  {}",
                type_char,
                entry.header.mode.get(),
                entry.header.uid.get(),
                entry.header.gid.get(),
                entry.header.byte_size.get(),
                entry.header.data_offset.get(),
                entry.path,
            );
        } else {
            println!("{}", entry.path);
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Create { directory, output } => cmd_create(&directory, &output),
        Command::Extract { input, output } => cmd_extract(&input, &output),
        Command::List { input, long } => cmd_list(&input, long),
    }
}
