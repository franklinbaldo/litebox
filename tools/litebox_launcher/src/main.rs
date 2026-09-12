// Copyright (c) franklinbaldo.
// Licensed under the MIT license.

//! Native per-user package lifecycle. Runtime support is checked separately.
mod package;
mod shell;
use package::{check_runtime, game_id, hash, identifier, no_reparse, read_json, verify, Result};
use serde::{Deserialize, Serialize};
use std::os::windows::{fs::OpenOptionsExt, process::CommandExt};
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    process::Command,
};
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED};
const MARKER: &str = "LiteBox native desktop packages v1\n";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    previous: Option<State>,
    next: State,
}
struct Root {
    path: PathBuf,
    custom: bool,
    id: String,
}
impl Root {
    fn new(custom: Option<PathBuf>, id: &str) -> Result<Self> {
        if !game_id(id) {
            return Err("invalid package ID".into());
        }
        let is_custom = custom.is_some();
        let path = std::path::absolute(match custom {
            Some(p) => p,
            None => shell::default_root()?,
        })?;
        no_reparse(&path)?;
        Ok(Self {
            path,
            custom: is_custom,
            id: id.into(),
        })
    }
    fn state(&self) -> PathBuf {
        self.path.join("state").join(format!("{}.json", self.id))
    }
    fn journal(&self) -> PathBuf {
        self.path
            .join("state")
            .join(format!("{}.pending.json", self.id))
    }
    fn package(&self, version: &str) -> Result<PathBuf> {
        if !identifier(version) {
            return Err("invalid version in installed state".into());
        }
        let path = self.path.join("packages").join(&self.id).join(version);
        no_reparse(&path)?;
        Ok(path)
    }
    fn require(&self) -> Result<()> {
        let marker = self.path.join(".litebox-desktop-v1");
        no_reparse(&marker)?;
        if fs::read_to_string(marker)? != MARKER {
            return Err("not a LiteBox installation root".into());
        }
        Ok(())
    }
    fn initialize(&self) -> Result<()> {
        let marker = self.path.join(".litebox-desktop-v1");
        if marker.exists() {
            self.require()?;
        } else {
            if self.path.exists() && fs::read_dir(&self.path)?.next().is_some() {
                return Err("root is nonempty and has no LiteBox marker".into());
            }
            fs::create_dir_all(&self.path)?;
            fs::write(marker, MARKER)?;
        }
        for name in ["bin", "state", "packages", "data", "icons"] {
            let path = self.path.join(name);
            no_reparse(&path)?;
            fs::create_dir_all(path)?;
        }
        for base in ["packages", "data"] {
            let path = self.path.join(base).join(&self.id);
            no_reparse(&path)?;
            fs::create_dir_all(path)?;
        }
        Ok(())
    }
    fn lock(&self, name: &str) -> Result<File> {
        self.require()?;
        let path = self.path.join(name);
        no_reparse(&path)?;
        Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(path)?)
    }
    fn link(&self) -> Result<PathBuf> {
        shell::link_path(&self.path, self.custom, &self.id)
    }
}
fn finish(root: &Root, state: &State) -> Result<()> {
    let directory = root.package(&state.version)?;
    let package = verify(&directory)?;
    if package.version != state.version || package.id != root.id {
        return Err("package/state version mismatch".into());
    }
    check_runtime(&package.runtime)?;
    let icon = root.path.join("icons").join(format!("{}.ico", root.id));
    no_reparse(&icon)?;
    fs::copy(directory.join(&package.icon), icon)?;
    shell::shortcut(&root.path, root.custom, &root.id, &package.name)?;
    shell::atomic_json(&root.state(), state)?;
    Ok(())
}
fn recover(root: &Root) -> Result<()> {
    if !root.journal().exists() {
        return Ok(());
    }
    let journal: Journal = read_json(&root.journal())?;
    if let Err(error) = finish(root, &journal.next) {
        if let Some(previous) = journal.previous {
            finish(root, &previous)?;
        } else {
            if root.state().exists() {
                fs::remove_file(root.state())?;
            }
            let link = root.link()?;
            if link.exists() {
                fs::remove_file(link)?;
            }
        }
        fs::remove_file(root.journal())?;
        return Err(format!("interrupted installation rolled back: {error}").into());
    }
    fs::remove_file(root.journal())?;
    Ok(())
}
fn install(root: &Root, source: &Path) -> Result<()> {
    let package = verify(source)?; // Validate source before writing any installed state.
    if package.id != root.id {
        return Err("source package ID mismatch".into());
    }
    check_runtime(&package.runtime)?;
    root.initialize()?;
    let _operation = root.lock("operation.lock")?;
    recover(root)?;
    let destination = root.package(&package.version)?;
    if !destination.exists() {
        let staging = root.package(&format!("{}-staging", package.version))?;
        if staging.exists() {
            return Err(
                "staging exists; preserve it for inspection or choose another version".into(),
            );
        }
        fs::create_dir(&staging)?;
        for f in &package.files {
            fs::copy(source.join(&f.path), staging.join(&f.path))?;
        }
        fs::write(
            staging.join("package.json"),
            serde_json::to_vec_pretty(&package)?,
        )?;
        verify(&staging)?;
        fs::rename(&staging, &destination)?;
    }
    let installed = verify(&destination)?;
    if serde_json::to_vec(&installed)? != serde_json::to_vec(&package)? {
        return Err("package versions are immutable".into());
    }
    let bootstrap = root.path.join("bin/LiteBox.exe");
    no_reparse(&bootstrap)?;
    let current = std::env::current_exe()?;
    if !bootstrap.exists() || hash(&bootstrap)? != hash(&current)? {
        fs::copy(current, bootstrap)?;
    }
    let previous = if root.state().exists() {
        Some(read_json(&root.state())?)
    } else {
        None
    };
    shell::atomic_json(
        &root.journal(),
        &Journal {
            previous,
            next: State {
                version: package.version,
            },
        },
    )?;
    recover(root)?;
    println!(
        "Installed {}. Shortcut: {}",
        package.name,
        root.link()?.display()
    );
    Ok(())
}
fn launch(root: &Root, seconds: Option<&str>) -> Result<()> {
    let operation = root.lock("operation.lock")?;
    recover(root)?;
    let _session = root.lock(&format!("{}-session.lock", root.id))?;
    let state: State = read_json(&root.state())?;
    let directory = root.package(&state.version)?;
    let package = verify(&directory)?;
    if package.id != root.id || package.version != state.version {
        return Err("installed identity mismatch".into());
    }
    check_runtime(&package.runtime)?;
    let mut command = Command::new(directory.join(&package.runtime.host));
    command
        .arg("--runner")
        .arg(directory.join(&package.runtime.runner))
        .arg("--tar")
        .arg(directory.join(&package.content))
        .arg("--icon")
        .arg(root.path.join("icons").join(format!("{}.ico", root.id)))
        .arg("--app-id")
        .arg(shell::app_id(&root.id))
        .creation_flags(0x08000000);
    if let Some(seconds) = seconds {
        command.arg("--smoke-seconds").arg(seconds);
    }
    let mut child = command.spawn()?;
    drop(operation); // Version pinned; allow updates during play.
    let status = child.wait()?;
    if !status.success() {
        return Err(format!("host exited with {status}").into());
    }
    Ok(())
}
fn uninstall(root: &Root) -> Result<()> {
    let _operation = root.lock("operation.lock")?;
    recover(root)?;
    let _session = root.lock(&format!("{}-session.lock", root.id))?; // Refuse removal while running.
    let packages = root.path.join("packages").join(&root.id);
    no_reparse(&packages)?;
    let mut files = Vec::new();
    let mut directories = Vec::new();
    for entry in fs::read_dir(&packages)? {
        let path = entry?.path();
        no_reparse(&path)?;
        let package = verify(&path)?;
        if package.id != root.id {
            return Err("package identity mismatch during removal".into());
        }
        for entry in fs::read_dir(&path)? {
            let path = entry?.path();
            no_reparse(&path)?;
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or("invalid package filename")?;
            if (!package.files.iter().any(|f| f.path == name) && name != "package.json")
                || !path.is_file()
            {
                return Err("unknown package contents; preserving installation".into());
            }
            files.push(path);
        }
        directories.push(path);
    }
    let link = root.link()?;
    if link.exists() {
        fs::remove_file(link)?;
    }
    if root.state().exists() {
        fs::remove_file(root.state())?;
    }
    // Only verified files and empty directories are removed. No recursive delete.
    for path in files {
        fs::remove_file(path)?;
    }
    for path in directories {
        fs::remove_dir(path)?;
    }
    println!(
        "Removed {}; preserved data in {}",
        root.id,
        root.path.join("data").join(&root.id).display()
    );
    Ok(())
}
fn run() -> Result<()> {
    let mut args: Vec<_> = std::env::args().skip(1).collect();
    let mut custom = None;
    let mut seconds = None;
    for flag in ["--root", "--smoke-seconds"] {
        if let Some(index) = args.iter().position(|s| s == flag) {
            if index + 1 >= args.len() {
                return Err(format!("missing value for {flag}").into());
            }
            let value = args.remove(index + 1);
            args.remove(index);
            if flag == "--root" {
                custom = Some(PathBuf::from(value));
            } else {
                seconds = Some(value);
            }
        }
    }
    if args.len() != 2 {
        return Err("usage: LiteBox install <package-dir> | launch <game-id> | uninstall <game-id> [--root <staging-root>] [--smoke-seconds N]".into());
    }
    let id = if args[0] == "install" {
        verify(Path::new(&args[1]))?.id
    } else {
        args[1].clone()
    };
    let root = Root::new(custom, &id)?;
    match args[0].as_str() {
        "install" => install(&root, Path::new(&args[1])),
        "launch" => launch(&root, seconds.as_deref()),
        "uninstall" => uninstall(&root),
        _ => Err("unsupported command".into()),
    }
}
fn main() {
    if let Err(error) = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok() } {
        eprintln!("COM initialization: {error}");
        std::process::exit(1);
    }
    let result = run();
    unsafe {
        CoUninitialize();
    }
    if let Err(error) = result {
        eprintln!("LiteBox: {error}");
        std::process::exit(1);
    }
}
