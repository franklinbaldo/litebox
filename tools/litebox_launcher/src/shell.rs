use crate::package::{no_reparse, Result};
use std::os::windows::ffi::OsStrExt;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};
use windows::core::{Interface, PCWSTR};
use windows::Win32::Storage::EnhancedStorage::PKEY_AppUserModel_ID;
use windows::Win32::System::Com::StructuredStorage::PROPVARIANT;
use windows::Win32::System::Com::{
    CoCreateInstance, CoTaskMemFree, IPersistFile, CLSCTX_INPROC_SERVER,
};
use windows::Win32::UI::Shell::PropertiesSystem::IPropertyStore;
use windows::Win32::UI::Shell::{
    FOLDERID_LocalAppData, FOLDERID_Programs, IShellLinkW, SHGetKnownFolderPath, ShellLink,
    KF_FLAG_DEFAULT,
};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};
pub fn app_id(id: &str) -> String {
    format!("LiteBox.Game.{id}")
}
pub fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
pub fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    let mut slashes = 0;
    for ch in value.chars() {
        if ch == '\\' {
            slashes += 1;
            continue;
        }
        out.push_str(&"\\".repeat(if ch == '"' { slashes * 2 + 1 } else { slashes }));
        slashes = 0;
        out.push(ch);
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}
fn known_folder(id: &windows::core::GUID) -> Result<PathBuf> {
    unsafe {
        let value = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None)?;
        let result = value.to_string();
        CoTaskMemFree(Some(value.0.cast()));
        Ok(PathBuf::from(result?))
    }
}
pub fn default_root() -> Result<PathBuf> {
    Ok(known_folder(&FOLDERID_LocalAppData)?.join("LiteBox"))
}
pub fn link_path(root: &Path, custom: bool, id: &str) -> Result<PathBuf> {
    let base = if custom {
        root.join("shortcuts")
    } else {
        known_folder(&FOLDERID_Programs)?.join("LiteBox")
    };
    no_reparse(&base)?;
    fs::create_dir_all(&base)?;
    let path = base.join(format!("{id} - LiteBox.lnk"));
    no_reparse(&path)?;
    Ok(path)
}
pub fn atomic_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    no_reparse(path)?;
    let temp = path.with_extension("json.tmp");
    no_reparse(&temp)?;
    let mut file = File::create(&temp)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    drop(file);
    if unsafe {
        MoveFileExW(
            wide(&temp).as_ptr(),
            wide(path).as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
pub fn shortcut(root: &Path, custom: bool, id: &str, name: &str) -> Result<()> {
    let args = if custom {
        format!(
            "launch {} --root {}",
            quote(id),
            quote(&root.to_string_lossy())
        )
    } else {
        format!("launch {}", quote(id))
    };
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
        link.SetPath(PCWSTR(wide(root.join("bin/LiteBox.exe")).as_ptr()))?;
        link.SetArguments(PCWSTR(wide(&args).as_ptr()))?;
        link.SetDescription(PCWSTR(wide(name).as_ptr()))?;
        link.SetWorkingDirectory(PCWSTR(wide(root).as_ptr()))?;
        link.SetIconLocation(
            PCWSTR(wide(root.join("icons").join(format!("{id}.ico"))).as_ptr()),
            0,
        )?;
        let props: IPropertyStore = link.cast()?;
        props.SetValue(
            &PKEY_AppUserModel_ID,
            &PROPVARIANT::from(app_id(id).as_str()),
        )?;
        props.Commit()?;
        let persist: IPersistFile = link.cast()?;
        persist.Save(PCWSTR(wide(link_path(root, custom, id)?).as_ptr()), true)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quote_handles_windows_paths_and_quotes() {
        assert_eq!(quote("C:\\a b\\"), "\"C:\\a b\\\\\"");
        assert_eq!(quote("a\"b"), "\"a\\\"b\"");
    }
}
