// Copyright (c) franklinbaldo.
// Licensed under the MIT license.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::windows::fs::MetadataExt;
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    path::Path,
};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub profile: String,
    pub required_features: Vec<String>,
    pub host: String,
    pub runner: String,
}

/// Only capabilities actually implemented by the bundled control host.
/// New profiles require a launch adapter and runtime acceptance tests.
pub fn check_runtime(runtime: &Runtime) -> Result<()> {
    let available: &[&str] = match runtime.profile.as_str() {
        "demo_stdio_v1" => &["rgb24_160x120", "pcm_s16_mono_22050", "keyboard_demo"],
        other => return Err(format!("runtime profile is not implemented: {other}").into()),
    };
    let missing: Vec<_> = runtime
        .required_features
        .iter()
        .filter(|feature| !available.contains(&feature.as_str()))
        .collect();
    if !missing.is_empty() {
        return Err(format!("runtime lacks required capabilities: {missing:?}").into());
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub version: String,
    pub runtime: Runtime,
    pub content: String,
    pub icon: String,
    pub files: Vec<Artifact>,
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.ends_with('.')
        && !matches!(
            value
                .split('.')
                .next()
                .unwrap_or("")
                .to_ascii_uppercase()
                .as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
pub fn game_id(value: &str) -> bool {
    identifier(value)
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}
pub fn validate(p: &Package) -> Result<()> {
    if p.schema_version != 1
        || !game_id(&p.id)
        || !identifier(&p.version)
        || p.id != p.id.to_ascii_lowercase()
        || p.name.trim().is_empty()
        || p.name.len() > 128
        || p.name.chars().any(char::is_control)
    {
        return Err("invalid package identity/version/name".into());
    }
    let names: BTreeSet<_> = p.files.iter().map(|f| f.path.as_str()).collect();
    let folded: BTreeSet<_> = p
        .files
        .iter()
        .map(|f| f.path.to_ascii_lowercase())
        .collect();
    if p.files.is_empty()
        || p.files.len() > 128
        || folded.len() != p.files.len()
        || names
            .iter()
            .any(|name| !identifier(name) || name.eq_ignore_ascii_case("package.json"))
    {
        return Err("unexpected or duplicate artifact paths".into());
    }
    for role in [&p.runtime.host, &p.runtime.runner, &p.content, &p.icon] {
        if !names.contains(role.as_str()) {
            return Err(format!("missing artifact: {role}").into());
        }
    }
    for f in &p.files {
        if f.size == 0
            || f.size > 16 * 1024 * 1024 * 1024
            || f.sha256.len() != 64
            || !f
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid artifact size/hash".into());
        }
    }
    Ok(())
}
pub fn no_reparse(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.exists() && fs::symlink_metadata(ancestor)?.file_attributes() & 0x400 != 0 {
            return Err(format!("reparse point is not allowed: {}", ancestor.display()).into());
        }
    }
    Ok(())
}
pub fn hash(path: &Path) -> Result<String> {
    no_reparse(path)?;
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
pub fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T> {
    no_reparse(path)?;
    if fs::metadata(path)?.len() > 65536 {
        return Err("JSON exceeds size limit".into());
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
pub fn verify(directory: &Path) -> Result<Package> {
    let p: Package = read_json(&directory.join("package.json"))?;
    validate(&p)?;
    for f in &p.files {
        let path = directory.join(&f.path);
        if fs::metadata(&path)?.len() != f.size || hash(&path)? != f.sha256 {
            return Err(format!("artifact integrity check failed: {}", f.path).into());
        }
    }
    Ok(p)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn versions_cannot_escape() {
        for bad in [
            "",
            "..",
            "../other",
            "C:\\Windows",
            "/tmp",
            "v1:stream",
            "a/b",
            "a\\b",
        ] {
            assert!(!identifier(bad), "{bad}");
        }
        assert!(identifier("1.0.0-native.1"));
        for bad in ["con", "nul.txt", "v1.", "COM1"] {
            assert!(!identifier(bad));
        }
        for bad in ["game.pending", "game--two", "Game", "-game"] {
            assert!(!game_id(bad));
        }
        for good in ["chocolate-doom", "sdl-sopwith", "cdogs-sdl", "neverball"] {
            assert!(game_id(good));
        }
    }
    #[test]
    fn package_rejects_path_and_hash_substitution() {
        let mut p = Package {
            schema_version: 1,
            id: "breakout".into(),
            name: "Breakout".into(),
            version: "1.0.0".into(),
            runtime: Runtime {
                profile: "demo_stdio_v1".into(),
                required_features: vec![],
                host: "host.exe".into(),
                runner: "runner.exe".into(),
            },
            content: "game.tar".into(),
            icon: "icon.ico".into(),
            files: [
                "host.exe",
                "runner.exe",
                "game.tar",
                "icon.ico",
                "license.txt",
            ]
            .iter()
            .map(|name| Artifact {
                path: name.to_string(),
                sha256: "0".repeat(64),
                size: 1,
            })
            .collect(),
        };
        validate(&p).unwrap();
        p.files[0].path = "../host.exe".into();
        assert!(validate(&p).is_err());
        p.files[0].path = "host.exe".into();
        p.files[0].sha256 = "x".repeat(64);
        assert!(validate(&p).is_err());
    }
    #[test]
    fn unsupported_capabilities_fail_closed() {
        let mut runtime = Runtime {
            profile: "demo_stdio_v1".into(),
            required_features: vec!["pcm_s16_mono_22050".into()],
            host: "host.exe".into(),
            runner: "runner.exe".into(),
        };
        check_runtime(&runtime).unwrap();
        for feature in ["sdl2", "x11", "wayland", "alsa", "opengl", "persistent_fs"] {
            runtime.required_features = vec![feature.into()];
            assert!(check_runtime(&runtime).is_err(), "{feature}");
        }
        runtime.required_features.clear();
        runtime.profile = "desktop_fd_v1".into();
        assert!(check_runtime(&runtime).is_err());
    }
}
