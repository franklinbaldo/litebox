// OCI config.json generator from accumulated Dockerfile metadata.

use std::path::Path;

use anyhow::{Context, Result};

/// Accumulated metadata from Dockerfile instructions.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ImageMetadata {
    pub env: Vec<String>,
    pub working_dir: Option<String>,
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
}

/// Generate an OCI runtime spec JSON string from image metadata.
///
/// The returned string is a valid OCI runtime spec (`config.json`) that can be
/// deserialized into `oci_spec::runtime::Spec`.
pub fn generate_spec(metadata: &ImageMetadata) -> Result<String> {
    // 1. Process args: combine ENTRYPOINT + CMD
    let args = match (&metadata.entrypoint, &metadata.cmd) {
        (Some(ep), Some(cmd)) => {
            let mut combined = ep.clone();
            combined.extend(cmd.iter().cloned());
            combined
        }
        (Some(ep), None) => ep.clone(),
        (None, Some(cmd)) => cmd.clone(),
        (None, None) => vec!["/bin/sh".to_string()],
    };

    // 2. Process cwd: from working_dir, default "/"
    let cwd = metadata.working_dir.as_deref().unwrap_or("/").to_string();

    // 3. Build the spec as a serde_json::Value for robustness
    let spec = serde_json::json!({
        "ociVersion": "1.0.2",
        "process": {
            "args": args,
            "env": metadata.env,
            "cwd": cwd,
            "user": { "uid": 0, "gid": 0 }
        },
        "root": {
            "path": "rootfs",
            "readonly": true
        },
        "mounts": [
            { "destination": "/proc", "type": "proc", "source": "proc" },
            { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs" }
        ],
        "linux": {}
    });

    serde_json::to_string_pretty(&spec).context("failed to serialize OCI spec")
}

/// Write the spec as `config.json` to the given bundle directory.
pub fn write_config_json(bundle_dir: &Path, metadata: &ImageMetadata) -> Result<()> {
    let json = generate_spec(metadata)?;

    // Verify the generated JSON round-trips through oci_spec::runtime::Spec
    let _: oci_spec::runtime::Spec =
        serde_json::from_str(&json).context("generated spec is not valid OCI runtime spec")?;

    let config_path = bundle_dir.join("config.json");
    std::fs::write(&config_path, json)
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_spec_with_all_fields() {
        let metadata = ImageMetadata {
            env: vec!["PATH=/usr/bin:/bin".into(), "HOME=/root".into()],
            working_dir: Some("/app".into()),
            entrypoint: Some(vec!["python3".into()]),
            cmd: Some(vec!["app.py".into()]),
        };
        let json = generate_spec(&metadata).unwrap();
        let spec: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            spec["process"]["args"],
            serde_json::json!(["python3", "app.py"])
        );
        assert_eq!(spec["process"]["cwd"], "/app");
        assert_eq!(spec["process"]["env"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn generate_spec_defaults_to_sh() {
        let metadata = ImageMetadata::default();
        let json = generate_spec(&metadata).unwrap();
        let spec: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(spec["process"]["args"], serde_json::json!(["/bin/sh"]));
        assert_eq!(spec["process"]["cwd"], "/");
    }

    #[test]
    fn generate_spec_only_entrypoint() {
        let metadata = ImageMetadata {
            entrypoint: Some(vec!["/usr/bin/myapp".into()]),
            ..Default::default()
        };
        let json = generate_spec(&metadata).unwrap();
        let spec: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            spec["process"]["args"],
            serde_json::json!(["/usr/bin/myapp"])
        );
    }

    #[test]
    fn generate_spec_only_cmd() {
        let metadata = ImageMetadata {
            cmd: Some(vec!["echo".into(), "hello".into()]),
            ..Default::default()
        };
        let json = generate_spec(&metadata).unwrap();
        let spec: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            spec["process"]["args"],
            serde_json::json!(["echo", "hello"])
        );
    }

    #[test]
    fn generate_spec_roundtrips_through_oci_spec() {
        let metadata = ImageMetadata {
            env: vec!["PATH=/usr/bin".into()],
            working_dir: Some("/app".into()),
            entrypoint: Some(vec!["node".into()]),
            cmd: Some(vec!["index.js".into()]),
        };
        let json = generate_spec(&metadata).unwrap();
        // Must deserialize cleanly into the oci_spec Spec type
        let parsed: oci_spec::runtime::Spec = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.process().as_ref().unwrap().args().as_ref().unwrap(),
            &vec!["node".to_string(), "index.js".to_string()]
        );
        assert_eq!(
            parsed.root().as_ref().unwrap().path().to_str().unwrap(),
            "rootfs"
        );
    }

    #[test]
    fn generate_spec_has_required_mounts() {
        let metadata = ImageMetadata::default();
        let json = generate_spec(&metadata).unwrap();
        let spec: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mounts = spec["mounts"].as_array().unwrap();
        assert!(mounts
            .iter()
            .any(|m| m["destination"] == "/proc" && m["type"] == "proc"));
        assert!(mounts
            .iter()
            .any(|m| m["destination"] == "/tmp" && m["type"] == "tmpfs"));
    }

    #[test]
    fn write_config_json_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let metadata = ImageMetadata {
            env: vec!["FOO=bar".into()],
            working_dir: None,
            entrypoint: Some(vec!["/bin/echo".into()]),
            cmd: Some(vec!["hello".into()]),
        };
        write_config_json(dir.path(), &metadata).unwrap();
        let config_path = dir.path().join("config.json");
        assert!(config_path.exists());
        let content = std::fs::read_to_string(config_path).unwrap();
        let spec: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            spec["process"]["args"],
            serde_json::json!(["/bin/echo", "hello"])
        );
    }
}
