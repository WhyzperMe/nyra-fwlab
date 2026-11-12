//! Ghidra exports are validated before admission or optional cache reuse.
use crate::{
    files,
    output::{json, write_new},
    publish::rename_new,
    sandbox,
};
use nyra_fw_analysis::{callgraph, ghidra::parse_bundle, symbols};
use nyra_fw_core::{FwError, Result, budget::RunBudget, errors::io, sha256_hex};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

// Diagnostics must not turn a closed host pipe into a processing panic.
fn cache_message(arguments: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr().lock(), "nyra-fw: {arguments}");
}

const NAMES: [&str; 3] = ["functions.json", "callgraph.json", "pseudocode.json"];
const SCRIPTS: [(&str, &str); 3] = [
    (
        "ExportFunctions.java",
        include_str!("../../../integrations/ghidra/ExportFunctions.java"),
    ),
    (
        "ExportCallGraph.java",
        include_str!("../../../integrations/ghidra/ExportCallGraph.java"),
    ),
    (
        "ExportDecompilation.java",
        include_str!("../../../integrations/ghidra/ExportDecompilation.java"),
    ),
];

pub(crate) struct Exports {
    pub provenance: serde_json::Value,
    pub functions: symbols::GhidraFunctions,
    pub calls: callgraph::StaticCallGraph,
    pub decompiled: usize,
    raw: [Vec<u8>; 3],
}

impl Exports {
    pub(crate) fn files(&self) -> impl Iterator<Item = (&str, &[u8])> {
        NAMES.into_iter().zip(self.raw.iter().map(Vec::as_slice))
    }

    fn parse(provenance: serde_json::Value, raw: [Vec<u8>; 3]) -> Result<Self> {
        let bundle = parse_bundle(raw.each_ref().map(Vec::as_slice))?;
        let decompiled = bundle
            .decompilation
            .functions
            .iter()
            .filter(|f| f.decompiled && !f.pseudocode.is_empty())
            .count();
        Ok(Self {
            provenance,
            functions: bundle.functions,
            calls: bundle.calls,
            decompiled,
            raw,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct CacheRecord {
    key: String,
    sha256: [String; 3],
}

fn read_exports(dir: &Path) -> Result<[Vec<u8>; 3]> {
    let mut remaining = 128 * 1024 * 1024;
    let mut read = |name| {
        let bytes = files::read_relative(dir, name, remaining.min(files::REPORT_BYTES))?;
        remaining -= bytes.len() as u64;
        Ok::<_, FwError>(bytes)
    };
    Ok([read(NAMES[0])?, read(NAMES[1])?, read(NAMES[2])?])
}

fn read_cache(dir: &Path, key: &str, provenance: &serde_json::Value) -> Result<Exports> {
    let record: CacheRecord =
        serde_json::from_slice(&files::read_relative(dir, "cache.json", 4096)?)?;
    if record.key != key {
        return Err(FwError::Verification("Ghidra cache key mismatch".into()));
    }
    let raw = read_exports(dir)?;
    if raw.each_ref().map(|bytes| sha256_hex(bytes)) != record.sha256 {
        return Err(FwError::Verification("Ghidra cache digest mismatch".into()));
    }
    Exports::parse(provenance.clone(), raw)
}

fn write_cache(root: &Path, key: &str, exports: &Exports) -> Result<()> {
    let stage = tempfile::Builder::new()
        .prefix(".nyra-cache-")
        .tempdir_in(root)
        .map_err(|e| io(root, e))?;
    for (name, bytes) in exports.files() {
        write_new(stage.path(), name, bytes)?;
    }
    let record = CacheRecord {
        key: key.into(),
        sha256: exports.raw.each_ref().map(|bytes| sha256_hex(bytes)),
    };
    write_new(stage.path(), "cache.json", &json(&record)?)?;
    match rename_new(stage.path(), &root.join(key)) {
        Ok(()) => {
            let _ = stage.keep();
        }
        Err(FwError::AlreadyExists(_)) => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

const CACHE_BYTES: u64 = 512 * 1024 * 1024;
const CACHE_ENTRIES: usize = 64;

fn toolchain_digest(root: &Path, roots: &[&str], budget: &RunBudget) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut pending: Vec<_> = roots.iter().map(|path| root.join(path)).collect();
    let mut files = Vec::new();
    let mut nodes = 0;
    while let Some(dir) = pending.pop() {
        budget.checkpoint()?;
        if !fs::symlink_metadata(&dir)
            .map_err(|err| io(&dir, err))?
            .is_dir()
        {
            return Err(FwError::UnsafePath(dir.display().to_string()));
        }
        for entry in fs::read_dir(&dir).map_err(|err| io(&dir, err))? {
            let entry = entry.map_err(|err| io(&dir, err))?;
            nodes += 1;
            if nodes > 32_768 {
                return Err(FwError::Limit(
                    "toolchain fingerprint exceeds node budget".into(),
                ));
            }
            let path = entry.path();
            let kind = entry.file_type().map_err(|err| io(&path, err))?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                files.push(path);
            } else {
                return Err(FwError::UnsafePath(path.display().to_string()));
            }
        }
    }
    files.sort();
    let mut remaining = 4 * 1024 * 1024 * 1024;
    let mut aggregate = Sha256::new();
    for path in files {
        budget.checkpoint()?;
        let relative = path
            .strip_prefix(root)
            .ok()
            .and_then(Path::to_str)
            .ok_or_else(|| FwError::UnsafePath(path.display().to_string()))?;
        let (size, hash) = files::digest_relative(root, relative, remaining)?;
        remaining -= size;
        aggregate.update((relative.len() as u64).to_le_bytes());
        aggregate.update(relative.as_bytes());
        aggregate.update(size.to_le_bytes());
        aggregate.update(hash.as_bytes());
    }
    Ok(hex::encode(aggregate.finalize()))
}

fn cache_namespace(root: &Path) -> Result<PathBuf> {
    let dir = root.join(".nyra-ghidra-v2");
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io(&dir, error)),
    }
    if !fs::symlink_metadata(&dir)
        .map_err(|error| io(&dir, error))?
        .is_dir()
    {
        return Err(FwError::UnsafePath(dir.display().to_string()));
    }
    Ok(dir)
}

fn with_cache<T>(dir: &Path, action: impl FnOnce() -> Result<T>) -> Result<T> {
    let lock = dir.join("lock");
    let file = fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock)
        .map_err(|error| io(&lock, error))?;
    file.try_lock()
        .map_err(|error| FwError::Config(format!("Ghidra cache lock unavailable: {error}")))?;
    action()
}

fn cache_entry_files(dir: &Path) -> Result<(u64, Vec<PathBuf>)> {
    let mut paths = Vec::new();
    let mut size = 0u64;
    for entry in fs::read_dir(dir).map_err(|error| io(dir, error))? {
        let entry = entry.map_err(|error| io(dir, error))?;
        let name = entry.file_name();
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| io(&path, error))?;
        if !metadata.is_file()
            || !name
                .to_str()
                .is_some_and(|name| name == "cache.json" || NAMES.contains(&name))
        {
            return Err(FwError::UnsafePath(path.display().to_string()));
        }
        size = size
            .checked_add(metadata.len())
            .ok_or_else(|| FwError::Limit("cache size overflow".into()))?;
        paths.push(path);
    }
    Ok((size, paths))
}

fn remove_entry(dir: &Path) -> Result<()> {
    let (_, paths) = cache_entry_files(dir)?;
    for path in paths {
        fs::remove_file(&path).map_err(|error| io(&path, error))?;
    }
    fs::remove_dir(dir).map_err(|error| io(dir, error))
}

/// Called under the cache lock. Only known cache entries in the private
/// namespace are eligible for eviction. Interrupted writes are reclaimed.
fn make_room(dir: &Path, key: &str, incoming: u64) -> Result<()> {
    make_room_bounded(dir, key, incoming, CACHE_BYTES, CACHE_ENTRIES)
}

fn make_room_bounded(
    dir: &Path,
    key: &str,
    incoming: u64,
    max_bytes: u64,
    max_entries: usize,
) -> Result<()> {
    if incoming > max_bytes || max_entries == 0 {
        return Err(FwError::Limit("entry exceeds cache budget".into()));
    }
    let mut entries = Vec::new();
    let mut bytes = 0u64;
    let mut visited = 0;
    for item in fs::read_dir(dir).map_err(|error| io(dir, error))? {
        let item = item.map_err(|error| io(dir, error))?;
        visited += 1;
        if visited > 128 {
            return Err(FwError::Limit(
                "cache namespace contains too many nodes".into(),
            ));
        }
        let name = item.file_name();
        let path = item.path();
        let name = name
            .to_str()
            .ok_or_else(|| FwError::UnsafePath(path.display().to_string()))?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| io(&path, error))?;
        if name == "lock" && metadata.is_file() {
            continue;
        }
        if !metadata.is_dir() {
            return Err(FwError::UnsafePath(path.display().to_string()));
        }
        if name.strip_prefix(".nyra-cache-").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
        }) || name == key
        {
            remove_entry(&path)?;
            continue;
        }
        if name.len() != 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(FwError::UnsafePath(path.display().to_string()));
        }
        let (size, _) = cache_entry_files(&path)?;
        bytes = bytes
            .checked_add(size)
            .ok_or_else(|| FwError::Limit("cache size overflow".into()))?;
        entries.push((
            metadata.modified().map_err(|error| io(&path, error))?,
            path,
            size,
        ));
    }
    entries.sort();
    let mut count = entries.len();
    for (_, path, size) in entries {
        if count < max_entries && bytes <= max_bytes - incoming {
            break;
        }
        remove_entry(&path)?;
        count -= 1;
        bytes -= size;
    }
    Ok(())
}

pub(crate) fn publish_scripts(root: &Path) -> Result<()> {
    for (name, source) in SCRIPTS {
        write_new(
            root,
            &format!("analysis/ghidra/scripts/{name}"),
            source.as_bytes(),
        )?;
    }
    Ok(())
}

pub(crate) fn run(
    root: &Path,
    headless: &Path,
    target: (&str, &str),
    timeout: Duration,
    budget: &RunBudget,
    cache: Option<&Path>,
    require_cgroup: bool,
) -> Result<Exports> {
    budget.checkpoint()?;
    if !cfg!(target_os = "linux") {
        return Err(FwError::Unsupported(
            "Ghidra requires the Linux sandbox".into(),
        ));
    }
    let (target_path, target_sha256) = target;
    let cache = cache
        .map(|dir| {
            let path = dir.canonicalize().map_err(|err| io(dir, err))?;
            if !path.is_dir() {
                return Err(FwError::Config(
                    "Ghidra cache requires an existing private directory".into(),
                ));
            }
            let root = root.canonicalize().map_err(|err| io(root, err))?;
            if root.starts_with(&path) || path.starts_with(&root) {
                return Err(FwError::Config(
                    "Ghidra cache must be separate from the workspace".into(),
                ));
            }
            Ok(path)
        })
        .transpose()?;
    let cache = cache.as_deref();
    let headless = fs::canonicalize(headless).map_err(|e| io(headless, e))?;
    let installation = headless
        .parent()
        .filter(|path| path.file_name().is_some_and(|name| name == "support"))
        .and_then(Path::parent)
        .filter(|_| {
            headless
                .file_name()
                .is_some_and(|name| name == "analyzeHeadless")
        })
        .ok_or_else(|| {
            FwError::Config("expected trusted Linux Ghidra support/analyzeHeadless".into())
        })?;
    let java_home = std::env::var_os("NYRA_JAVA_HOME")
        .map(PathBuf::from)
        .map(|path| fs::canonicalize(&path).map_err(|e| io(&path, e)))
        .transpose()?;
    if java_home
        .as_ref()
        .is_some_and(|jdk| !jdk.join("bin/java").is_file() || !jdk.join("bin/javac").is_file())
    {
        return Err(FwError::Config(
            "NYRA_JAVA_HOME must point to a trusted Linux JDK".into(),
        ));
    }
    if cache.is_some() && java_home.is_none() {
        return Err(FwError::Config(
            "Ghidra cache requires an explicit NYRA_JAVA_HOME".into(),
        ));
    }
    let metadata = files::read_input(
        &installation.join("Ghidra/application.properties"),
        64 * 1024,
    )?;
    let property_bytes = String::from_utf8_lossy(&metadata);
    let ghidra_version = property_bytes
        .lines()
        .find_map(|line| line.strip_prefix("application.version="));
    let java_release = java_home
        .as_ref()
        .map(|jdk| files::read_input(&jdk.join("release"), 64 * 1024))
        .transpose()?;
    let java_version = java_release.as_ref().and_then(|bytes| {
        String::from_utf8_lossy(bytes)
            .lines()
            .find_map(|line| line.strip_prefix("JAVA_VERSION="))
            .map(|value| value.trim_matches('"').to_owned())
    });
    if cache.is_some() && (ghidra_version.is_none() || java_version.is_none()) {
        return Err(FwError::Config(
            "Ghidra cache requires identifiable Ghidra and JDK releases".into(),
        ));
    }
    let provenance = serde_json::json!({
        "schema_version": 1, "ghidra_version": ghidra_version,
        "java_version_from_jdk_release": java_version, "target": target_path,
        "target_sha256": target_sha256,
        "application_properties_sha256": sha256_hex(&metadata),
        "jdk_release_sha256": java_release.as_deref().map(sha256_hex),
        "headless_launcher_sha256": sha256_hex(&files::read_input(&headless, 1024 * 1024)?),
        "launch_script_sha256": sha256_hex(&files::read_input(&installation.join("support/launch.sh"), 1024 * 1024)?),
        "launch_properties_sha256": sha256_hex(&files::read_input(&installation.join("support/launch.properties"), 1024 * 1024)?),
        "scripts_sha256": SCRIPTS.map(|(_, source)| sha256_hex(source.as_bytes())),
        "timeout_seconds": timeout.as_secs(), "analysis_timeout_seconds": timeout.as_secs() / 2,
        "loader": "ElfLoader", "cpu_limit": 2,
    });
    let mut provenance = provenance;
    let cache = cache.zip(java_home.as_deref()).and_then(|(path, java)| {
        let identity = toolchain_digest(installation, &["."], budget).and_then(|ghidra| {
            toolchain_digest(java, &["bin", "conf", "lib"], budget).map(|jdk| (ghidra, jdk))
        });
        match identity.and_then(|identity| cache_namespace(path).map(|dir| (dir, identity))) {
            Ok((dir, (ghidra, jdk))) => {
                provenance["ghidra_installation_sha256"] = ghidra.into();
                provenance["jdk_runtime_sha256"] = jdk.into();
                Some(dir)
            }
            Err(error) => {
                cache_message(format_args!("Ghidra cache bypassed: {error}"));
                None
            }
        }
    });
    let key = sha256_hex(&json(&(
        "nyra-ghidra-cache-v2",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH,
        &provenance,
    ))?);
    if let Some(cache) = &cache {
        match with_cache(cache, || read_cache(&cache.join(&key), &key, &provenance)) {
            Ok(hit) => {
                cache_message(format_args!("Ghidra cache hit"));
                budget.checkpoint()?;
                return Ok(hit);
            }
            Err(FwError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                cache_message(format_args!("Ghidra cache miss"));
            }
            Err(error) => cache_message(format_args!("Ghidra cache entry bypassed: {error}")),
        }
    }

    let stage = tempfile::tempdir_in(root).map_err(|e| io(root, e))?;
    publish_scripts(stage.path())?;
    let output = sandbox::run(
        sandbox::Tool::Ghidra {
            installation,
            scripts: &stage.path().join("analysis/ghidra/scripts"),
            java_home: java_home.as_deref(),
        },
        &root.join(target_path),
        stage.path(),
        "results",
        timeout,
        budget,
        require_cgroup,
    )?;
    if output.entries != NAMES.len() {
        return Err(FwError::Verification(format!(
            "Ghidra produced {} of 3 required exports\n{}",
            output.entries, output.diagnostics
        )));
    }
    let exports = Exports::parse(provenance, read_exports(&stage.path().join("results"))?)?;
    if let Some(cache) = &cache {
        let result = with_cache(cache, || {
            if read_cache(&cache.join(&key), &key, &exports.provenance).is_ok() {
                return Ok(());
            }
            let size = exports
                .raw
                .iter()
                .map(|bytes| bytes.len() as u64)
                .sum::<u64>()
                + 4096;
            make_room(cache, &key, size)?;
            write_cache(cache, &key, &exports)
        });
        if let Err(error) = result {
            cache_message(format_args!("Ghidra cache write bypassed: {error}"));
        }
    }
    budget.checkpoint()?;
    Ok(exports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_refuses_inconsistent_exports_even_with_matching_digests() {
        let temp = tempfile::tempdir().unwrap();
        let entry = temp.path().join("key");
        fs::create_dir(&entry).unwrap();
        let raw = [
            br#"{"schema_version":1,"functions":[{"name":"focus","entry":"1000","size":4,"external":false}],"exported":1}"#.as_slice(),
            br#"{"schema_version":1,"kind":"static_entry_references","edges":[],"exported":0}"#.as_slice(),
            br#"{"schema_version":1,"kind":"inferred_pseudocode","functions":[{"name":"other","entry":"1000","decompiled":true,"pseudocode":"inferred"}],"exported":1,"limited_to_lens_functions":true}"#.as_slice(),
        ];
        for (name, bytes) in NAMES.iter().zip(raw) {
            fs::write(entry.join(name), bytes).unwrap();
        }
        let record = CacheRecord {
            key: "key".into(),
            sha256: raw.map(sha256_hex),
        };
        fs::write(entry.join("cache.json"), json(&record).unwrap()).unwrap();
        assert!(read_cache(&entry, "key", &serde_json::json!({})).is_err());
    }

    #[test]
    fn bounded_cache_evicts_old_entries_and_recovers_interrupted_writes() {
        let temp = tempfile::tempdir().unwrap();
        let dir = cache_namespace(temp.path()).unwrap();
        let stale = dir.join(".nyra-cache-partial");
        fs::create_dir(&stale).unwrap();
        fs::write(stale.join("functions.json"), b"partial").unwrap();
        for key in ["a".repeat(64), "b".repeat(64)] {
            let entry = dir.join(key);
            fs::create_dir(&entry).unwrap();
            fs::write(entry.join("functions.json"), [0; 16]).unwrap();
        }
        with_cache(&dir, || make_room_bounded(&dir, &"c".repeat(64), 16, 32, 2)).unwrap();
        assert!(!stale.exists());
        let remaining = fs::read_dir(&dir)
            .unwrap()
            .filter(|item| item.as_ref().unwrap().file_type().unwrap().is_dir())
            .count();
        assert_eq!(remaining, 1);
    }

    #[test]
    fn toolchain_key_changes_when_runtime_bytes_change() {
        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("runtime");
        fs::write(&bin, b"old").unwrap();
        let budget = RunBudget::new(nyra_fw_core::Limits::default(), None);
        let old = toolchain_digest(temp.path(), &["."], &budget).unwrap();
        fs::write(&bin, b"new").unwrap();
        assert_ne!(old, toolchain_digest(temp.path(), &["."], &budget).unwrap());
    }

    #[test]
    fn cache_rechecks_keys_and_file_digests() {
        let temp = tempfile::tempdir().unwrap();
        let provenance = serde_json::json!({"schema_version": 1});
        let raw = [
            br#"{"schema_version":1,"functions":[],"exported":0}"#.to_vec(),
            br#"{"schema_version":1,"kind":"static_entry_references","edges":[],"exported":0}"#.to_vec(),
            br#"{"schema_version":1,"kind":"inferred_pseudocode","functions":[],"exported":0,"limited_to_lens_functions":true}"#.to_vec(),
        ];
        let exports = Exports::parse(provenance.clone(), raw).unwrap();
        write_cache(temp.path(), "key", &exports).unwrap();
        let entry = temp.path().join("key");
        assert!(read_cache(&entry, "other-key", &provenance).is_err());
        assert_eq!(
            read_cache(&entry, "key", &provenance).unwrap().decompiled,
            0
        );
        // Whitespace preserves JSON validity but changes the recorded digest.
        let mut changed = exports.raw[0].clone();
        changed.push(b' ');
        fs::write(entry.join(NAMES[0]), changed).unwrap();
        assert!(read_cache(&entry, "key", &provenance).is_err());
    }
}
