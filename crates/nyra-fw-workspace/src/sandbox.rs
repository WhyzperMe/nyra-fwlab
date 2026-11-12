//! External parsers receive one read-only input and return bounded data.
use nyra_fw_core::{FwError, Result, budget::RunBudget};
use std::{path::Path, time::Duration};

pub(crate) enum Tool<'a> {
    SquashFs,
    Ghidra {
        installation: &'a Path,
        scripts: &'a Path,
        java_home: Option<&'a Path>,
    },
}

#[derive(Default)]
pub(crate) struct Output {
    pub bytes: u64,
    pub entries: usize,
    pub symlinks: Vec<(String, String)>,
    pub diagnostics: String,
    pub excluded_dev: bool,
}

pub(crate) fn run(
    tool: Tool<'_>,
    input: &Path,
    root: &Path,
    destination: &str,
    timeout: Duration,
    budget: &RunBudget,
    require_cgroup: bool,
) -> Result<Output> {
    #[cfg(target_os = "linux")]
    return linux::run(
        tool,
        input,
        root,
        destination,
        timeout,
        budget,
        require_cgroup,
    );
    #[cfg(not(target_os = "linux"))]
    {
        if let Tool::Ghidra {
            installation,
            scripts,
            java_home,
        } = tool
        {
            let _ = (installation, scripts, java_home);
        }
        let _ = (input, root, destination, timeout, budget, require_cgroup);
        Err(FwError::Unsupported(
            "external analysis requires Linux with bubblewrap and user namespaces".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::files;
    use nyra_fw_core::{errors::io, path::is_safe_relative};
    use std::{
        collections::BTreeMap,
        fs::{self, OpenOptions},
        io::{Read, Seek, SeekFrom},
        path::PathBuf,
        process::{Command, Stdio},
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::Instant,
    };

    struct JobGroup(PathBuf);

    impl JobGroup {
        fn delegated() -> Result<Option<Self>> {
            static SERIAL: AtomicU64 = AtomicU64::new(0);
            let Some(root) = std::env::var_os("NYRA_CGROUP_PARENT") else {
                return Ok(None);
            };
            let root = PathBuf::from(root);
            let root = root.canonicalize().map_err(|err| io(&root, err))?;
            if !root.starts_with("/sys/fs/cgroup") || !root.join("cgroup.controllers").is_file() {
                return Err(FwError::Config(
                    "NYRA_CGROUP_PARENT must be a delegated cgroup v2 directory".into(),
                ));
            }
            let group = root.join(format!(
                "nyra-{}-{}",
                std::process::id(),
                SERIAL.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&group).map_err(|err| io(&group, err))?;
            let group = Self(group);
            for (name, value) in [
                ("memory.max", "2147483648"),
                ("memory.swap.max", "0"),
                ("pids.max", "128"),
                ("memory.oom.group", "1"),
            ] {
                let control = group.0.join(name);
                fs::write(&control, value).map_err(|err| io(&control, err))?;
            }
            if !group.0.join("cgroup.kill").is_file() {
                return Err(FwError::Config("delegated cgroup lacks cgroup.kill".into()));
            }
            Ok(Some(group))
        }

        fn kill(&self) {
            let _ = fs::write(self.0.join("cgroup.kill"), "1");
        }
    }

    impl Drop for JobGroup {
        fn drop(&mut self) {
            self.kill();
            let _ = fs::remove_dir(&self.0);
        }
    }

    const WRAPPER: &str = r#"
        umask 077
        /usr/bin/mkdir -p /scratch/result /scratch/home /scratch/tmp /scratch/project || exit
        /usr/bin/prlimit --fsize=67108864 --core=0 --nofile="$2" --nproc=512 --as=8589934592 --cpu="$1" -- "${@:3}" >&2 || exit
        exec /usr/bin/tar --format=ustar --hard-dereference -C /scratch -cf - result
    "#;

    // Read the inode listing for the literal dev subtree before extracting.
    // The listing can select only a fixed exclusion. No firmware path is ever
    // interpolated into a command, and stderr never controls extraction.
    const SQUASHFS_WRAPPER: &str = r#"
        umask 077
        /usr/bin/mkdir -p /scratch/result /scratch/home /scratch/tmp || exit
        seconds="$1"
        files="$2"
        bounded() {
            /usr/bin/prlimit --fsize="$1" --core=0 --nofile="$files" --nproc=512 --as=8589934592 --cpu="$seconds" -- "${@:2}"
        }
        args=(-no-progress -no-xattrs -strict-errors -processors 2 -data-queue 16 -frag-queue 16 -d /scratch/result -no-wildcards)
        bounded 16777216 /usr/bin/unsquashfs "${args[@]}" -lln /input dev > /scratch/dev-listing || exit
        /usr/bin/awk '
            length($1) == 10 && /^[bc][rwxstST-]+ +[0-9]+\/[0-9]+ +[0-9]+, *[0-9]+ +[0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+ \/scratch\/result\/dev\/[^[:cntrl:]]+$/ { found = 1 }
            END { exit !found }
        ' /scratch/dev-listing
        case $? in
            0)
                # A pathname or symlink target can contain a newline. Confirm
                # the same number of records in the path-only listing, which
                # omits link targets, and reject injected metadata lines there.
                bounded 16777216 /usr/bin/unsquashfs "${args[@]}" -ls /input dev > /scratch/dev-paths || exit
                /usr/bin/awk '
                    FILENAME == ARGV[1] { records++; next }
                    !/^\/scratch\/result(\/dev(\/[^[:cntrl:]]+)?)?$/ { invalid = 1 }
                    END { exit (invalid || FNR != records) }
                ' /scratch/dev-listing /scratch/dev-paths || {
                    printf '%s\n' 'ambiguous SquashFS dev listing' >&2
                    exit 125
                }
                bounded 67108864 /usr/bin/unsquashfs "${args[@]}" -excludes /input dev >&2 || exit
                : > /scratch/excluded-dev || exit
                exec /usr/bin/tar --format=ustar --hard-dereference -C /scratch -cf - excluded-dev result
                ;;
            1)
                bounded 67108864 /usr/bin/unsquashfs "${args[@]}" /input >&2 || exit
                exec /usr/bin/tar --format=ustar --hard-dereference -C /scratch -cf - result
                ;;
            *) exit 125 ;;
        esac
    "#;

    pub(super) fn run(
        tool: Tool<'_>,
        input: &Path,
        root: &Path,
        destination: &str,
        timeout: Duration,
        budget: &RunBudget,
        require_cgroup: bool,
    ) -> Result<Output> {
        let limits = &budget.limits;
        let seconds = timeout.as_secs().clamp(10, 3600);
        let input = input.canonicalize().map_err(|e| io(input, e))?;
        let group = JobGroup::delegated()?;
        if require_cgroup && group.is_none() {
            return Err(FwError::Config(
                "--require-cgroup requires a delegated NYRA_CGROUP_PARENT before tool launch"
                    .into(),
            ));
        }
        let mut cmd = if let Some(group) = &group {
            let mut shell = Command::new("/bin/sh");
            shell
                .args([
                    "-c",
                    "printf '%s\n' \"$$\" > \"$1\" || exit 125; shift; exec \"$@\"",
                    "nyra-cgroup",
                ])
                .arg(group.0.join("cgroup.procs"))
                .arg("/usr/bin/bwrap");
            shell
        } else {
            Command::new("/usr/bin/bwrap")
        };
        cmd.env_clear().args([
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--cap-drop",
            "ALL",
            "--clearenv",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--ro-bind",
            "/usr",
            "/usr",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/scratch/home",
            "--setenv",
            "TMPDIR",
            "/scratch/tmp",
            "--setenv",
            "LC_ALL",
            "C",
            "--size",
            "335544320",
            "--tmpfs",
            "/scratch",
            "--symlink",
            "/scratch/tmp",
            "/tmp",
            "--chdir",
            "/scratch",
        ]);
        for dir in [
            "/bin",
            "/lib",
            "/lib64",
            "/etc/alternatives",
            "/etc/ld.so.cache",
        ] {
            if Path::new(dir).exists() {
                cmd.args(["--ro-bind", dir, dir]);
            }
        }
        cmd.arg("--ro-bind").arg(&input).arg("/input");
        let ghidra = matches!(tool, Tool::Ghidra { .. });
        if let Tool::Ghidra {
            installation,
            scripts,
            java_home,
        } = tool
        {
            cmd.arg("--ro-bind")
                .arg(installation)
                .arg("/ghidra")
                .arg("--ro-bind")
                .arg(scripts)
                .arg("/scripts")
                .args([
                    "--setenv",
                    "GHIDRA_HEADLESS_MAXMEM",
                    "512M",
                    "--setenv",
                    "JAVA_TOOL_OPTIONS",
                    "-XX:ActiveProcessorCount=2 -XX:MaxMetaspaceSize=256m -Duser.home=/scratch/home -Djava.io.tmpdir=/scratch/tmp",
                ]);
            if let Some(jdk) = java_home {
                cmd.arg("--ro-bind").arg(jdk).arg("/jdk").args([
                    "--setenv",
                    "JAVA_HOME",
                    "/jdk",
                    "--setenv",
                    "PATH",
                    "/jdk/bin:/usr/bin:/bin",
                ]);
            }
            for entry in fs::read_dir("/etc").map_err(|e| io(Path::new("/etc"), e))? {
                let entry = entry.map_err(|e| io(Path::new("/etc"), e))?;
                if entry.file_name().to_string_lossy().starts_with("java-") {
                    cmd.arg("--ro-bind").arg(entry.path()).arg(entry.path());
                }
            }
        }
        cmd.args([
            "--remount-ro",
            "/",
            "--",
            "/bin/bash",
            "-c",
            if ghidra { WRAPPER } else { SQUASHFS_WRAPPER },
            "nyra-fw-sandbox",
        ])
        .arg(seconds.to_string())
        .arg(if ghidra { "1024" } else { "256" });
        if ghidra {
            cmd.args([
                "/ghidra/support/analyzeHeadless",
                "/scratch/project",
                "nyra_fwlab",
                "-import",
                "/input",
                "-loader",
                "ElfLoader",
                "-loader-loadLibraries",
                "false",
                "-scriptPath",
                "/scripts",
                "-readOnly",
                "-deleteProject",
                "-max-cpu",
                "2",
                "-analysisTimeoutPerFile",
            ])
            .arg((seconds / 2).to_string())
            .args([
                "-postScript",
                "ExportFunctions.java",
                "/scratch/result/functions.json",
                "-postScript",
                "ExportCallGraph.java",
                "/scratch/result/callgraph.json",
                "-postScript",
                "ExportDecompilation.java",
                "/scratch/result/pseudocode.json",
            ]);
        }
        let mut archive = tempfile::tempfile().map_err(|e| io(root, e))?;
        let max_archive = limits
            .max_total_output_bytes
            .saturating_add(32 * 1024 * 1024);
        let wall_time = budget.time_for(Duration::from_secs(seconds))?;
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| FwError::Config(format!("cannot launch Linux analysis sandbox: {e}")))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| FwError::Config("missing sandbox output pipe".into()))?;
        let errors = child
            .stderr
            .take()
            .ok_or_else(|| FwError::Config("missing sandbox diagnostics pipe".into()))?;
        let status = thread::scope(|scope| {
            let copy = scope.spawn(|| {
                std::io::copy(
                    &mut output.take(max_archive.saturating_add(1)),
                    &mut archive,
                )
            });
            let log = scope.spawn(|| capture_log(errors));
            let start = Instant::now();
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Ok(status),
                    Ok(None) if start.elapsed() < wall_time => {
                        thread::sleep(Duration::from_millis(25));
                    }
                    wait => {
                        if let Some(group) = &group {
                            group.kill();
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                        break match wait {
                            Err(e) => Err(FwError::Config(format!("cannot wait for sandbox: {e}"))),
                            _ => Err(FwError::ToolTimeout),
                        };
                    }
                }
            };
            let written = copy
                .join()
                .map_err(|_| FwError::Config("sandbox output reader stopped".into()))?
                .map_err(|e| io(root, e))?;
            let log = log
                .join()
                .map_err(|_| FwError::Config("sandbox log reader stopped".into()))?
                .map_err(|e| io(root, e))?;
            if written > max_archive {
                return Err(FwError::Limit("sandbox output stream too large".into()));
            }
            let detail: String = String::from_utf8_lossy(&log)
                .chars()
                .filter(|c| !c.is_control() || *c == '\n')
                .collect();
            if !status?.success() {
                return Err(FwError::Verification(format!(
                    "external analysis sandbox failed: {detail}"
                )));
            }
            Ok(detail)
        });
        let diagnostics = status?;
        archive.seek(SeekFrom::Start(0)).map_err(|e| io(root, e))?;
        let mut archive = tar::Archive::new(archive);
        let mut output = unpack(&mut archive, root, destination, budget, ghidra)?;
        output.diagnostics = diagnostics;
        Ok(output)
    }

    fn capture_log(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
        let mut prefix = Vec::new();
        reader.by_ref().take(16_384).read_to_end(&mut prefix)?;
        std::io::copy(&mut reader, &mut std::io::sink())?;
        Ok(prefix)
    }

    fn unpack(
        archive: &mut tar::Archive<impl Read>,
        root: &Path,
        destination: &str,
        budget: &RunBudget,
        ghidra: bool,
    ) -> Result<Output> {
        let limits = &budget.limits;
        let mut output = Output::default();
        let mut names = BTreeMap::<String, (String, bool)>::new();
        let mut result_seen = false;
        for entry in archive.entries().map_err(|e| io(root, e))?.raw(true) {
            budget.checkpoint()?;
            let mut entry = entry.map_err(|e| io(root, e))?;
            let name = entry.path_bytes();
            let name = std::str::from_utf8(&name)
                .map_err(|_| FwError::UnsafePath("non-UTF-8 sandbox output".into()))?;
            let kind = entry.header().entry_type();
            if !ghidra
                && name == "excluded-dev"
                && kind.is_file()
                && entry.size() == 0
                && !output.excluded_dev
                && !result_seen
            {
                output.excluded_dev = true;
                continue;
            }
            if name == "result/" && kind.is_dir() {
                if result_seen {
                    return Err(FwError::Verification(
                        "duplicate sandbox output root".into(),
                    ));
                }
                result_seen = true;
                continue;
            }
            let relative = name.strip_prefix("result/").unwrap_or_default();
            let relative = if kind.is_dir() {
                relative.strip_suffix('/').unwrap_or(relative)
            } else {
                relative
            };
            if !result_seen
                || (output.excluded_dev && (relative == "dev" || relative.starts_with("dev/")))
                || !is_safe_relative(relative)
                || (ghidra
                    && !matches!(
                        relative,
                        "functions.json" | "callgraph.json" | "pseudocode.json"
                    ))
            {
                return Err(FwError::UnsafePath(format!(
                    "invalid sandbox output name: {name:?}"
                )));
            }
            let path = format!("{destination}/{relative}");
            if !is_safe_relative(&path)
                || relative.rsplit_once('/').is_some_and(|(parent, _)| {
                    names
                        .get(&parent.to_ascii_lowercase())
                        .is_none_or(|(prior, directory)| prior != parent || !directory)
                })
                || names
                    .insert(
                        relative.to_ascii_lowercase(),
                        (relative.into(), kind.is_dir()),
                    )
                    .is_some()
            {
                return Err(FwError::UnsafePath(format!(
                    "sandbox output path collision: {relative}"
                )));
            }
            let path = root.join(path);
            output.entries += 1;
            if output.entries > limits.max_entries {
                return Err(FwError::Limit(
                    "sandbox output contains too many nodes".into(),
                ));
            }
            if kind.is_dir() && !ghidra {
                fs::create_dir_all(&path).map_err(|e| io(&path, e))?;
            } else if kind.is_symlink() && !ghidra {
                let target = entry
                    .link_name_bytes()
                    .ok_or_else(|| FwError::UnsafePath(relative.into()))?;
                output.symlinks.push((
                    relative.into(),
                    String::from_utf8_lossy(&target).into_owned(),
                ));
            } else if kind.is_file() {
                let max_file = if ghidra {
                    files::REPORT_BYTES
                } else {
                    limits.max_entry_bytes
                };
                output.bytes = output
                    .bytes
                    .checked_add(entry.size())
                    .ok_or_else(|| FwError::Limit("sandbox output size overflow".into()))?;
                limits.check_total(output.bytes)?;
                if entry.size() > max_file {
                    return Err(FwError::Limit("sandbox file too large".into()));
                }
                let parent = path
                    .parent()
                    .ok_or_else(|| FwError::UnsafePath(path.display().to_string()))?;
                fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)
                    .map_err(|e| io(&path, e))?;
                if std::io::copy(&mut entry, &mut file).map_err(|e| io(&path, e))? != entry.size() {
                    return Err(FwError::Verification("truncated sandbox file".into()));
                }
                file.sync_all().map_err(|e| io(&path, e))?;
            } else {
                return Err(FwError::UnsafePath(format!(
                    "unsupported sandbox node: {relative}"
                )));
            }
        }
        if !result_seen {
            return Err(FwError::Verification("missing sandbox output root".into()));
        }
        output.symlinks.sort();
        Ok(output)
    }
}
