use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use super::matches_env_pattern;

pub fn exec_sandboxed(
    deny_paths: &[String],
    deny_env: &[String],
    command: &[String],
    project_dir: &Path,
) -> Result<()> {
    let bwrap = find_bwrap().context(
        "Linux filesystem sandboxing requires bubblewrap (`bwrap`); refusing to run without enforcement",
    )?;

    let masked = expand_existing_paths(deny_paths)?;
    let sandbox_cwd = safe_working_dir(project_dir, &masked);

    let (cmd, args) = command
        .split_first()
        .context("sandbox command cannot be empty")?;

    let mut child = Command::new(bwrap);
    child
        .arg("--die-with-parent")
        .arg("--unshare-pid")
        .arg("--bind")
        .arg("/")
        .arg("/")
        .arg("--dev-bind")
        .arg("/dev")
        .arg("/dev")
        .arg("--proc")
        .arg("/proc")
        .arg("--chdir")
        .arg(&sandbox_cwd);

    for path in &masked {
        if path.is_dir() {
            child.arg("--tmpfs").arg(path);
        } else if path.is_file() {
            child.arg("--ro-bind").arg("/dev/null").arg(path);
        }
    }

    child.arg("--").arg(cmd).args(args);

    for pattern in deny_env {
        for (key, _) in std::env::vars() {
            if matches_env_pattern(&key, pattern) {
                child.env_remove(&key);
            }
        }
    }
    let status = child
        .status()
        .context("failed to start bubblewrap Linux sandbox")?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

fn safe_working_dir(project_dir: &Path, masked: &[PathBuf]) -> PathBuf {
    let blocked = masked.iter().any(|deny| project_dir.starts_with(deny));
    if blocked {
        PathBuf::from("/tmp")
    } else {
        project_dir.to_path_buf()
    }
}

fn find_bwrap() -> Option<PathBuf> {
    ["/usr/bin/bwrap", "/bin/bwrap"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

fn expand_existing_paths(paths: &[String]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();

    for raw in paths {
        if has_glob(raw) {
            let mut matched = false;
            for entry in glob::glob(raw).with_context(|| format!("invalid deny glob: {raw}"))? {
                let path = entry.with_context(|| format!("failed to expand deny glob: {raw}"))?;
                if path.exists() {
                    out.push(path);
                    matched = true;
                }
            }
            if !matched {
                continue;
            }
        } else {
            let path = PathBuf::from(raw);
            if path.exists() {
                out.push(path);
            }
        }
    }

    out.sort();
    out.dedup();

    if out.is_empty() && !paths.is_empty() {
        bail!("none of the configured deny paths exist; refusing to claim filesystem enforcement");
    }

    Ok(out)
}
fn has_glob(value: &str) -> bool {
    value.contains('*') || value.contains('?') || value.contains('[')
}

#[cfg(test)]
mod tests {
    use super::has_glob;

    #[test]
    fn detects_glob_patterns() {
        assert!(has_glob(".env*"));
        assert!(has_glob("keys/[ab].pem"));
        assert!(!has_glob("/home/forge/private"));
    }
}
